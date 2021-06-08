#!/usr/bin/python3
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Union, List

import click

import src.utils.logger as logger
from src.client.device_resolver import DeviceResolver, DHCPReason
from src.client.version import APP_VERSION, HASH_VERSION
from src.executor.shell_executor import SystemHelper
from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils import about
from src.utils.constants import ErrorCode, AppEnv
from src.utils.downloader import download, VPNType, downloader_opt_factory, DownloaderOpt
from src.utils.helper import FileHelper, loop_interval, JsonHelper, \
    TextHelper, EnvHelper, NetworkHelper
from src.utils.opts_shared import CLI_CTX_SETTINGS, permission, verbose_opts, UnixServiceOpts, unix_service_opts, \
    dev_mode_opts
from src.utils.opts_vpn import AuthOpts, vpn_auth_opts, ServerOpts, vpn_server_opts, VpnDirectory, \
    vpn_dir_opts_factory


class ClientOpts(VpnDirectory):
    VPN_ZIP = 'vpnclient.zip'
    VPN_HOME = '/app/vpnclient'
    VPN_CONFIG_FILE = 'vpn_client.config'

    @property
    def config_file(self):
        return self.vpn_dir.joinpath(self.VPN_CONFIG_FILE)

    @property
    def vpnclient(self):
        return self.vpn_dir.joinpath('vpnclient')

    @property
    def log_file(self):
        return self.get_log_file(datetime.today().strftime("%Y%m%d"))

    @property
    def pid_file(self):
        return self.runtime_dir.joinpath('vpn.pid')

    @property
    def account_cache_file(self):
        return self.runtime_dir.joinpath('vpn.account.cache')

    @property
    def service_cache_file(self):
        return self.runtime_dir.joinpath('vpn.service.cache')

    def get_log_file(self, date):
        return os.path.join(self.vpn_dir, 'client_log', f'client_{date}.log')

    @classmethod
    def get_resource(cls, file_name) -> str:
        return EnvHelper.resource_finder(file_name, os.path.dirname(__file__))

    @staticmethod
    def account_to_nic(account: str) -> str:
        return 'vpn_' + account.strip()

    @staticmethod
    def nic_to_account(nic: str) -> str:
        return nic.replace('vpn_', '', 1)

    @staticmethod
    def is_vpn_nic(nic: str) -> bool:
        return nic.startswith('vpn_')

    @staticmethod
    def vpn_service_name() -> str:
        binary = EnvHelper.binary_name()
        brand = binary.split('-', 1)[0] if binary else AppEnv.BRAND
        return (os.environ.get(AppEnv.VPN_CORP_ENV) or brand) + '-vpn'


class AccountInfo:

    def __init__(self, hub: str, account: str, hostname: str, is_default: bool = False, is_current: bool = False):
        self.hub = hub
        self.account = account or hub
        self.hostname = hostname
        self.is_default = is_default
        self.is_current = is_current

    def to_json(self):
        return {self.account: {k: v for k, v in self.__dict__.items() if k not in ['is_default', 'is_current']}}

    @staticmethod
    def merge(_acc1: 'AccountInfo', _acc2: 'AccountInfo') -> 'AccountInfo':
        if not _acc1 and not _acc2:
            raise ValueError('Cannot merge 2 null value')
        if not _acc2:
            return _acc1
        if not _acc1:
            return _acc2
        return AccountInfo(_acc2.hub or _acc1.hub, _acc2.account or _acc2.account, _acc2.hostname or _acc1.hostname,
                           _acc2.is_default if _acc2.is_default is None else _acc1.is_default,
                           _acc2.is_current if _acc2.is_current is None else _acc1.is_current)


class AccountStorage:
    def __init__(self, account_file: Union[str, Path]):
        self._account_file = account_file

    def _load(self):
        return JsonHelper.read(self._account_file, strict=False)

    def create_or_update(self, account: AccountInfo, connect: bool):
        data = self._load()
        accounts = self._accounts(data)
        accounts = {**accounts, **account.to_json()}
        self._dump(data=data, _accounts=accounts, _current=account.account if connect else None,
                   _default=account.account if account.is_default else None)
        return account

    def list(self) -> List[AccountInfo]:
        data = self._load()
        return [self._to_account_info(acc, data) for acc in self._accounts(data).values()]

    def find(self, account: str, data=None) -> Optional[AccountInfo]:
        if not account:
            return None
        data = data or self._load()
        return next((self._to_account_info(acc, data) for k, acc in self._accounts(data).items() if k == account), None)

    def remove(self, accounts: Union[str, List[str]]) -> (bool, bool):
        data = self._load()
        _accounts = self._accounts(data)
        _default = self.get_default(data)
        _current = self.get_current(data)
        accounts = accounts if isinstance(accounts, list) else [accounts]
        self._dump(data=data, _accounts={k: v for k, v in _accounts.items() if k not in accounts},
                   _default='' if _default in accounts else _default,
                   _current='' if _current in accounts else _current)
        return _default in accounts, _current in accounts

    def empty(self):
        if FileHelper.is_writable(self._account_file):
            self._dump({}, '', '')

    def set_default(self, account: str):
        self._dump(_default=account)

    def set_current(self, account):
        self._dump(_current=account)

    def get_default(self, data=None, info=False) -> Optional[Union[str, AccountInfo]]:
        return self._lookup('_default', data, info)

    def get_current(self, data=None, info=False) -> Optional[Union[str, AccountInfo]]:
        return self._lookup('_current', data, info)

    def _accounts(self, data=None) -> dict:
        return (data or self._load()).get('_accounts', {})

    def _lookup(self, key, data=None, info=False) -> Optional[Union[str, AccountInfo]]:
        load = data or self._load()
        acc = load.get(key, None)
        return acc if not info else self.find(acc, data)

    def _to_account_info(self, acc, data=None) -> AccountInfo:
        acc['is_default'] = acc['account'] == self.get_default(data)
        acc['is_current'] = acc['account'] == self.get_current(data)
        return AccountInfo(**acc)

    def _dump(self, _accounts: dict = None, _current: str = None, _default: str = None, data=None):
        data = data or self._load()
        data['_accounts'] = self._accounts(data) if _accounts is None else _accounts
        data['_current'] = self.get_current(data) if _current is None else _current
        data['_default'] = self.get_default(data) if _default is None else _default
        JsonHelper.dump(self._account_file, data)


class VPNPIDHandler:
    def __init__(self, vpn_opts: ClientOpts):
        self.opts = vpn_opts

    @property
    def current_pid(self):
        return self._find_pid()

    def is_running(self, log_lvl=logger.DEBUG) -> bool:
        logger.log(log_lvl, 'Check if VPN is running...')
        pid = self._find_pid(logger.down_lvl(log_lvl))
        if pid:
            self._dump_pid(pid, logger.down_lvl(log_lvl))
            return True
        self.cleanup()
        return False

    def cleanup(self):
        FileHelper.rm(self._pid_files())
        FileHelper.rm(self.opts.pid_file)

    def _find_pid(self, log_lvl=logger.TRACE) -> int:
        return next((pid for pid in map(lambda x: self._check_pid(x, log_lvl), self._pid_files(log_lvl)) if pid), 0)

    def _pid_files(self, log_lvl=logger.TRACE) -> list:
        files = FileHelper.find_files(self.opts.vpn_dir, '.pid_*')
        logger.log(log_lvl, f'PID files [{",".join(files)}]')
        return files

    def _dump_pid(self, pid, log_lvl=logger.TRACE):
        logger.log(log_lvl, f'VPN PID [{pid}]')
        FileHelper.write_file(self.opts.pid_file, str(pid), mode=0o644, log_lvl=log_lvl)

    @staticmethod
    def _check_pid(pid_file: str, log_lvl=logger.TRACE) -> int:
        try:
            logger.log(log_lvl, f'Read PID file {pid_file}')
            pid = FileHelper.read_file_by_line(pid_file)
            pid = int(pid)
            if pid and pid > 0 and SystemHelper.is_pid_exists(pid):
                return pid
        except Exception as _:
            FileHelper.rm(pid_file)
        return 0


class VPNClientExecutor(VpnCmdExecutor):

    def __init__(self, vpn_opts: ClientOpts, adhoc_task=False):
        super().__init__(vpn_opts)
        self.storage = AccountStorage(self.opts.account_cache_file)
        self._device = DeviceResolver()
        self.pid_handler = VPNPIDHandler(self.opts)
        self.adhoc_task = adhoc_task

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        logger.log(log_lvl, 'Start VPN Client if not yet running...')
        if not self.is_installed(silent, log_lvl) or self.pid_handler.is_running():
            return
        SystemHelper.exec_command(f'{self.opts.vpnclient} start', log_lvl=logger.down_lvl(log_lvl))
        time.sleep(1)
        if not self.pid_handler.is_running(log_lvl=logger.down_lvl(log_lvl)):
            logger.error('Unable start VPN Client')
            sys.exit(ErrorCode.VPN_START_FAILED)

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        logger.log(log_lvl, 'Stop VPN Client if applicable...')
        if (not self.is_installed(silent, log_lvl) or not self.adhoc_task
            or self.device.unix_service.status(self.vpn_service).is_running()):
            return
        lvl = logger.down_lvl(log_lvl)
        if self.pid_handler.is_running(log_lvl=lvl):
            SystemHelper.exec_command(f'{self.opts.vpnclient} stop', silent=silent, log_lvl=lvl)
            self.cleanup_zombie_vpn(1, log_lvl=lvl)
            self.pid_handler.cleanup()

    def vpn_cmd_opt(self):
        return '/CLIENT localhost /CMD'

    @property
    def device(self) -> DeviceResolver:
        return self._device

    @property
    def vpn_service(self) -> str:
        return self._standard_service_opt().service_name

    def require_install(self) -> 'VPNClientExecutor':
        self.is_installed()
        return self

    def probe(self, silent=True, log_lvl=logger.DEBUG) -> 'VPNClientExecutor':
        self._device = self.device.probe(ClientOpts.resource_dir(), self.opts.runtime_dir, log_lvl, silent)
        return self

    def vpn_status(self, vpn_acc: str):
        if not vpn_acc:
            return None
        try:
            status = self.exec_command('AccountStatusGet', params=vpn_acc, silent=True, log_lvl=logger.DEBUG)
            return TextHelper.awk(next(iter(TextHelper.grep(status, r'Session Status.+')), None), sep='|',
                                  pos=1).strip()
        except:
            return None

    def is_running(self, silent=True, log_lvl=logger.DEBUG):
        return self.is_installed(silent, log_lvl) and self.pid_handler.is_running(log_lvl)

    def install(self, service_opts: UnixServiceOpts, auto_startup: bool = False):
        FileHelper.mkdirs(self.opts.vpn_dir.parent)
        FileHelper.unpack_archive(ClientOpts.get_resource(ClientOpts.VPN_ZIP), self.opts.vpn_dir)
        FileHelper.mkdirs([self.opts.vpn_dir, self.opts.runtime_dir])
        FileHelper.chmod(self.opts.runtime_dir, mode=0o0755)
        FileHelper.chmod([os.path.join(self.opts.vpn_dir, p) for p in ('vpnclient', 'vpncmd')], mode=0o0755)
        _, cmd = EnvHelper.build_executable_command()
        svc_opts = self._standard_service_opt(service_opts)
        self.device.unix_service.create(svc_opts, {
            '{{WORKING_DIR}}': f'{self.opts.vpn_dir}', '{{PID_FILE}}': f'{self.opts.pid_file}',
            '{{VPN_DESC}}': svc_opts.service_name,
            '{{START_CMD}}': f'{cmd} start --vpn-dir {self.opts.vpn_dir}',
            '{{STOP_CMD}}': f'{cmd} stop --vpn-dir {self.opts.vpn_dir}'
        }, auto_startup)
        self.device.ip_resolver.add_hook(svc_opts.service_name,
                                         {'{{WORKING_DIR}}': f'{self.opts.vpn_dir}', '{{VPN_CLIENT_CLI}}': cmd})
        self.device.dns_resolver.create_config(svc_opts.service_name)
        self._dump_cache_service(svc_opts)
        self.storage.empty()
        self.opts.export_env()

    def uninstall(self, keep_vpn: bool = True, keep_dnsmasq: bool = True, service_opts: UnixServiceOpts = None,
                  log_lvl: int = logger.INFO):
        svc_opts = self._standard_service_opt(service_opts)
        vpn_service = svc_opts.service_name
        logger.info(f'Uninstall VPN service [{vpn_service}]...')
        accounts = [a.account for a in self.storage.list()]
        if len(accounts) > 0:
            self.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], accounts, silent=True)
        self.shutdown_vpn_service(is_stop=True, is_disable=True, keep_dnsmasq=keep_dnsmasq, vpn_service=vpn_service)
        if keep_vpn:
            self.storage.empty()
        else:
            logger.log(log_lvl, f'Remove VPN Client [{self.opts.vpn_dir}]...')
            self.device.unix_service.remove(svc_opts, force=True)
            self.device.ip_resolver.remove_hook(vpn_service)
            self.opts.remove_env()
            FileHelper.rm(self.opts.vpn_dir)
        self.device.ip_resolver.renew_all_ip()

    def backup_config(self):
        backup_dir = self.opts.backup_dir()
        logger.info(f'Backup VPN configuration [{self.opts.vpn_dir}] to [{backup_dir}] ...')
        FileHelper.mkdirs(backup_dir)
        FileHelper.copy(self.opts.config_file, backup_dir, force=True)
        FileHelper.copy(self.opts.runtime_dir, backup_dir.joinpath(self.opts.RUNTIME_FOLDER), force=True)
        default_acc = self.storage.get_default()
        current_acc = self.storage.get_current()
        svc_opt = self._standard_service_opt()
        return default_acc, current_acc, svc_opt, backup_dir

    def restore_config(self, backup_dir: Path):
        logger.info(f'Restore VPN configuration [{backup_dir}] to [{self.opts.vpn_dir}]...')
        FileHelper.copy(backup_dir.joinpath(self.opts.VPN_CONFIG_FILE), self.opts.config_file, force=True)
        FileHelper.copy(backup_dir.joinpath(self.opts.RUNTIME_FOLDER), self.opts.runtime_dir, force=True)
        FileHelper.rm(backup_dir)

    def connect_vpn(self, account: str, is_default: bool, log_lvl: int = logger.INFO):
        if not account:
            logger.error(f'VPN account is not correct')
            sys.exit(ErrorCode.INVALID_ARGUMENT)
        logger.log(log_lvl, f'Connect VPN account [{account}]...')
        setup_cmd = ['AccountConnect', 'AccountStartupSet'] if is_default else ['AccountConnect']
        self.exec_command(setup_cmd, params=account)
        acc = AccountInfo.merge(self.storage.find(account), AccountInfo('', account, '', is_default))
        self.storage.create_or_update(acc, connect=True)
        self.lease_vpn_service(is_enable=acc.is_default, is_restart=acc.is_default, is_lease_ip=not acc.is_default,
                               account=acc.account)

    def disconnect_vpn(self, log_lvl: int = logger.INFO, silent: bool = False, force=False):
        account = self.storage.get_current() or self.storage.get_default()
        if not account:
            logger.log(logger.down_lvl(log_lvl), 'Not found any VPN account')
            if force:
                self.cleanup_zombie_vpn(1, log_lvl)
            return None
        logger.log(log_lvl, f'Disconnect VPN account [{account}]...')
        self.exec_command('AccountDisconnect', params=account, log_lvl=logger.down_lvl(log_lvl), silent=silent)
        self.storage.set_current('')
        self.device.dns_resolver.reset_vpn_nameservers()
        self.device.ip_resolver.release_ip(account, self.opts.account_to_nic(account))
        self.device.ip_resolver.cleanup_zombie(f' {self.vpn_dir}.* {self.opts.account_to_nic(account)}')

    def lease_vpn_service(self, is_enable: bool = True, is_restart: bool = True, is_lease_ip: bool = False,
                          account: Optional[str] = None):
        vpn_service = self.vpn_service
        if is_enable:
            self.device.unix_service.enable(vpn_service)
        if is_restart:
            self.device.unix_service.restart(vpn_service)
        if is_lease_ip and account:
            self.lease_vpn_ip(account, log_lvl=logger.INFO)

    def lease_vpn_ip(self, account: str, log_lvl=logger.DEBUG):
        logger.log(log_lvl, 'Waiting VPN session is established then lease new VPN IP...')
        loop_interval(lambda: self.vpn_status(account) == 'Connection Completed (Session Established)',
                      'Unable connect VPN. Please check log for more detail', max_retries=10, interval=2)
        self.device.ip_resolver.lease_ip(account, self.opts.account_to_nic(account))

    def shutdown_vpn_service(self, is_stop=True, is_disable=False, keep_dnsmasq=True, vpn_service: str = None):
        vpn_service = vpn_service or self.vpn_service
        if is_disable:
            self.device.unix_service.disable(vpn_service)
        if is_stop:
            self.device.unix_service.stop(vpn_service)
            self.cleanup_zombie_vpn()
            self.device.dns_resolver.cleanup_config(vpn_service, keep_dnsmasq=keep_dnsmasq)

    def cleanup_zombie_vpn(self, delay=1, log_lvl=logger.DEBUG):
        time.sleep(delay)
        SystemHelper.kill_by_process(f'{self.vpn_dir}/vpnclient execsvc', silent=True, log_lvl=log_lvl)
        self.device.ip_resolver.cleanup_zombie(f' {self.vpn_dir}.* vpn_')

    def _is_install(self) -> bool:
        return FileHelper.is_executable(self.opts.vpnclient)

    def _not_install_error_msg(self, cmd) -> str:
        return f'Missing VPN client. Might be the installation is corrupted. ' + \
               f'Use "{cmd} uninstall -f" then try reinstall by "{cmd} install"'

    def _optimize_command_result(self, output):
        r = TextHelper.grep(output, r'VPN Client>.+((?:\n.+)+)')
        return ''.join(r).replace('The command completed successfully.', '').strip()

    def _dump_cache_service(self, svc_opts: UnixServiceOpts):
        JsonHelper.dump(self.opts.service_cache_file, svc_opts)

    def _standard_service_opt(self, svc_opts: UnixServiceOpts = None) -> UnixServiceOpts:
        if svc_opts:
            return UnixServiceOpts(svc_opts.service_dir or self.device.unix_service.standard_service_dir,
                                   svc_opts.service_name)
        try:
            data = JsonHelper.read(self.opts.service_cache_file)
            return UnixServiceOpts(data.get('service_dir') or self.device.unix_service.standard_service_dir,
                                   data.get('service_name'))
        except FileNotFoundError:
            return UnixServiceOpts(self.device.unix_service.standard_service_dir, ClientOpts.vpn_service_name())


vpn_client_opts = vpn_dir_opts_factory(app_dir=ClientOpts.VPN_HOME, opt_func=ClientOpts)


@click.group(name="vpnclient", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN client CLI that helps to install VPN Client service and setup VPN connection
    """
    pass


@cli.command(name="download", help="Download VPN client", hidden=True)
@downloader_opt_factory(ClientOpts.resource_dir())
@dev_mode_opts(hidden=False, opt_name=DownloaderOpt.OPT_NAME)
def __download(downloader_opts: DownloaderOpt):
    download(VPNType.CLIENT, downloader_opts)


@cli.command(name="install", help="Install VPN client and setup *nix service")
@click.option("--auto-startup", type=bool, default=False, flag_value=True, help="Enable auto-startup VPN service")
@click.option("--auto-dnsmasq", type=bool, default=False, flag_value=True, help="Give a try to install dnsmasq")
@click.option("--dnsmasq/--no-dnsmasq", type=bool, default=True, flag_value=False,
              help="By default, dnsmasq is used as local DNS cache. Disabled it if using default System DNS resolver")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts(ClientOpts.vpn_service_name())
@click.option("-f", "--force", type=bool, flag_value=True,
              help="If force is enabled, VPN service will be removed then reinstall without backup")
@verbose_opts
@permission
def __install(vpn_opts: ClientOpts, svc_opts: UnixServiceOpts, auto_startup: bool, auto_dnsmasq: bool, dnsmasq: bool,
              force: bool):
    if not dnsmasq:
        logger.error('Only support dnsmasq as DNS resolver in first version')
        sys.exit(ErrorCode.NOT_YET_SUPPORTED)
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    if executor.is_installed(silent=True):
        if force:
            logger.warn('VPN service is already installed. Try to remove then reinstall...')
            executor.uninstall(keep_vpn=False, keep_dnsmasq=True)
        else:
            logger.error('VPN service is already installed')
            sys.exit(ErrorCode.VPN_ALREADY_INSTALLED)
    device = executor.device
    if dnsmasq and not device.dns_resolver.is_dnsmasq_available():
        executor.device.install_dnsmasq(auto_dnsmasq)
    logger.info(f'Installing VPN client into [{vpn_opts.vpn_dir}] and register service[{svc_opts.service_name}]...')
    executor.install(svc_opts, auto_startup)
    logger.done()


@cli.command(name="uninstall", help="Stop and disable VPN client and *nix service")
@click.option("-f", "--force", type=bool, flag_value=True, help="If force is enabled, VPN service will be removed")
@click.option("--keep-dnsmasq/--no-keep-dnsmasq", type=bool, default=True, flag_value=False,
              help="By default, dnsmasq is used as local DNS cache.")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __uninstall(vpn_opts: ClientOpts, force: bool = False, keep_dnsmasq: bool = True):
    VPNClientExecutor(vpn_opts).probe().uninstall(keep_vpn=not force, keep_dnsmasq=keep_dnsmasq)
    logger.done()


@cli.command(name="upgrade", help="Upgrade VPN client")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __upgrade(vpn_opts: ClientOpts):
    def _reconnect_vpn(_executor: VPNClientExecutor, _default_acc: str, _current_acc: str):
        logger.debug(f'UPGRADE::Reconnect VPN previous state: default[{_default_acc}] - current[{_current_acc}]')
        if not _current_acc and not _default_acc:
            return
        if not _current_acc and _default_acc:
            logger.debug('UPGRADE::Enable VPN service but no connect...')
            return _executor.lease_vpn_service(is_enable=True, is_restart=False, is_lease_ip=False)
        if _current_acc == _default_acc:
            logger.debug('UPGRADE::Enable then restart VPN service...')
            return _executor.lease_vpn_service(is_enable=True, is_restart=True, is_lease_ip=False)
        logger.debug(f'UPGRADE::Start VPN service then connect to previous current acc [{_current_acc}]...')
        _executor.device.unix_service.restart(_executor.vpn_service, delay=0)
        _executor.disconnect_vpn(log_lvl=logger.DEBUG, silent=True)
        _executor.connect_vpn(_current_acc, is_default=False)

    executor = VPNClientExecutor(vpn_opts).require_install().probe()
    is_running = executor.is_running(silent=True)
    default_acc, current_acc, svc_opts, backup_dir = executor.backup_config()
    if is_running:
        executor.disconnect_vpn(force=True)
    executor.uninstall(keep_vpn=False, keep_dnsmasq=True, service_opts=svc_opts)
    logger.info(f'Re-install VPN client into [{vpn_opts.vpn_dir}]...')
    executor.install(service_opts=svc_opts, auto_startup=False)
    executor.restore_config(backup_dir)
    _reconnect_vpn(executor, default_acc, current_acc)
    logger.done()


@cli.command(name="add", help="Add new VPN Account")
@vpn_server_opts
@click.option("-ca", "--account", type=str, help='VPN Client account name. Default is VPN hub')
@click.option("-cd", "--default", "is_default", type=bool, flag_value=True, help='Set VPN Client Account is default')
@vpn_auth_opts
@click.option("--no-connect", type=bool, flag_value=True, help='Just add VPN account without open connection')
@click.option("--hostname", 'dns_prefix', type=str, hidden=True,
              help='Use custom hostname as prefix DNS instead of depends on VPN user')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __add(vpn_opts: ClientOpts, server_opts: ServerOpts, auth_opts: AuthOpts, account: str, is_default: bool,
          dns_prefix: str, no_connect: bool):
    executor = VPNClientExecutor(vpn_opts).require_install().probe()
    hostname = dns_prefix or executor.generate_host_name(server_opts.hub, auth_opts.user, log_lvl=logger.TRACE)
    acc = AccountInfo(server_opts.hub, account, hostname, is_default)
    logger.info(f'Setup VPN Client with VPN account [{acc.account}]...')
    setup_cmd = {
        'NicCreate': acc.account,
        'AccountCreate': f'{acc.account} /SERVER:{server_opts.server} /HUB:{acc.hub} /USERNAME:{auth_opts.user} /NICNAME:{acc.account}'
    }
    setup_cmd = {**setup_cmd, **auth_opts.setup(acc.account)}
    setup_cmd = setup_cmd if no_connect else {**setup_cmd, **{'AccountConnect': acc.account}}
    setup_cmd = setup_cmd if not acc.is_default else {**setup_cmd, **{'AccountStartupSet': acc.account}}
    if not no_connect:
        executor.disconnect_vpn(log_lvl=logger.DEBUG, silent=True)
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], acc.account, silent=True)
    executor.exec_command(setup_cmd)
    executor.storage.create_or_update(acc, connect=not no_connect)
    executor.device.ip_resolver.create_config(acc.account, {'{{HOST_NAME}}': hostname})
    executor.device.dns_resolver.tweak_on_nic(vpn_opts.account_to_nic(acc.account))
    executor.lease_vpn_service(is_enable=acc.is_default, is_restart=not no_connect, is_lease_ip=no_connect,
                               account=acc.account)
    logger.done()


@cli.command(name='delete', help='Delete one or many VPN account')
@click.argument('accounts', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __delete(vpn_opts: ClientOpts, accounts):
    logger.info(f'Delete VPN account [{accounts}] and stop/disable VPN service if it\'s a current VPN connection...')
    if accounts is None or len(accounts) == 0:
        logger.error('Must provide at least account')
        sys.exit(ErrorCode.INVALID_ARGUMENT)
    executor = VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO)
    is_disable, is_stop = False, False
    for account in accounts:
        executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, True, logger.INFO)
        is_default, is_current = executor.storage.remove(account)
        is_stop = is_current or is_stop
        is_disable = is_default or is_disable
    if is_stop or is_disable:
        executor.shutdown_vpn_service(is_stop=is_stop, is_disable=is_disable)
    logger.done()


@cli.command(name="set-default", help="Set VPN default connection in startup by given VPN account")
@click.argument('account', nargs=1)
@click.option('--connect', type=bool, default=False, flag_value=True, help='Open connection immediately')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __set_default(vpn_opts: ClientOpts, account: str, connect: bool):
    logger.info(f'Set VPN account [{account}] as startup VPN connection ' +
                f'{"then connect immediately" if connect else ""}...')
    executor = VPNClientExecutor(vpn_opts).require_install().probe()
    executor.exec_command('AccountStartupSet', params=account, log_lvl=logger.INFO)
    executor.storage.set_default(account)
    if connect:
        executor.disconnect_vpn(silent=False)
        executor.storage.set_current(account)
    executor.lease_vpn_service(is_enable=True, is_restart=connect, is_lease_ip=False, account=account)
    logger.done()


@cli.command(name='connect', help='Connect to VPN connection by given VPN account')
@click.argument('account', nargs=1)
@click.option("-cd", "--default", "is_default", type=bool, flag_value=True, help='Set VPN Client Account is default')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __connect(vpn_opts: ClientOpts, account: str, is_default: bool):
    executor = VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO)
    executor.disconnect_vpn(log_lvl=logger.DEBUG, silent=True)
    executor.connect_vpn(account, is_default, log_lvl=logger.INFO)
    logger.done()


@cli.command(name='disconnect', help='Disconnect VPN connection')
@click.option("--disable", type=bool, default=False, flag_value=True, help='Disable VPN Client service')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __disconnect(disable: bool, vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO)
    executor.disconnect_vpn(silent=False)
    executor.shutdown_vpn_service(is_stop=True, is_disable=disable)
    logger.done()


@cli.command(name='status', help='Get current VPN status')
@click.option('--json', 'is_json', default=False, flag_value=True, help='Output to json')
@click.option('-d', '--domain', 'domains', multiple=True, help='Test connection to one or more domains')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __status(vpn_opts: ClientOpts, is_json: bool, domains: list):
    executor = VPNClientExecutor(vpn_opts, adhoc_task=True).probe()
    installed = executor.is_installed(silent=True)
    vpn_service = executor.vpn_service
    vpn_acc = executor.storage.get_current() or None
    svc_status = executor.device.unix_service.status(vpn_service)
    dns_status = True
    status = {
        'app_state': installed, 'app_state_msg': 'Installed' if installed else 'Not yet installed',
        'app_dir': executor.opts.vpn_dir if installed else None,
        'service': executor.vpn_service, 'service_status': svc_status.value,
        'vpn_pid': executor.pid_handler.current_pid, 'vpn_account': vpn_acc,
        'vpn_status': False, 'vpn_status_msg': None, 'vpn_ip': None
    }
    if vpn_acc:
        status['vpn_status_msg'] = executor.vpn_status(vpn_acc)
        status['vpn_status'] = 'Connection Completed (Session Established)' == status['vpn_status_msg']
        status['vpn_ip'] = executor.device.ip_resolver.get_vpn_ip(ClientOpts.account_to_nic(vpn_acc))
    if domains:
        _domains = {domain: NetworkHelper.lookup_ipv4_by_domain(domain) for domain in domains}
        dns_status = next(filter(lambda r: r[1] is False, _domains.values()), ('', True))[1]
        status['domains'] = {k: v[0] for k, v in _domains.items()}
        status['dns_status'] = dns_status
    if is_json:
        print(JsonHelper.to_json(status))
    else:
        logger.info(f'VPN Application   : {status["app_state_msg"]} - {status["app_dir"]}')
        logger.info(f'VPN Service       : {status["service"]} - {status["service_status"]} - PID[{status["vpn_pid"]}]')
        logger.info(f'VPN Account       : {status["vpn_account"]} - {status["vpn_status_msg"]}')
        logger.info(f'VPN IP address    : {status["vpn_ip"]}')
        if domains:
            logger.info(f'DNS status        : {"Good" if status["dns_status"] else "Unable resolve all given domains"}')
            [logger.info(f'Domain IPv4       : {k} - {v}') for k, v in status['domains'].items()]
        logger.sep(logger.INFO)
    if installed and not status["vpn_status"] or not status["vpn_ip"] or not svc_status.is_running() or not dns_status:
        sys.exit(ErrorCode.VPN_SERVICE_IS_NOT_WORKING)


@cli.command(name="trust", help="Trust VPN Server cert")
@click.option("-ca", "--account", type=str, help="Client Account for manage VPN connection")
@click.option("-cck", "--cert-key", type=click.Path(exists=True, resolve_path=True), help="VPN Server Cert")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __add_trust_server(vpn_opts: ClientOpts, account: str, cert_key: str):
    logger.info("Enable Trust VPN Server on VPN client...")
    commands = {'AccountServerCertSet': f'{account} /LOADCERT:{cert_key}', 'AccountServerCertEnable': account}
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe().exec_command(commands)
    logger.done()


@cli.command(name="list", help="Get all VPN Accounts")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __list(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe().exec_command('AccountList',
                                                                                        log_lvl=logger.INFO)


@cli.command(name='detail', help='Get detail VPN configuration and status by one or many accounts')
@click.argument('accounts', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __detail(vpn_opts: ClientOpts, accounts):
    if accounts is None or len(accounts) == 0:
        logger.error('Must provide at least account')
        sys.exit(ErrorCode.INVALID_ARGUMENT)
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe().exec_command('AccountGet', params=accounts,
                                                                                        log_lvl=logger.INFO)


@cli.command(name='log', help='Get VPN log')
@click.option('-n', '--lines', default=10, help='output the last NUM lines')
@click.option('-f', '--follow', default=False, flag_value=True, help='Follow logs')
@click.option('--date', type=str, help='VPN client log at date by format "yyyymmdd"')
@click.option('--another', type=str, help='Another file', hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __log(vpn_opts: ClientOpts, date, lines, follow, another):
    f = another or vpn_opts.log_file if not date else vpn_opts.get_log_file(date)
    for line in FileHelper.tail(f, prev=lines, follow=follow):
        print(line.strip())


@cli.command(name="version", help="VPN Version")
@click.option('--json', 'is_json', default=False, flag_value=True, help='Output to json')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
def __version(vpn_opts: ClientOpts, is_json: bool):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, is_json=is_json)


@cli.command(name="about", help="Show VPN software info")
@click.option('-l', '--license', 'show_license', default=False, flag_value=True, help='Show licenses')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
def __about(vpn_opts: ClientOpts, show_license: bool):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, True, show_license)


@cli.command(name='command', help='Execute Ad-hoc VPN command', hidden=True)
@click.argument("command", type=str, required=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME, hidden=False)
@verbose_opts
@permission
def __execute(vpn_opts: ClientOpts, command):
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().exec_command(command, log_lvl=logger.INFO)


@cli.command(name="start", help="Start VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __start_service(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO)
    executor.pre_exec(log_lvl=logger.INFO)
    vpn_acc = executor.storage.get_default()
    if vpn_acc:
        executor.storage.set_current(vpn_acc)
        executor.lease_vpn_ip(vpn_acc, log_lvl=logger.INFO)
    else:
        executor.device.ip_resolver.renew_all_ip()


@cli.command(name="stop", help="Stop VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __stop_service(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO)
    executor.post_exec(log_lvl=logger.INFO)
    executor.storage.set_current('')
    executor.cleanup_zombie_vpn()
    executor.device.ip_resolver.renew_all_ip()


@cli.command(name="dns", help="Update VPN DNS server", hidden=True)
@click.argument('reason', type=click.Choice([r.name for r in DHCPReason]), required=True)
@click.option('-n', '--nic', type=str, default='', help='VPN network interface card')
@click.option('-nns', '--new-nameservers', type=str, default='', help='New domain name servers')
@click.option('-ons', '--old-nameservers', type=str, default='', help='Previous domain name servers')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME, hidden=False)
@click.option('--debug', default=False, flag_value=True, help='Enable write debug into /tmp/vpn_dns')
@verbose_opts
@permission
def __dns(vpn_opts: ClientOpts, nic: str, reason: str, new_nameservers: str, old_nameservers: str, debug: bool):
    def _manual_discover(_executor: VPNClientExecutor, _cur_acc: AccountInfo):
        dns_resolver = _executor.device.dns_resolver
        loop_interval(lambda: len(dns_resolver.query_vpn_nameservers(_cur_acc.hub)) > 0,
                      'Unable read DHCP status', exit_if_error=True, max_retries=10)
        _nic = executor.opts.account_to_nic(current.account)
        _new_nameservers = ','.join(dns_resolver.query_vpn_nameservers(_cur_acc.hub))
        return _nic, _new_nameservers, DHCPReason.BOUND

    logger.info(f'Update DNS with {reason}::{nic}...')
    _reason = DHCPReason[reason]
    is_manual_discover = _reason is DHCPReason.SCAN
    if not vpn_opts.is_vpn_nic(nic) and not is_manual_discover:
        logger.warn(f'NIC[{nic}] does not belong to VPN service')
        sys.exit(0)
    executor = VPNClientExecutor(vpn_opts).require_install().probe(silent=True, log_lvl=logger.INFO)
    current = executor.storage.get_current(info=True)
    if not current:
        current = executor.storage.find(executor.opts.nic_to_account(nic))
        if not current:
            logger.warn(f'Not found any VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_FOUND)
    if is_manual_discover:
        nic, new_nameservers, _reason = _manual_discover(executor, current)
    if executor.opts.nic_to_account(nic) != current.account:
        logger.warn(f'NIC[{nic}] does not meet current VPN account')
        sys.exit(ErrorCode.VPN_ACCOUNT_NOT_MATCH)
    if debug:
        now = datetime.now().isoformat()
        FileHelper.write_file(FileHelper.tmp_dir().joinpath('vpn_dns'), append=True,
                              content=f"{now}::{reason}::{nic}::{new_nameservers}::{old_nameservers}\n")
    executor.device.dns_resolver.resolve(executor.vpn_service, _reason, current.hub, new_nameservers, old_nameservers)
    if is_manual_discover:
        executor.device.ip_resolver.renew_all_ip()


@cli.command(name="tree", help="Tree inside binary", hidden=True)
@click.option("-l", "--level", type=int, default=1, help="Tree level")
def __inside(level):
    FileHelper.tree(dir_path=EnvHelper.get_base_path(), level=level)


if __name__ == "__main__":
    cli()
