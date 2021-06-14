#!/usr/bin/python3
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Union, List, Sequence

import click

import src.utils.logger as logger
from src.client.device_resolver import DeviceResolver, DHCPReason
from src.client.version import APP_VERSION, HASH_VERSION
from src.executor.shell_executor import SystemHelper
from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils import about
from src.utils.constants import ErrorCode, AppEnv
from src.utils.downloader import download, VPNType, downloader_opt_factory, DownloaderOpt
from src.utils.helper import FileHelper, loop_interval, JsonHelper, TextHelper, EnvHelper, NetworkHelper
from src.utils.opts_shared import CLI_CTX_SETTINGS, permission, verbose_opts, UnixServiceOpts, unix_service_opts, \
    dev_mode_opts
from src.utils.opts_vpn import AuthOpts, vpn_auth_opts, ServerOpts, vpn_server_opts, VpnDirectory, vpn_dir_opts_factory


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


class AccountStorage:
    def __init__(self, account_file: Union[str, Path]):
        self._account_file = account_file

    def _load(self):
        return JsonHelper.read(self._account_file, strict=False)

    def create_or_update(self, account: AccountInfo, _connect: bool):
        data = self._load()
        accounts = self._accounts(data)
        accounts = {**accounts, **account.to_json()}
        self._dump(data=data, _accounts=accounts, _current=account.account if _connect else None,
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
        accounts = [accounts] if isinstance(accounts, str) else accounts
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
            logger.log(log_lvl, f'VPN PID [{pid}]')
            return True
        self.cleanup()
        return False

    def cleanup(self):
        FileHelper.rm(self._pid_files())

    def _find_pid(self, log_lvl=logger.TRACE) -> int:
        return next((pid for pid in map(lambda x: self._check_pid(x, log_lvl), self._pid_files(log_lvl)) if pid), 0)

    def _pid_files(self, log_lvl=logger.TRACE) -> list:
        files = FileHelper.find_files(self.opts.vpn_dir, '.pid_*')
        logger.log(log_lvl, f'PID files [{",".join(files)}]')
        return files

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
        self._prev_is_run = False

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        logger.log(log_lvl, 'Start VPN Client if not yet running...')
        if not self.is_installed(silent, log_lvl):
            return
        if self.pid_handler.is_running():
            self._prev_is_run = True
            return
        SystemHelper.exec_command(f'{self.opts.vpnclient} start', log_lvl=logger.down_lvl(log_lvl))
        time.sleep(1)
        if not self.pid_handler.is_running(log_lvl=logger.down_lvl(log_lvl)):
            logger.error('Unable start VPN Client')
            sys.exit(ErrorCode.VPN_START_FAILED)

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        logger.log(log_lvl, 'Stop VPN Client if applicable...')
        if not self.is_installed(silent, log_lvl):
            return
        if (self._prev_is_run or not self.adhoc_task) and not kwargs.get('_force_stop', False):
            return
        lvl = logger.down_lvl(log_lvl)
        if self.pid_handler.is_running(log_lvl=lvl):
            SystemHelper.exec_command(f'{self.opts.vpnclient} stop', silent=silent, log_lvl=lvl)
            self._cleanup_zombie_vpn(1, log_lvl=lvl)
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

    def get_vpn_status(self, vpn_acc: str) -> dict:
        if not vpn_acc:
            return {'connected': False}
        try:
            ss = self.exec_command('AccountStatusGet', params=vpn_acc, silent=True, log_lvl=logger.DEBUG)
            ss_msg = TextHelper.awk(next(iter(TextHelper.grep(ss, r'Session Status.+')), None), sep='|', pos=1).strip()
            return {'connected': ss_msg == 'Connection Completed (Session Established)', 'msg': ss_msg}
        except Exception as err:
            logger.debug(f'Something wrong when getting VPN status. Error[{err}]')
            return {'connected': False}

    def do_install(self, service_opts: UnixServiceOpts, auto_startup: bool = False):
        FileHelper.mkdirs(self.opts.vpn_dir.parent)
        FileHelper.unpack_archive(ClientOpts.get_resource(ClientOpts.VPN_ZIP), self.opts.vpn_dir)
        FileHelper.mkdirs([self.opts.vpn_dir, self.opts.runtime_dir])
        FileHelper.chmod(self.opts.runtime_dir, mode=0o0755)
        FileHelper.chmod([os.path.join(self.opts.vpn_dir, p) for p in ('vpnclient', 'vpncmd')], mode=0o0755)
        _, cmd = EnvHelper.build_executable_command()
        svc_opts = self._standard_service_opt(service_opts)
        self.device.unix_service.create(svc_opts, {
            '{{WORKING_DIR}}': f'{self.opts.vpn_dir}',
            '{{VPN_DESC}}': svc_opts.service_name,
            '{{START_CMD}}': f'{cmd} start --vpn-dir {self.opts.vpn_dir}',
            '{{STOP_CMD}}': f'{cmd} stop --vpn-dir {self.opts.vpn_dir}'
        }, auto_startup)
        self._dump_cache_service(svc_opts)
        self.device.ip_resolver.add_hook(svc_opts.service_name,
                                         {'{{WORKING_DIR}}': f'{self.opts.vpn_dir}', '{{VPN_CLIENT_CLI}}': cmd})
        self.device.dns_resolver.create_config(svc_opts.service_name)
        self.storage.empty()
        self.opts.export_env()

    def do_uninstall(self, keep_vpn: bool = True, keep_dnsmasq: bool = True, service_opts: UnixServiceOpts = None,
                     log_lvl: int = logger.INFO):
        vpn_service = self._standard_service_opt(service_opts).service_name
        logger.info(f'Uninstall VPN service [{vpn_service}]...')
        self.do_delete([a.account for a in self.storage.list()], force_stop=True, log_lvl=log_lvl)
        if not keep_vpn:
            logger.log(log_lvl, f'Remove VPN Client [{self.opts.vpn_dir}]...')
            self.device.ip_resolver.remove_hook(vpn_service)
            self.opts.remove_env()
            FileHelper.rm(self.opts.vpn_dir)
        self.device.dns_resolver.cleanup_config(vpn_service, keep_dnsmasq=keep_dnsmasq)

    def do_connect(self, account: str, log_lvl: int = logger.INFO):
        if not account:
            logger.error(f'VPN account is not correct')
            sys.exit(ErrorCode.INVALID_ARGUMENT)
        acc = self.storage.find(account)
        if not acc:
            logger.error(f'Not found VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_FOUND)
        logger.log(log_lvl, f'Connect VPN account [{account}]...')
        self.storage.create_or_update(acc, _connect=True)
        self.exec_command(['AccountConnect'], params=account)
        self.lease_vpn_service(is_enable=acc.is_default, is_restart=acc.is_default, is_lease_ip=not acc.is_default,
                               account=acc.account)

    def do_delete(self, accounts: Sequence[str], log_lvl: int = logger.INFO, silent: bool = True, force_stop=False):
        cur_acc = self.storage.get_current()
        is_disable, is_stop = False, force_stop or cur_acc is None or cur_acc == ''
        for acc in accounts:
            logger.log(log_lvl, f'Delete VPN account [{acc}]...')
            is_default, is_current = self.storage.remove(acc)
            is_stop = is_current or is_stop
            is_disable = is_default or is_disable
            commands = ['AccountDisconnect', 'AccountDelete', 'NicDelete']
            if is_default:
                commands.insert(1, 'AccountStartupRemove')
                self.storage.set_default('')
            self.exec_command(commands, acc, silent, log_lvl)
        self.shutdown_vpn_service(is_stop=is_stop, is_disable=is_disable, log_lvl=log_lvl)

    def do_disconnect(self, accounts: Sequence[str], must_disable_service=False, log_lvl: int = logger.INFO,
                      silent: bool = True):
        cur_acc = self.storage.get_current()
        is_stop = cur_acc is None or cur_acc == ''
        for acc in accounts:
            logger.log(log_lvl, f'Disconnect VPN account [{acc}]...')
            self.exec_command('AccountDisconnect', params=acc, log_lvl=logger.down_lvl(log_lvl), silent=silent)
            self.device.ip_resolver.release_ip(acc, self.opts.account_to_nic(acc))
            self.device.ip_resolver.cleanup_zombie(f'--no-pid.* {self.opts.account_to_nic(acc)}')
            is_stop = acc == cur_acc or is_stop
        if is_stop:
            self.shutdown_vpn_service(is_stop=True, is_disable=must_disable_service, log_lvl=log_lvl)

    def do_switch_default_acc(self, account: str):
        def_acc = self.storage.get_default()
        commands = {} if not def_acc else {'AccountStartupRemove': def_acc}
        self.storage.set_default(account)
        return self.exec_command({**commands, 'AccountStartUpSet': account}, slient=True)

    def do_disconnect_current(self, must_disable_service=False, log_lvl: int = logger.INFO, silent: bool = True):
        account = self.storage.get_current()
        if not account:
            logger.log(logger.down_lvl(log_lvl), 'Not found any VPN account')
            return
        self.do_disconnect([account], must_disable_service=must_disable_service, log_lvl=log_lvl, silent=silent)

    def do_force_start(self, log_lvl=logger.INFO):
        vpn_acc = self.storage.get_default()
        if vpn_acc:
            self.storage.set_current(vpn_acc)
            self.pre_exec(log_lvl=log_lvl)
            self.lease_vpn_ip(vpn_acc, log_lvl=log_lvl)

    def do_force_stop(self, log_lvl=logger.INFO):
        self.storage.set_current('')
        self.post_exec(log_lvl=log_lvl, _force_stop=True)
        if self.device.dns_resolver.is_connman():
            self.device.ip_resolver.renew_all_ip()
        else:
            self.device.dns_resolver.restart()

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
        logger.log(log_lvl, 'Wait a VPN session is established...')
        loop_interval(lambda: self.get_vpn_status(account)['connected'],
                      'Unable connect VPN. Please check log for more detail', max_retries=3, interval=1)
        nic = self.opts.account_to_nic(account)
        if self.device.dns_resolver.is_connman():
            logger.log(logger.WARN, f'Please lease VPN IP manually by ' +
                       f'[{self.device.ip_resolver.lease_ip(account, nic, daemon=True, is_execute=False)}]')
            return
        logger.log(log_lvl, 'Wait a VPN IP is leased...')
        self.device.ip_resolver.lease_ip(account, nic, daemon=True)

    def shutdown_vpn_service(self, is_stop=True, is_disable=False, vpn_service: str = None, log_lvl=logger.DEBUG):
        vpn_service = vpn_service or self.vpn_service
        if is_disable:
            self.device.unix_service.disable(vpn_service)
        if is_stop:
            self.device.unix_service.stop(vpn_service)
            self.storage.set_current('')
            self._cleanup_zombie_vpn(log_lvl=log_lvl)
            if self.device.dns_resolver.is_connman():
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

    def restore_config(self, backup_dir: Path, keep_backup: bool):
        logger.info(f'Restore VPN configuration [{backup_dir}] to [{self.opts.vpn_dir}]...')
        FileHelper.copy(backup_dir.joinpath(self.opts.VPN_CONFIG_FILE), self.opts.config_file, force=True)
        FileHelper.copy(backup_dir.joinpath(self.opts.RUNTIME_FOLDER), self.opts.runtime_dir, force=True)
        FileHelper.rm(backup_dir, force=not keep_backup)

    def _cleanup_zombie_vpn(self, delay=1, log_lvl=logger.DEBUG):
        time.sleep(delay)
        logger.log(log_lvl, 'Cleanup the VPN zombie processes...')
        SystemHelper.kill_by_process(f'{self.vpn_dir}/vpnclient execsvc', silent=True, log_lvl=logger.down_lvl(log_lvl))
        self.device.ip_resolver.cleanup_zombie(f'vpn_')

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

    def tweak_network_per_account(self, account: str, hostname: str):
        # self.device.ip_resolver.create_config(account, {'{{HOST_NAME}}': hostname})
        self.device.dns_resolver.tweak_on_nic(self.opts.account_to_nic(account))


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
def install(vpn_opts: ClientOpts, svc_opts: UnixServiceOpts, auto_startup: bool, auto_dnsmasq: bool, dnsmasq: bool,
            force: bool):
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    dns_resolver = executor.device.dns_resolver
    if not dnsmasq and not dns_resolver.is_connman():
        logger.error('Only support dnsmasq as DNS resolver in first version')
        sys.exit(ErrorCode.NOT_YET_SUPPORTED)
    if executor.is_installed(silent=True):
        if force:
            logger.warn('VPN service is already installed. Try to remove then reinstall...')
            executor.do_uninstall(keep_vpn=False, keep_dnsmasq=True)
        else:
            logger.error('VPN service is already installed')
            sys.exit(ErrorCode.VPN_ALREADY_INSTALLED)
    if dnsmasq and not dns_resolver.is_dnsmasq_available() and not dns_resolver.is_connman():
        executor.device.install_dnsmasq(auto_dnsmasq)
    logger.info(f'Installing VPN client into [{vpn_opts.vpn_dir}] and register service[{svc_opts.service_name}]...')
    executor.do_install(svc_opts, auto_startup)
    logger.done()


@cli.command(name="uninstall", help="Stop and disable VPN client and *nix service")
@click.option("-f", "--force", type=bool, flag_value=True, help="If force is enabled, VPN service will be removed")
@click.option("--keep-dnsmasq/--no-keep-dnsmasq", type=bool, default=True, flag_value=False,
              help="By default, dnsmasq is used as local DNS cache.")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def uninstall(vpn_opts: ClientOpts, force: bool = False, keep_dnsmasq: bool = True):
    VPNClientExecutor(vpn_opts).probe().do_uninstall(keep_vpn=not force, keep_dnsmasq=keep_dnsmasq)
    logger.done()


@cli.command(name="upgrade", help="Upgrade VPN client")
@click.option("--keep-backup", type=bool, flag_value=True, help="Keep backup file")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def upgrade(keep_backup: bool, vpn_opts: ClientOpts):
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
        _executor.do_disconnect_current(log_lvl=logger.DEBUG)
        _executor.do_connect(_current_acc)

    executor = VPNClientExecutor(vpn_opts).require_install().probe()
    default_acc, current_acc, svc_opts, backup_dir = executor.backup_config()
    executor.do_uninstall(keep_vpn=False, keep_dnsmasq=True, service_opts=svc_opts)
    logger.info(f'Re-install VPN client into [{vpn_opts.vpn_dir}]...')
    executor.do_install(service_opts=svc_opts, auto_startup=False)
    executor.restore_config(backup_dir, keep_backup)
    _reconnect_vpn(executor, default_acc, current_acc)
    logger.done()


@cli.command(name="add", help="Add and connect new VPN Account")
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
def add(vpn_opts: ClientOpts, server_opts: ServerOpts, auth_opts: AuthOpts, account: str, is_default: bool,
        dns_prefix: str, no_connect: bool):
    is_connect = not no_connect
    executor = VPNClientExecutor(vpn_opts).require_install().probe()
    hostname = dns_prefix or executor.generate_host_name(server_opts.hub, auth_opts.user, log_lvl=logger.TRACE)
    acc = AccountInfo(server_opts.hub, account, hostname, is_default)
    logger.info(f'Setup VPN Client with VPN account [{acc.account}]...')
    executor.tweak_network_per_account(acc.account, hostname)
    setup_cmd = {
        'AccountCreate': f'{acc.account} /SERVER:{server_opts.server} /HUB:{acc.hub} /USERNAME:{auth_opts.user} /NICNAME:{acc.account}'
    }
    setup_cmd = {**setup_cmd, **auth_opts.setup(acc.account)}
    setup_cmd = setup_cmd if not is_connect else {**setup_cmd, **{'AccountConnect': acc.account}}
    if acc.is_default or is_connect:
        executor.do_disconnect_current(log_lvl=logger.DEBUG)
    executor.exec_command(['NicCreate', 'AccountDisconnect', 'AccountDelete'], acc.account, silent=True)
    executor.exec_command(setup_cmd)
    executor.storage.create_or_update(acc, _connect=is_connect)
    if acc.is_default:
        executor.do_switch_default_acc(acc.account)
    executor.lease_vpn_service(account=acc.account, is_enable=acc.is_default, is_restart=acc.is_default,
                               is_lease_ip=not acc.is_default and is_connect)
    logger.done()


@cli.command(name='delete', help='Delete one or many VPN account')
@click.argument('accounts', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def delete(vpn_opts: ClientOpts, accounts):
    logger.info(f'Delete VPN account [{accounts}] and stop/disable VPN service if it\'s a current VPN connection...')
    if accounts is None or len(accounts) == 0:
        logger.error('Must provide at least account')
        sys.exit(ErrorCode.INVALID_ARGUMENT)
    VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO).do_delete(accounts)
    logger.done()


@cli.command(name="set-default", help="Set VPN default connection in startup by given VPN account")
@click.argument('account', nargs=1)
@click.option('--connect', 'is_connect', type=bool, default=False, flag_value=True, help='Open connection immediately')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def set_default(vpn_opts: ClientOpts, account: str, is_connect: bool):
    logger.info(f'Set VPN account [{account}] as startup VPN connection ' +
                f'{"then connect immediately" if is_connect else ""}...')
    executor = VPNClientExecutor(vpn_opts, adhoc_task=not is_connect).require_install().probe()
    executor.do_switch_default_acc(account)
    if is_connect:
        executor.do_disconnect_current()
    executor.lease_vpn_service(is_enable=True, is_restart=is_connect, is_lease_ip=False, account=account)
    logger.done()


@cli.command(name='connect', help='Connect to VPN connection by given VPN account')
@click.argument('account', nargs=1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def connect(vpn_opts: ClientOpts, account: str):
    executor = VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO)
    def_acc = executor.storage.get_default()
    if account and def_acc == account:
        executor.do_disconnect_current(log_lvl=logger.DEBUG)
        executor.lease_vpn_service(is_enable=True, is_restart=True, is_lease_ip=False)
    else:
        cur_acc = executor.storage.get_current()
        executor.do_disconnect([account, cur_acc] if cur_acc else [account], log_lvl=logger.DEBUG)
        executor.do_connect(account, log_lvl=logger.INFO)
    logger.done()


@cli.command(name='disconnect', help="""Disconnect one or more VPN connection.\n
             If no VPN account is provided, this command will try to disconnect current VPN connection""")
@click.argument('accounts', nargs=-1)
@click.option("--all", "_all", type=bool, default=False, flag_value=True, help='Disconnect all VPN connections')
@click.option("--disable", type=bool, default=False, flag_value=True, help='Disable VPN Client service')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def disconnect(vpn_opts: ClientOpts, accounts: list, _all: bool, disable: bool):
    executor = VPNClientExecutor(vpn_opts).require_install().probe(log_lvl=logger.INFO)
    if not accounts and not _all:
        executor.do_disconnect_current(must_disable_service=disable, silent=False)
    else:
        list_acc = [acc.account for acc in executor.storage.list() if _all or acc.account in accounts]
        executor.do_disconnect(list_acc, must_disable_service=disable, log_lvl=logger.INFO)
    logger.done()


@cli.command(name='status', help='Get current VPN status')
@click.option('--json', 'is_json', default=False, flag_value=True, help='Output to json')
@click.option('-d', '--domain', 'domains', multiple=True, help='Test connection to one or more domains')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def status(vpn_opts: ClientOpts, is_json: bool, domains: list):
    executor = VPNClientExecutor(vpn_opts, adhoc_task=True).probe()
    installed = executor.is_installed(silent=True)
    vpn_service = executor.vpn_service
    vpn_acc = executor.storage.get_current() or None
    svc_status = executor.device.unix_service.status(vpn_service)
    dns_status = True
    ss = {
        'app_state': installed, 'app_state_msg': 'Installed' if installed else 'Not yet installed',
        'app_dir': executor.opts.vpn_dir if installed else None,
        'service': executor.vpn_service, 'service_status': svc_status.value,
        'vpn_pid': executor.pid_handler.current_pid, 'vpn_account': vpn_acc,
        'vpn_status': False, 'vpn_status_msg': None, 'vpn_ip': None
    }
    if vpn_acc:
        vpn_ss = executor.get_vpn_status(vpn_acc)
        ss = {**ss, **{'vpn_status_msg': vpn_ss.get('msg'), 'vpn_status': vpn_ss.get('connected')},
              'vpn_ip': executor.device.ip_resolver.get_vpn_ip(ClientOpts.account_to_nic(vpn_acc))}
    if domains:
        _domains = {domain: NetworkHelper.lookup_ipv4_by_domain(domain) for domain in domains}
        dns_status = next(filter(lambda r: r[1] is False, _domains.values()), ('', True))[1]
        ss['domains'] = {k: v[0] for k, v in _domains.items()}
        ss['dns_status'] = dns_status
    if is_json:
        print(JsonHelper.to_json(ss))
    else:
        logger.info(f'VPN Application   : {ss["app_state_msg"]} - {ss["app_dir"]}')
        logger.info(f'VPN Service       : {ss["service"]} - {ss["service_status"]} - PID[{ss["vpn_pid"]}]')
        logger.info(f'VPN Account       : {ss["vpn_account"]} - {ss["vpn_status_msg"]}')
        logger.info(f'VPN IP address    : {ss["vpn_ip"]}')
        if domains:
            logger.info(f'DNS status        : {"Good" if ss["dns_status"] else "Unable resolve all given domains"}')
            [logger.info(f'Domain IPv4       : {k} - {v}') for k, v in ss['domains'].items()]
        logger.sep(logger.INFO)
    if installed and not ss["vpn_status"] or not ss["vpn_ip"] or not svc_status.is_running() or not dns_status:
        sys.exit(ErrorCode.VPN_SERVICE_IS_NOT_WORKING)


@cli.command(name="trust", help="Trust VPN Server cert")
@click.option("-ca", "--account", type=str, help="Client Account for manage VPN connection")
@click.option("-cck", "--cert-key", type=click.Path(exists=True, resolve_path=True), help="VPN Server Cert")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def add_trust_server(vpn_opts: ClientOpts, account: str, cert_key: str):
    logger.info("Enable Trust VPN Server on VPN client...")
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe().exec_command(
        {'AccountServerCertSet': f'{account} /LOADCERT:{cert_key}', 'AccountServerCertEnable': account})
    logger.done()


@cli.command(name="list", help="Get all VPN Accounts")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def list_account(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe().exec_command('AccountList',
                                                                                        log_lvl=logger.INFO)


@cli.command(name='detail', help='Get detail VPN configuration and status by one or many accounts')
@click.argument('accounts', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def detail(vpn_opts: ClientOpts, accounts):
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
def log(vpn_opts: ClientOpts, date, lines, follow, another):
    f = another or vpn_opts.log_file if not date else vpn_opts.get_log_file(date)
    for line in FileHelper.tail(f, prev=lines, follow=follow):
        print(line.strip())


@cli.command(name="version", help="VPN Version")
@click.option('--json', 'is_json', default=False, flag_value=True, help='Output to json')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
def show_version(vpn_opts: ClientOpts, is_json: bool):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, is_json=is_json)


@cli.command(name="about", help="Show VPN software info")
@click.option('-l', '--license', 'show_license', default=False, flag_value=True, help='Show licenses')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
def show_about(vpn_opts: ClientOpts, show_license: bool):
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
    VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO).do_force_start()


@cli.command(name="stop", help="Stop VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __stop_service(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO).do_force_stop()


@cli.command(name="dns", help="Discover VPN DNS server", hidden=True)
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
    logger.info(f'Discover DNS with {reason}::{nic}...')
    _reason = DHCPReason[reason]
    if not vpn_opts.is_vpn_nic(nic):
        logger.warn(f'NIC[{nic}] does not belong to VPN service')
        sys.exit(0)
    executor = VPNClientExecutor(vpn_opts, adhoc_task=True).require_install().probe(silent=True, log_lvl=logger.INFO)
    current = executor.storage.get_current(info=True)
    if not current:
        current = executor.storage.find(executor.opts.nic_to_account(nic))
        if not current:
            logger.warn(f'Not found any VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_FOUND)
    if executor.opts.nic_to_account(nic) != current.account:
        logger.warn(f'NIC[{nic}] does not meet current VPN account')
        sys.exit(ErrorCode.VPN_ACCOUNT_NOT_MATCH)
    if debug:
        now = datetime.now().isoformat()
        FileHelper.write_file(FileHelper.tmp_dir().joinpath('vpn_dns'), append=True,
                              content=f"{now}::{reason}::{nic}::{new_nameservers}::{old_nameservers}\n")
    executor.device.dns_resolver.resolve(executor.vpn_service, _reason, current.hub, new_nameservers, old_nameservers)


@cli.command(name="tree", help="Tree inside binary", hidden=True)
@click.option("-l", "--level", type=int, default=1, help="Tree level")
def __inside(level):
    FileHelper.tree(dir_path=EnvHelper.get_base_path(), level=level)


if __name__ == "__main__":
    cli()
