#!/usr/bin/python3
import os
import re
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
from src.utils.helper import resource_finder, FileHelper, build_executable_command, grep, awk, tail, \
    get_base_path, tree, loop_interval, JsonHelper, binary_name
from src.utils.opts_shared import CLI_CTX_SETTINGS, permission, verbose_opts, UnixServiceOpts, unix_service_opts, \
    dev_mode_opts
from src.utils.opts_vpn import AuthOpts, vpn_auth_opts, ServerOpts, vpn_server_opts, VpnDirectory, \
    vpn_dir_opts_factory


class ClientOpts(VpnDirectory):
    VPNCLIENT_ZIP = 'vpnclient.zip'
    VPN_HOME = '/app/vpnclient'

    @property
    def config_file(self):
        return self.vpn_dir.joinpath('vpn_client.config')

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
        return resource_finder(file_name, os.path.dirname(__file__))

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
        binary = binary_name()
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
        accounts = self._accounts()
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
        _accounts = self._accounts()
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
        self.current_pid = None

    def is_running(self, log_lvl=logger.DEBUG) -> bool:
        self.current_pid = self._find_pid(log_lvl)
        if self.current_pid:
            self._dump_pid(logger.down_lvl(log_lvl))
            return True
        self.cleanup()
        return False

    def cleanup(self):
        FileHelper.rm(self._pid_files())
        FileHelper.rm(self.opts.pid_file)

    def _find_pid(self, log_lvl=logger.DEBUG) -> int:
        logger.log(log_lvl, 'Check if VPN is running...')
        return next((pid for pid in map(lambda x: self._check_pid(x, log_lvl), self._pid_files(log_lvl)) if pid), 0)

    def _pid_files(self, log_lvl=logger.DEBUG) -> list:
        files = FileHelper.find_files(self.opts.vpn_dir, '.pid_*')
        logger.log(log_lvl, f'PID files [{",".join(files)}]')
        return files

    def _dump_pid(self, log_lvl=logger.DEBUG):
        logger.log(log_lvl, f'VPN PID [{self.current_pid}]')
        FileHelper.write_file(self.opts.pid_file, str(self.current_pid))

    @staticmethod
    def _check_pid(pid_file: str, log_lvl=logger.DEBUG) -> int:
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

    def __init__(self, vpn_opts: ClientOpts):
        super().__init__(vpn_opts)
        self.storage = AccountStorage(self.opts.account_cache_file)
        self._device = DeviceResolver()
        self.pid_handler = VPNPIDHandler(self.opts)

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        if not self.is_installed(silent, log_lvl) or self.pid_handler.is_running():
            return
        self.pid_handler.cleanup()
        logger.log(log_lvl, 'Start VPN Client...')
        SystemHelper.exec_command(f'{self.opts.vpnclient} start', log_lvl=logger.down_lvl(log_lvl))
        time.sleep(1)
        if not self.pid_handler.is_running():
            logger.error('Unable start VPN Client')
            sys.exit(ErrorCode.VPN_START_FAILED)

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        if not self.is_installed(silent, log_lvl) or self.pid_handler.is_running():
            return
        logger.log(log_lvl, 'Stop VPN Client...')
        SystemHelper.exec_command(f'{self.opts.vpnclient} stop', silent=silent, log_lvl=logger.down_lvl(log_lvl))
        self.pid_handler.cleanup()

    def vpn_cmd_opt(self):
        return '/CLIENT localhost /CMD'

    @property
    def device(self) -> DeviceResolver:
        return self._device

    @property
    def vpn_service(self) -> str:
        return self._read_cache_service().service_name

    def probe(self, silent=True, log_lvl=logger.DEBUG) -> 'VPNClientExecutor':
        self._device = self.device.probe(ClientOpts.resource_dir(), self.opts.runtime_dir, log_lvl, silent)
        return self

    def vpn_status(self, vpn_acc: str):
        try:
            status = self.exec_command('AccountStatusGet', params=vpn_acc, silent=True, log_lvl=logger.DEBUG)
            return awk(next(iter(grep(status, r'Session Status.+', flags=re.MULTILINE)), None), sep='|', pos=1)
        except:
            return None

    def is_running(self, silent=True, log_lvl=logger.DEBUG):
        return self.is_installed(silent, log_lvl) and self.pid_handler.is_running(log_lvl)

    def install(self, unix_service: UnixServiceOpts, auto_startup: bool = False):
        FileHelper.mkdirs(self.opts.vpn_dir.parent)
        FileHelper.unpack_archive(ClientOpts.get_resource(ClientOpts.VPNCLIENT_ZIP), self.opts.vpn_dir)
        FileHelper.mkdirs([self.opts.vpn_dir, self.opts.runtime_dir])
        FileHelper.chmod(self.opts.runtime_dir, mode=0o0755)
        FileHelper.chmod([os.path.join(self.opts.vpn_dir, p) for p in ('vpnclient', 'vpncmd')], mode=0o0755)
        _, cmd = build_executable_command()
        self.device.unix_service.create(unix_service, {
            '{{WORKING_DIR}}': f'{self.opts.vpn_dir}', '{{PID_FILE}}': f'{self.opts.pid_file}',
            '{{VPN_DESC}}': unix_service.service_name,
            '{{START_CMD}}': f'{cmd} start --vpn-dir {self.opts.vpn_dir}',
            '{{STOP_CMD}}': f'{cmd} stop --vpn-dir {self.opts.vpn_dir}'
        }, auto_startup)
        self.device.ip_resolver.add_hook(unix_service.service_name,
                                         {'{{WORKING_DIR}}': f'{self.opts.vpn_dir}', '{{VPN_CLIENT_CLI}}': cmd})
        self.device.dns_resolver.create_config(unix_service.service_name)
        self._dump_cache_service(unix_service)
        self.storage.empty()
        self.opts.export_env()

    def uninstall(self, force: bool = False, keep_dnsmasq: bool = True):
        service_opts = self._read_cache_service()
        accounts = [a.account for a in self.storage.list()]
        if len(accounts) > 0:
            self.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], accounts, silent=True)
        self.stop_or_disable_vpn_service(service_opts.service_name, True, True, keep_dnsmasq=keep_dnsmasq)
        self.device.unix_service.remove(service_opts, force)
        self.device.ip_resolver.remove_hook(service_opts.service_name)
        self.device.ip_resolver.renew_all_ip()
        if force:
            logger.info(f'Remove VPN Client [{self.opts.vpn_dir}]...')
            FileHelper.rm(self.opts.vpn_dir)
            self.opts.remove_env()
        else:
            self.storage.empty()

    def disconnect_current(self, log_lvl=logger.INFO, silent=False):
        current = self.storage.get_current()
        if not current:
            return
        logger.log(log_lvl, f'Disconnect VPN account [{current}]...')
        self.exec_command('AccountDisconnect', params=current, log_lvl=logger.down_lvl(log_lvl), silent=silent)
        self.storage.set_current('')
        self.device.dns_resolver.reset_vpn_nameservers()
        self.device.ip_resolver.release_ip(current, self.opts.account_to_nic(current))
        self.device.ip_resolver.cleanup_zombie(f' {self.vpn_dir}.* {self.opts.account_to_nic(current)}')

    def stop_or_disable_vpn_service(self, service_name: str, is_stop=True, is_disable=False, keep_dnsmasq=True):
        if is_stop:
            self.device.unix_service.stop(service_name)
        if is_disable:
            self.device.unix_service.disable(service_name)
        if is_stop or is_disable:
            self.cleanup_zombie_vpn()
            self.device.dns_resolver.cleanup_config(service_name, keep_dnsmasq=keep_dnsmasq)

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
        r = grep(output, r'VPN Client>.+((?:\n.+)+)', re.MULTILINE)
        return ''.join(r).replace('The command completed successfully.', '').strip()

    def _dump_cache_service(self, _unix_service_opts: UnixServiceOpts):
        JsonHelper.dump(self.opts.service_cache_file, _unix_service_opts)

    def _read_cache_service(self) -> UnixServiceOpts:
        try:
            data = JsonHelper.read(self.opts.service_cache_file)
            return UnixServiceOpts(data.get('service_dir'), data.get('service_name'))
        except FileNotFoundError:
            return UnixServiceOpts(None, ClientOpts.vpn_service_name())


vpn_client_opts = vpn_dir_opts_factory(app_dir=ClientOpts.VPN_HOME, opt_func=ClientOpts)


@click.group(name="vpnclient", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    CLI tool to install VPN Client and setup VPN connection
    """
    pass


@cli.command(name="download", help="Download VPN client", hidden=True)
@downloader_opt_factory(ClientOpts.resource_dir())
@dev_mode_opts(hidden=False, opt_name=DownloaderOpt.OPT_NAME)
def __download(downloader_opts: DownloaderOpt):
    download(VPNType.CLIENT, downloader_opts)


@cli.command(name="install", help="Install VPN client and setup *nix service")
@click.option("--auto-startup", type=bool, default=False, flag_value=True, help="Enable auto-startup VPN service")
@click.option("--dnsmasq/--no-dnsmasq", type=bool, default=True, flag_value=False,
              help="By default, dnsmasq is used as local DNS cache. Disabled it if using default System DNS resolver")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts(ClientOpts.vpn_service_name())
@click.option("-f", "--force", type=bool, flag_value=True,
              help="If force is enabled, VPN service will be removed then reinstall without backup")
@verbose_opts
@permission
def __install(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, auto_startup: bool, dnsmasq: bool, force: bool):
    if not dnsmasq:
        logger.error('Only support dnsmasq as DNS resolver in first version')
        sys.exit(ErrorCode.NOT_YET_SUPPORTED)
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    if executor.is_installed(silent=True):
        if force:
            logger.warn('VPN service is already installed. Try to remove then reinstall...')
            executor.uninstall(True, True)
        else:
            logger.error('VPN service is already installed')
            sys.exit(ErrorCode.VPN_ALREADY_INSTALLED)
    device = executor.device
    if dnsmasq and not device.dns_resolver.is_dnsmasq_available():
        logger.error('dnsmasq is not yet installed. Install by [apt install dnsmasq]/[yum install dnsmasq] ' +
                     'or depends on package-manager of your distro')
        sys.exit(ErrorCode.MISSING_REQUIREMENT)
    logger.info(f'Installing VPN client into [{vpn_opts.vpn_dir}] and register service[{unix_service.service_name}]...')
    executor.install(unix_service, auto_startup)
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
    logger.info('Uninstall VPN service...')
    VPNClientExecutor(vpn_opts).probe().uninstall(force, keep_dnsmasq)
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
    logger.info(f'Setup VPN Client with VPN account {account}...')
    executor = VPNClientExecutor(vpn_opts).probe()
    hostname = dns_prefix or executor.generate_host_name(server_opts.hub, auth_opts.user, log_lvl=logger.DEBUG)
    acc = AccountInfo(server_opts.hub, account, hostname, is_default)
    setup_cmd = {
        'NicCreate': acc.account,
        'AccountCreate': f'{acc.account} /SERVER:{server_opts.server} /HUB:{acc.hub} /USERNAME:{auth_opts.user} /NICNAME:{acc.account}'
    }
    setup_cmd = {**setup_cmd, **auth_opts.setup(acc.account)}
    setup_cmd = setup_cmd if no_connect else {**setup_cmd, **{'AccountConnect': acc.account}}
    setup_cmd = setup_cmd if not acc.is_default else {**setup_cmd, **{'AccountStartupSet': acc.account}}
    if not no_connect:
        executor.disconnect_current(log_lvl=logger.DEBUG, silent=True)
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], acc.account, silent=True)
    executor.exec_command(setup_cmd)
    executor.storage.create_or_update(acc, connect=not no_connect)
    executor.device.ip_resolver.create_config(acc.account, {'{{HOST_NAME}}': hostname})
    executor.device.dns_resolver.tweak_on_nic(vpn_opts.account_to_nic(acc.account))
    if acc.is_default:
        vpn_service = executor.vpn_service
        executor.device.unix_service.enable(vpn_service)
        if not no_connect:
            executor.device.unix_service.restart(vpn_service)
    if no_connect:
        executor.device.ip_resolver.lease_ip(acc.account, vpn_opts.account_to_nic(acc.account))
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
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    is_disable, is_stop = False, False
    for account in accounts:
        executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, True, logger.INFO)
        is_default, is_current = executor.storage.remove(account)
        is_stop = is_current or is_stop
        is_disable = is_default or is_disable
    if is_stop or is_disable:
        executor.stop_or_disable_vpn_service(executor.vpn_service, is_stop=is_stop, is_disable=is_disable)
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
    executor = VPNClientExecutor(vpn_opts)
    executor.exec_command('AccountStartupSet', params=account, log_lvl=logger.INFO)
    executor.storage.set_default(account)
    if connect:
        executor.probe(log_lvl=logger.DEBUG)
        executor.disconnect_current(silent=False)
        executor.storage.set_current(account)
        executor.device.unix_service.restart(executor.vpn_service)
    logger.done()


@cli.command(name='connect', help='Connect to VPN connection by given VPN account')
@click.argument('account', nargs=1)
@click.option("-cd", "--default", "is_default", type=bool, flag_value=True, help='Set VPN Client Account is default')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __connect(vpn_opts: ClientOpts, account: str, is_default: bool):
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    logger.info(f'Connect VPN account [{account}]...')
    setup_cmd = ['AccountConnect', 'AccountStartupSet'] if is_default else ['AccountConnect']
    executor.disconnect_current(log_lvl=logger.DEBUG, silent=True)
    executor.exec_command(setup_cmd, params=account)
    acc = AccountInfo.merge(executor.storage.find(account), AccountInfo('', account, '', is_default))
    executor.storage.create_or_update(acc, connect=True)
    if acc.is_default:
        vpn_service = executor.vpn_service
        executor.device.unix_service.enable(vpn_service)
        executor.device.unix_service.restart(vpn_service)
    else:
        executor.device.ip_resolver.lease_ip(acc.account, vpn_opts.account_to_nic(acc.account))
    logger.done()


@cli.command(name='disconnect', help='Disconnect VPN connection')
@click.option("--disable", type=bool, default=False, flag_value=True, help='Disable VPN Client service')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __disconnect(disable: bool, vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe(log_lvl=logger.INFO)
    executor.disconnect_current(silent=False)
    executor.stop_or_disable_vpn_service(executor.vpn_service, is_stop=True, is_disable=disable)
    logger.done()


@cli.command(name='status', help='Get current VPN status')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __status(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe()
    vpn_service = executor.vpn_service
    service_status = executor.device.unix_service.status(vpn_service)
    current_acc, vpn_ip, vpn_status = executor.storage.get_current(), None, None
    if current_acc:
        vpn_ip = executor.device.ip_resolver.get_vpn_ip(ClientOpts.account_to_nic(current_acc))
        vpn_status = executor.vpn_status(current_acc)

    logger.info(f'VPN Service        : {vpn_service} - {service_status.value}')
    logger.info(f'Current VPN IP     : {vpn_ip}')
    logger.info(f'Current VPN Account: {current_acc or None} - {vpn_status}')
    if not vpn_status or not vpn_ip or service_status != service_status.RUNNING:
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
    VPNClientExecutor(vpn_opts).exec_command({'AccountServerCertSet': '%s /LOADCERT:%s' % (account, cert_key),
                                              'AccountServerCertEnable': account})
    logger.done()


@cli.command(name="list", help="Get all VPN Accounts")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __list(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts).exec_command(['AccountList'], log_lvl=logger.INFO)


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
    VPNClientExecutor(vpn_opts).exec_command('AccountGet', params=accounts, log_lvl=logger.INFO)


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
    for line in tail(f, prev=lines, follow=follow):
        print(line.strip())


@cli.command(name="version", help="VPN Version")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
def __version(vpn_opts: ClientOpts):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION)


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
    VPNClientExecutor(vpn_opts).exec_command(command, log_lvl=logger.INFO)


@cli.command(name="start", help="Start VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __start_service(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO)
    executor.pre_exec(log_lvl=logger.INFO)
    vpn_acc = executor.storage.get_default()
    if vpn_acc:
        executor.device.ip_resolver.lease_ip(vpn_acc, ClientOpts.account_to_nic(vpn_acc))
    else:
        executor.device.ip_resolver.renew_all_ip()


@cli.command(name="stop", help="Stop VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __stop_service(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts).probe(silent=False, log_lvl=logger.INFO)
    executor.post_exec(log_lvl=logger.INFO)
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
    logger.info(f'Update DNS with {reason}::{nic}...')
    _reason = DHCPReason[reason]
    executor = VPNClientExecutor(vpn_opts).probe(silent=True, log_lvl=logger.INFO)
    current = executor.storage.get_current(info=True)
    is_in_scan = _reason is DHCPReason.SCAN
    if not _reason.is_release() and not is_in_scan:
        if not current:
            logger.warn(f'Not found any VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_FOUND)
        if not vpn_opts.is_vpn_nic(nic):
            logger.warn(f'NIC[{nic}] does not belong to VPN service')
            sys.exit(0)
        if vpn_opts.nic_to_account(nic) != current.account:
            logger.warn(f'NIC[{nic}] does not meet current VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_MATCH)
    if is_in_scan:
        dns_root = current.hub
        loop_interval(lambda: None, lambda: len(executor.device.dns_resolver.query_vpn_nameservers(dns_root)) > 0,
                      'Unable read DHCP status', exit_if_error=True, max_retries=10)
        nic = vpn_opts.account_to_nic(current.account)
        new_nameservers = ','.join(executor.device.dns_resolver.query_vpn_nameservers(dns_root))
        _reason = DHCPReason.BOUND
    if debug:
        now = datetime.now().isoformat()
        FileHelper.write_file(os.path.join('/tmp', 'vpn_dns'), append=True,
                              content=f"{now}::{reason}::{nic}::{new_nameservers}::{old_nameservers}\n")
    executor.device.dns_resolver.resolve(executor.vpn_service, _reason, current.account, new_nameservers,
                                         old_nameservers)
    if is_in_scan:
        executor.device.ip_resolver.renew_all_ip()


@cli.command(name="tree", help="Tree inside binary", hidden=True)
@click.option("-l", "--level", type=int, default=1, help="Tree level")
def __inside(level):
    tree(dir_path=get_base_path(), level=level)


if __name__ == "__main__":
    cli()
