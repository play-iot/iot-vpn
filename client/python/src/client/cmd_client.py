#!/usr/bin/python3
import os
import shutil
import sys
import time
from datetime import datetime
from typing import Optional

import click
import netifaces

import src.utils.logger as logger
from src.client.network_resolver import DNSResolver, IPResolver
from src.client.version import CLI_VERSION
from src.executor.shell_executor import SystemHelper
from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils.constants import ErrorCode, Versions
from src.utils.downloader import download, VPNType, downloader_opt_factory, DownloaderOpt
from src.utils.helper import resource_finder, FileHelper, build_executable_command, grep, awk, tail, \
    get_base_path, tree
from src.utils.opts_shared import CLI_CTX_SETTINGS, permission, verbose_opts, UnixServiceOpts, unix_service_opts, \
    dev_mode_opts
from src.utils.opts_vpn import AuthOpts, vpn_auth_opts, ServerOpts, vpn_server_opts, VpnDirectory, \
    vpn_dir_opts_factory


def resource(f):
    return resource_finder(f, os.path.dirname(__file__))


class ClientOpts(VpnDirectory):
    SERVICE_FILE_TMPL = 'qweio-vpn.service.tmpl'
    DHCLIENT_HOOK_TMPL = 'dhclient-vpn-hook.tmpl'
    VPNCLIENT_ZIP = 'vpnclient.zip'

    @property
    def log_file(self):
        return self.get_log_file(datetime.today().strftime("%Y%m%d"))

    @property
    def vpnclient(self):
        return os.path.join(self.vpn_dir, 'vpnclient')

    @property
    def pid_file(self):
        return os.path.join(self.vpn_dir, 'vpn.pid')

    @property
    def dhcp_pid_file(self):
        return os.path.join(self.vpn_dir, 'vpn_dhclient.pid')

    @property
    def dhcp_lease_file(self):
        return os.path.join(self.vpn_dir, 'vpn_dhclient.lease')

    @property
    def current_acc_file(self):
        return os.path.join(self.vpn_dir, 'vpn_acc')

    def get_log_file(self, date):
        return os.path.join(self.vpn_dir, 'client_log', f'client_{date}.log')

    @staticmethod
    def vpn_nic(account) -> str:
        return 'vpn_' + account


class VPNClientExecutor(VpnCmdExecutor):
    current_pid = None

    def __init__(self, vpn_opts: ClientOpts = None):
        super().__init__(vpn_opts.vpn_dir)
        self.opts = vpn_opts

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        if not self._validate(silent, log_lvl):
            return
        self.current_pid = self.__find_pid()
        if self.current_pid:
            self.__write_pid_file(logger.down_lvl(log_lvl))
            return
        FileHelper.remove_files(self.__pid_files(), force=True)
        logger.log(log_lvl, 'Start VPN Client')
        SystemHelper.exec_command(f'{self.opts.vpnclient} start', log_lvl=logger.down_lvl(log_lvl))
        time.sleep(1)
        self.current_pid = self.__find_pid(logger.down_lvl(log_lvl))
        self.__write_pid_file(logger.down_lvl(log_lvl))

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        if not self._validate(silent, log_lvl) or self.current_pid:
            return
        logger.log(log_lvl, 'Stop VPN Client')
        SystemHelper.exec_command(f'{self.opts.vpnclient} stop', silent=silent, log_lvl=logger.down_lvl(log_lvl))
        FileHelper.remove_files([self.opts.pid_file], force=True)

    def vpn_cmd_opt(self):
        return '/CLIENT localhost /CMD'

    def cleanup_zombie_vpn(self, delay=1, log_lvl=logger.DEBUG):
        time.sleep(delay)
        SystemHelper.ps_kill('vpnclient execsvc', silent=True, log_lvl=log_lvl)
        self.ip_resolver(log_lvl, silent=True).cleanup_vpn_ip()

    def __find_pid(self, log_lvl=logger.DEBUG) -> int:
        logger.log(log_lvl, 'Checking if VPN is running')
        return next((pid for pid in map(lambda x: self._check_pid(x, log_lvl), self.__pid_files(log_lvl)) if pid), 0)

    def __pid_files(self, log_lvl=logger.DEBUG) -> list:
        files = FileHelper.find_files(self.vpn_dir, '.pid_*')
        logger.log(log_lvl, f'PID files: {",".join(files)}')
        return files

    def __write_pid_file(self, log_lvl=logger.DEBUG):
        logger.log(log_lvl, f'Current PID: {self.current_pid}')
        FileHelper.write_file(self.opts.pid_file, str(self.current_pid))

    def _check_pid(self, pid_file: str, log_lvl=logger.DEBUG) -> int:
        try:
            logger.log(log_lvl, f'Read PID file {pid_file}')
            pid = FileHelper.read_file_by_line(pid_file)
            pid = int(pid)
            if pid and pid > 0 and SystemHelper.is_pid_exists(pid):
                return pid
        except Exception as _:
            FileHelper.remove_files([pid_file], True)
        return 0

    def _validate(self, silent=False, log_lvl=logger.DEBUG):
        if FileHelper.is_exists(self.opts.vpnclient):
            return True
        msg = 'Missing VPN client. Might be not yet installed or wrong folder configuration'
        if silent:
            logger.decrease(log_lvl, msg)
            return False
        logger.error(msg)
        sys.exit(ErrorCode.NOT_FOUND_VPN_BINARY)

    def save_current_account(self, account: str):
        FileHelper.write_file(self.opts.current_acc_file, account)

    def remove_current_account(self) -> str:
        account = self.find_current_account()
        if account:
            FileHelper.remove_files([self.opts.current_acc_file], True)
        return account

    def find_current_account(self) -> Optional[str]:
        return FileHelper.read_file_by_line(self.opts.current_acc_file)

    def ip_resolver(self, log_lvl=logger.DEBUG, silent=True):
        return IPResolver(pid_file=self.opts.dhcp_pid_file, lease_file=self.opts.dhcp_lease_file, log_lvl=log_lvl,
                          silent=silent)


vpn_client_opts = vpn_dir_opts_factory(app_dir="/app/vpnclient", opt_func=ClientOpts)


@click.group(name="installer", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN Client tool to install Softether VPN Client and setup VPN connection
    """
    pass


@cli.command(name="download", help="Download VPN client", hidden=True)
@downloader_opt_factory(resource('.'))
@dev_mode_opts(hidden=False, opt_name=DownloaderOpt.OPT_NAME)
def __download(downloader_opts: DownloaderOpt):
    download(VPNType.CLIENT, downloader_opts)


@cli.command(name="install", help="Install VPN client and setup *nix service")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __install(vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    def copy_vpn_files(_opts: ClientOpts):
        FileHelper.unpack_archive(resource(ClientOpts.VPNCLIENT_ZIP), _opts.vpn_dir)
        FileHelper.chmod([os.path.join(_opts.vpn_dir, p) for p in ('vpnclient', 'vpncmd')], mode=0o755)

    def prepare_vpn_service(_opts: ClientOpts, service_fqn: str):
        FileHelper.copy(resource(ClientOpts.SERVICE_FILE_TMPL), _opts.vpn_dir)
        service_file = os.path.join(_opts.vpn_dir, ClientOpts.SERVICE_FILE_TMPL)
        FileHelper.chmod(service_file, mode=0o644)
        work_dir, cmd = build_executable_command()
        start_cmd = f'{cmd} start --vpn-dir {_opts.vpn_dir}'
        stop_cmd = f'{cmd} stop --vpn-dir {_opts.vpn_dir}'
        FileHelper.replace_in_file(service_file, {'{{WORKING_DIR}}': _opts.vpn_dir, '{{PID_FILE}}': vpn_opts.pid_file,
                                                  '{{START_CMD}}': start_cmd, '{{STOP_CMD}}': stop_cmd})
        FileHelper.copy(service_file, service_fqn)

    def prepare_dhclient_hook(_opts: ClientOpts, service_name: str):
        FileHelper.copy(resource(ClientOpts.DHCLIENT_HOOK_TMPL), _opts.vpn_dir)
        hook_file = os.path.join(_opts.vpn_dir, ClientOpts.DHCLIENT_HOOK_TMPL)
        FileHelper.chmod(hook_file, mode=0o755)
        work_dir, cmd = build_executable_command()
        FileHelper.replace_in_file(hook_file, {'{{VPN_CLIENT_CLI}}': cmd})
        FileHelper.copy(hook_file, f'/etc/dhcp/dhclient-exit-hooks.d/dhclient-{service_name}')

    FileHelper.create_folders(vpn_opts.vpn_dir)
    copy_vpn_files(vpn_opts)
    prepare_vpn_service(vpn_opts, unix_service.service_fqn)
    prepare_dhclient_hook(vpn_opts, unix_service.service_name)
    SystemHelper.create_service(unix_service.raw_name)


@cli.command(name="uninstall", help="Stop and disable VPN client and *nix service")
@click.option("-f", "--force", type=bool, flag_value=True, help="If enabled force, force remove everything in VPN")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __uninstall(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, force: bool = False):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    account = executor.remove_current_account()
    if account:
        executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True)
    SystemHelper.disable_service(unix_service.service_name, unix_service.service_fqn, force)
    executor.cleanup_zombie_vpn()
    if force:
        logger.info(f'Removing VPN Client in {vpn_opts.vpn_dir}...')
        shutil.rmtree(vpn_opts.vpn_dir, ignore_errors=True)
    logger.success("Done")


@cli.command(name="add", help="Add new VPN Account")
@vpn_server_opts
@click.option("--hostname", type=bool, default=False, flag_value=True,
              help='Change hostname based on VPN username and hub. Should use on IoT device')
@click.option("-ca", "--account", type=str, default="qweio", help='VPN Client account name')
@click.option("-cd", "--default", type=bool, default=False, flag_value=True, help='Set VPN Client Account is default')
@vpn_auth_opts
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __add(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, server_opts: ServerOpts, auth_opts: AuthOpts,
          account: str, default: bool, hostname: bool):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    if hostname:
        logger.info(f'Change device hostname based on VPN hub and VPN user...')
        executor.change_host_name(server_opts.hub, auth_opts.user, do_change=True, log_lvl=logger.INFO)
    logger.info("Setup VPN Client...")
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True)
    vpn_nic = vpn_opts.vpn_nic(account)
    auth_cmd, param = auth_opts.setup(account)
    setup_cmd = {
        'NicCreate': account,
        'AccountCreate': f'{account} /SERVER:{server_opts.server} /HUB:{server_opts.hub} /USERNAME:{auth_opts.user} /NICNAME:{account}',
        auth_cmd: param,
        'AccountConnect': account,
    }
    if default:
        setup_cmd.update({'AccountStartupSet': account})
    executor.exec_command(setup_cmd)
    executor.save_current_account(account)
    DNSResolver.probe().resolve(vpn_nic)
    SystemHelper.restart_service(unix_service.service_name)


@cli.command(name='delete', help='Delete VPN account')
@click.argument('account', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __delete(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, account):
    if account is None or len(account) == 0:
        logger.error('Must provide at least account')
        sys.exit(ErrorCode.INVALID_ARGUMENT)
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True,
                          log_lvl=logger.INFO)
    current_account = executor.find_current_account()
    if current_account and current_account in account:
        executor.remove_current_account()
        executor.ip_resolver(log_lvl=logger.INFO, silent=True).release_ip(vpn_opts.vpn_nic(current_account))
        SystemHelper.stop_service(unix_service.service_name)


@cli.command(name='connect', help='Connect to VPN connection with VPN account')
@click.argument('account', nargs=1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __connect(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, account):
    """Connect to VPN connection by VPN account

    Account is an VPN client account for each VPN connection
    """
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    current_account = executor.remove_current_account()
    if current_account:
        executor.ip_resolver(log_lvl=logger.INFO, silent=True).release_ip(vpn_opts.vpn_nic(current_account))
        executor.exec_command('AccountDisconnect', params=current_account, log_lvl=logger.INFO, silent=True)
    SystemHelper.stop_service(unix_service.service_name)
    executor.exec_command('AccountConnect', params=account, log_lvl=logger.INFO)
    executor.save_current_account(account)
    SystemHelper.restart_service(unix_service.service_name)


@cli.command(name='disconnect', help='Disconnect VPN connection')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __disconnect(vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    current_account = executor.remove_current_account()
    if current_account:
        executor.ip_resolver(log_lvl=logger.INFO, silent=True).release_ip(vpn_opts.vpn_nic(current_account))
        executor.exec_command('AccountDisconnect', current_account, silent=True)
    SystemHelper.stop_service(unix_service.service_name)


@cli.command(name='status', help='Get current VPN status')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __status(vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    service_status = SystemHelper.status_service(unix_service.service_name)
    current_acc, vpn_ip, status = executor.find_current_account(), None, None
    if current_acc:
        try:
            vpn_ip = netifaces.ifaddresses(ClientOpts.vpn_nic(current_acc))[netifaces.AF_INET]
        except:
            vpn_ip = None
        try:
            status = executor.exec_command('AccountStatusGet', params=current_acc, silent=True, log_lvl=logger.DEBUG)
            status = awk(next(iter(grep(status, r'Session Status.+')), None), sep='|', pos=1)
        except:
            status = None

    logger.info(f'VPN Service        : {unix_service.service_name} - {service_status.value}')
    logger.info(f'Current VPN IP     : {vpn_ip}')
    logger.info(f'Current VPN Account: {current_acc} - {status}')
    if not status or not vpn_ip or service_status != service_status.RUNNING:
        sys.exit(ErrorCode.VPN_SERVICE_IS_NOT_WORKING)


@cli.command(name="trust", help="Trust VPN Server cert")
@click.option("-ca", "--account", type=str, default="qweio", help="Client Account for manage VPN connection")
@click.option("-cck", "--cert-key", type=click.Path(exists=True, resolve_path=True), help="VPN Server Cert")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __add_trust_server(vpn_opts: ClientOpts, account: str, cert_key: str):
    logger.info("Enable Trust VPN Server on VPN client")
    VPNClientExecutor(vpn_opts=vpn_opts).exec_command({'AccountServerCertSet': '%s /LOADCERT:%s' % (account, cert_key),
                                                       'AccountServerCertEnable': account})


@cli.command(name="list", help="Get all VPN Accounts")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __list(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts=vpn_opts).exec_command(['AccountList'], log_lvl=logger.INFO)


@cli.command(name='detail', help='Get detail VPN Account configuration')
@click.argument('account', nargs=-1)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __detail(vpn_opts: ClientOpts, account):
    """Get detail VPN configuration and status by account

    Account is an VPN client account for each VPN connection
    """
    if account is None or len(account) == 0:
        logger.error('Must provide at least account')
        sys.exit(ErrorCode.INVALID_ARGUMENT)
    VPNClientExecutor(vpn_opts=vpn_opts).exec_command('AccountGet', params=account, log_lvl=logger.INFO)


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


@cli.command(name='command', help='Execute Ad-hoc VPN command')
@click.argument("command", type=str, required=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
@permission
def __execute(vpn_opts: ClientOpts, command):
    VPNClientExecutor(vpn_opts=vpn_opts).exec_command(command, log_lvl=logger.INFO)


@cli.command(name="version", help="VPN Version")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@verbose_opts
def __version(vpn_opts: ClientOpts):
    logger.info('VPN version: %s', vpn_opts.get_vpn_version(Versions.VPN_VERSION))
    logger.info('CLI version: %s', CLI_VERSION)


@cli.command(name="start", help="Start VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __start(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts)
    executor.pre_exec(log_lvl=logger.INFO)
    cur_acc = executor.find_current_account()
    if cur_acc:
        executor.ip_resolver(log_lvl=logger.INFO, silent=False).renew_ip(ClientOpts.vpn_nic(cur_acc), daemon=True)
    else:
        executor.ip_resolver(log_lvl=logger.INFO, silent=True).renew_all_ip(1)


@cli.command(name="stop", help="Stop VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __stop(vpn_opts: ClientOpts):
    executor = VPNClientExecutor(vpn_opts)
    executor.post_exec(log_lvl=logger.INFO)
    executor.ip_resolver().cleanup_vpn_ip(1)


@cli.command(name="dns", help="Update VPN DNS server", hidden=True)
@click.argument("nic", type=str, required=True)
@click.option('-r', '--reason', type=str, required=True, help='DHClient Reason')
@click.option('-ndns', '--new-domain-name-servers', type=str, required=True, help='New domain name servers')
@click.option('-odns', '--old-domain-name-servers', type=str, help='Old domain name servers')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __dns(nic: str, reason: str, new_domain_name_servers: str, old_domain_name_servers: str):
    logger.info(nic)
    logger.info(reason)
    logger.info(new_domain_name_servers)
    logger.info(old_domain_name_servers)


@cli.command(name="tree", help="Tree inside binary", hidden=True)
@click.option("-l", "--level", type=int, default=1, help="Tree level")
def __inside(level):
    tree(dir_path=get_base_path(), level=level)


if __name__ == "__main__":
    cli()
