#!/usr/bin/python3
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

import src.utils.logger as logger
from src.client.device_resolver import DeviceResolver, DHCPReason
from src.client.version import CLI_VERSION
from src.executor.shell_executor import SystemHelper
from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils.constants import ErrorCode, Versions
from src.utils.downloader import download, VPNType, downloader_opt_factory, DownloaderOpt
from src.utils.helper import resource_finder, FileHelper, build_executable_command, grep, awk, tail, \
    get_base_path, tree, loop_interval
from src.utils.opts_shared import CLI_CTX_SETTINGS, permission, verbose_opts, UnixServiceOpts, unix_service_opts, \
    dev_mode_opts
from src.utils.opts_vpn import AuthOpts, vpn_auth_opts, ServerOpts, vpn_server_opts, VpnDirectory, \
    vpn_dir_opts_factory


class ClientOpts(VpnDirectory):
    VPNCLIENT_ZIP = 'vpnclient.zip'

    @property
    def log_file(self):
        return self.get_log_file(datetime.today().strftime("%Y%m%d"))

    @property
    def vpnclient(self):
        return os.path.join(self.vpn_dir, 'vpnclient')

    @property
    def pid_file(self):
        return os.path.join(self.runtime_dir, 'vpn.pid')

    @property
    def current_acc_file(self):
        return os.path.join(self.runtime_dir, 'vpn_acc')

    def get_log_file(self, date):
        return os.path.join(self.vpn_dir, 'client_log', f'client_{date}.log')

    @staticmethod
    def resource_dir():
        return ClientOpts.get_resource('.')

    @staticmethod
    def get_resource(file_name):
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


class VPNClientExecutor(VpnCmdExecutor):

    def __init__(self, vpn_opts: ClientOpts):
        super().__init__(vpn_opts.vpn_dir)
        self.opts = vpn_opts
        self.current_pid = None

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        if not self._validate(silent, log_lvl):
            return
        self.current_pid = self.__find_pid()
        if self.current_pid:
            self.__write_pid_file(logger.down_lvl(log_lvl))
            return
        FileHelper.rm(self.__pid_files())
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
        FileHelper.rm(self.opts.pid_file)

    def vpn_cmd_opt(self):
        return '/CLIENT localhost /CMD'

    def vpn_status(self, vpn_acc: str):
        try:
            status = self.exec_command('AccountStatusGet', params=vpn_acc, silent=True, log_lvl=logger.DEBUG)
            return awk(next(iter(grep(status, r'Session Status.+', flags=re.MULTILINE)), None), sep='|', pos=1)
        except:
            return None

    def cleanup_zombie_vpn(self, delay=1, log_lvl=logger.DEBUG):
        time.sleep(delay)
        SystemHelper.ps_kill('vpnclient execsvc', silent=True, log_lvl=log_lvl)

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
            FileHelper.rm(pid_file)
        return 0

    def _validate(self, silent=False, log_lvl=logger.DEBUG):
        if (FileHelper.is_dir(self.opts.vpn_dir) and FileHelper.is_executable(self.opts.vpnclient)
            and FileHelper.is_executable(self.opts.vpncmd)):
            return True
        _, cmd = build_executable_command()
        msg = f'Missing VPN client. Might be the installation is corrupted. Use "{cmd} uninstall -f" then try again'
        if silent:
            logger.decrease(log_lvl, msg)
            return False
        logger.error(msg)
        sys.exit(ErrorCode.FILE_CORRUPTED)

    def save_current_account(self, account: str):
        FileHelper.write_file(self.opts.current_acc_file, account)

    def remove_current_account(self) -> str:
        account = self.find_current_account()
        if account:
            FileHelper.rm(self.opts.current_acc_file)
        return account

    def find_current_account(self) -> Optional[str]:
        return FileHelper.read_file_by_line(self.opts.current_acc_file)


vpn_client_opts = vpn_dir_opts_factory(app_dir="/app/vpnclient", opt_func=ClientOpts)


@click.group(name="installer", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN Client tool to install Softether VPN Client and setup VPN connection
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
@unix_service_opts
@verbose_opts
@permission
def __install(auto_startup: bool, dnsmasq: bool, vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    if not dnsmasq:
        logger.error('Unsupported using Systemd DNS resolver. Must use dnsmasq')
        sys.exit(ErrorCode.NOT_YET_SUPPORTED)
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, log_lvl=logger.INFO)
    if dnsmasq and not resolver.dns_resolver.is_dnsmasq_available():
        logger.error('dnsmasq is not yet installed. Install by [apt install dnsmasq]/[yum install dnsmasq] ' +
                     'or depends on package-manager of your distro')
        sys.exit(ErrorCode.MISSING_REQUIREMENT)
    FileHelper.mkdirs(Path(vpn_opts.vpn_dir).parent)
    FileHelper.unpack_archive(ClientOpts.get_resource(ClientOpts.VPNCLIENT_ZIP), vpn_opts.vpn_dir)
    FileHelper.mkdirs([vpn_opts.vpn_dir, vpn_opts.runtime_dir])
    FileHelper.chmod(vpn_opts.runtime_dir, mode=0o0755)
    FileHelper.chmod([os.path.join(vpn_opts.vpn_dir, p) for p in ('vpnclient', 'vpncmd')], mode=0o0755)
    _, cmd = build_executable_command()
    resolver.unix_service.create(unix_service, {
        '{{WORKING_DIR}}': str(vpn_opts.vpn_dir), '{{PID_FILE}}': str(vpn_opts.pid_file),
        '{{VPN_DESC}}': unix_service.service_name,
        '{{START_CMD}}': f'{cmd} start --vpn-dir {vpn_opts.vpn_dir}',
        '{{STOP_CMD}}': f'{cmd} stop --vpn-dir {vpn_opts.vpn_dir}'
    }, auto_startup)
    resolver.ip_resolver.add_hook(unix_service.service_name,
                                  {'{{WORKING_DIR}}': str(vpn_opts.vpn_dir), '{{VPN_CLIENT_CLI}}': cmd})
    resolver.dns_resolver.create_config(unix_service.service_name)
    logger.done()


@cli.command(name="uninstall", help="Stop and disable VPN client and *nix service")
@click.option("-f", "--force", type=bool, flag_value=True, help="If force is enabled, VPN service will be removed")
@click.option("--keep-dnsmasq/--no-keep-dnsmasq", type=bool, default=True, flag_value=False,
              help="By default, dnsmasq is used as local DNS cache.")
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __uninstall(vpn_opts: ClientOpts, unix_service: UnixServiceOpts, force: bool = False, keep_dnsmasq: bool = True):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir)
    account = executor.remove_current_account()
    if account:
        executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True)
    resolver.unix_service.remove(unix_service, force)
    executor.cleanup_zombie_vpn()
    resolver.dns_resolver.restore_config(unix_service.service_name, keep_dnsmasq=keep_dnsmasq)
    resolver.ip_resolver.remove_hook(unix_service.service_name)
    resolver.ip_resolver.cleanup_vpn_ip()
    resolver.ip_resolver.renew_all_ip()
    if force:
        logger.info(f'Remove VPN Client in {vpn_opts.vpn_dir}...')
        shutil.rmtree(vpn_opts.vpn_dir, ignore_errors=True)
    logger.done()


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
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir)
    host_name = executor.generate_host_name(server_opts.hub, auth_opts.user, log_lvl=logger.DEBUG)
    if hostname:
        SystemHelper.change_host_name(host_name, log_lvl=logger.DEBUG)
    logger.info(f'Setup VPN Client with VPN account {account}...')
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True)
    vpn_nic = vpn_opts.account_to_nic(account)
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
    resolver.ip_resolver.create_config(account, {'{{HOST_NAME}}': host_name})
    resolver.dns_resolver.tweak_on_nic(vpn_nic)
    resolver.unix_service.enable(unix_service.service_name)
    resolver.unix_service.restart(unix_service.service_name)
    logger.done()


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
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, logger.INFO)
    executor.exec_command(['AccountDisconnect', 'AccountDelete', 'NicDelete'], account, silent=True,
                          log_lvl=logger.INFO)
    current_account = executor.find_current_account()
    if current_account and current_account in account:
        executor.remove_current_account()
        resolver.ip_resolver.release_ip(current_account, vpn_opts.account_to_nic(current_account))
        resolver.dns_resolver.restore_config(unix_service.service_name)
        resolver.unix_service.stop(unix_service.service_name)
    logger.done()


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
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, logger.INFO)
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    current_account = executor.remove_current_account()
    if current_account:
        resolver.ip_resolver.release_ip(current_account, vpn_opts.account_to_nic(current_account))
        executor.exec_command('AccountDisconnect', params=current_account, log_lvl=logger.INFO, silent=True)
    resolver.unix_service.stop(unix_service.service_name)
    executor.exec_command('AccountConnect', params=account, log_lvl=logger.INFO)
    executor.save_current_account(account)
    resolver.unix_service.restart(unix_service.service_name)
    logger.done()


@cli.command(name='disconnect', help='Disconnect VPN connection')
@click.option("--disable", type=bool, default=False, flag_value=True, help='Disable VPN Client service')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __disconnect(disable: bool, vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, log_lvl=logger.INFO)
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    current_account = executor.remove_current_account()
    if current_account:
        resolver.ip_resolver.release_ip(current_account, vpn_opts.account_to_nic(current_account))
        executor.exec_command('AccountDisconnect', current_account, silent=True)
    resolver.dns_resolver.restore_config(unix_service.service_name)
    resolver.unix_service.stop(unix_service.service_name)
    executor.cleanup_zombie_vpn()
    if disable:
        resolver.unix_service.disable(unix_service.service_name)
    logger.done()


@cli.command(name='status', help='Get current VPN status')
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@unix_service_opts
@verbose_opts
@permission
def __status(vpn_opts: ClientOpts, unix_service: UnixServiceOpts):
    executor = VPNClientExecutor(vpn_opts=vpn_opts)
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir)
    service_status = resolver.unix_service.status(unix_service.service_name)
    current_acc, vpn_ip, vpn_status = executor.find_current_account(), None, None
    if current_acc:
        vpn_ip = resolver.ip_resolver.get_vpn_ip(ClientOpts.account_to_nic(current_acc))
        vpn_status = executor.vpn_status(current_acc)

    logger.info(f'VPN Service        : {unix_service.service_name} - {service_status.value}')
    logger.info(f'Current VPN IP     : {vpn_ip}')
    logger.info(f'Current VPN Account: {current_acc} - {vpn_status}')
    if not vpn_status or not vpn_ip or service_status != service_status.RUNNING:
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
    logger.done()


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
def __version(vpn_opts: ClientOpts):
    logger.info('VPN version: %s', vpn_opts.get_vpn_version(Versions.VPN_VERSION))
    logger.info('CLI version: %s', CLI_VERSION)


@cli.command(name="start", help="Start VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __start(vpn_opts: ClientOpts):
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, logger.INFO, False)
    executor = VPNClientExecutor(vpn_opts)
    executor.pre_exec(log_lvl=logger.INFO)
    vpn_acc = executor.find_current_account()
    if vpn_acc:
        resolver.ip_resolver.lease_ip(vpn_acc, ClientOpts.account_to_nic(vpn_acc))
    else:
        resolver.ip_resolver.renew_all_ip()


@cli.command(name="stop", help="Stop VPN client by *nix service", hidden=True)
@vpn_client_opts
@dev_mode_opts(opt_name=ClientOpts.OPT_NAME)
@permission
def __stop(vpn_opts: ClientOpts):
    VPNClientExecutor(vpn_opts).post_exec(log_lvl=logger.INFO)
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, logger.INFO, True)
    resolver.ip_resolver.cleanup_vpn_ip()
    resolver.ip_resolver.renew_all_ip()


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
    executor = VPNClientExecutor(vpn_opts)
    resolver = DeviceResolver().probe(ClientOpts.resource_dir(), vpn_opts.runtime_dir, logger.INFO, True)
    current_acc = executor.find_current_account()
    is_in_scan = _reason is DHCPReason.SCAN
    if not _reason.is_release() and not is_in_scan:
        if not current_acc:
            logger.warn(f'Not found any VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_FOUND)
        if not vpn_opts.is_vpn_nic(nic):
            logger.warn(f'NIC[{nic}] does not belong to VPN service')
            sys.exit(0)
        if vpn_opts.nic_to_account(nic) != current_acc:
            logger.warn(f'NIC[{nic}] does not meet current VPN account')
            sys.exit(ErrorCode.VPN_ACCOUNT_NOT_MATCH)
    if is_in_scan:
        loop_interval(lambda: None, lambda: len(resolver.dns_resolver.query_vpn_nameservers(current_acc)) > 0,
                      'Unable read DHCP status', exit_if_error=True, max_retries=10)
        nic = vpn_opts.account_to_nic(current_acc)
        new_nameservers = ','.join(resolver.dns_resolver.query_vpn_nameservers(current_acc))
        _reason = DHCPReason.BOUND
    if debug:
        now = datetime.now().isoformat()
        FileHelper.write_file(os.path.join('/tmp', 'vpn_dns'), append=True,
                              content=f"{now}::{reason}::{nic}::{new_nameservers}::{old_nameservers}\n")
    resolver.dns_resolver.resolve(_reason, current_acc, new_nameservers, old_nameservers)
    if is_in_scan:
        resolver.ip_resolver.renew_all_ip()


@cli.command(name="tree", help="Tree inside binary", hidden=True)
@click.option("-l", "--level", type=int, default=1, help="Tree level")
def __inside(level):
    tree(dir_path=get_base_path(), level=level)


if __name__ == "__main__":
    cli()
