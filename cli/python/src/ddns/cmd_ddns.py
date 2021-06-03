import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import Iterator, Optional, Tuple, Sequence

import click

from src.ddns.version import APP_VERSION, HASH_VERSION
from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils import logger, about
from src.utils.downloader import downloader_opt_factory, VPNType, DownloaderOpt, download
from src.utils.helper import JsonHelper, TextHelper, EnvHelper
from src.utils.opts_shared import CLI_CTX_SETTINGS, verbose_opts, dev_mode_opts
from src.utils.opts_vpn import vpn_server_opts, ServerOpts, vpn_dir_opts_factory, VpnDirectory


class CloudType(Enum):
    GCLOUD = 'gcloud'
    AMAZON = 'amazon'
    AZURE = 'azure'


class MacIp:

    def __init__(self, session_name: str, mac: str, vpn_ip: str, hostname: str):
        self.session_name = session_name
        self.mac = mac
        self.vpn_ip = vpn_ip
        self.hostname = hostname


class UserSession:
    NAT_SESSION_USER = 'SecureNAT'

    def __init__(self, session_name: str, user_name: str, public_ip: str, public_hostname: str, local_ip: str,
                 local_hostname: str):
        self.session_name = session_name
        self.user_name = user_name
        self.public_ip = public_ip
        self.public_hostname = public_hostname
        self.local_ip = local_ip
        self.local_hostname = local_hostname
        self.mac, self.vpn_ip, self.dhcp_hostname = None, None, None

    def load_ip(self, mac_ip: MacIp) -> 'UserSession':
        self.mac = mac_ip.mac
        self.vpn_ip = mac_ip.vpn_ip
        self.dhcp_hostname = mac_ip.hostname
        return self

    def decode_hostname(self) -> str:
        return VpnCmdExecutor.decode_host_name(self.dhcp_hostname)


class DNSEntry:
    DEFAULT_TTL = 120

    def __init__(self, user_session: UserSession, ttl: int = DEFAULT_TTL, vpn_hub: str = None):
        self.user_session = user_session
        self.ttl = ttl
        self._fqn_dns = self.fqn_dns(DNSEntry.device_dns(vpn_hub) if vpn_hub else None)

    @property
    def vpn_ip(self):
        return self.user_session.vpn_ip

    def is_valid(self):
        return self.user_session.mac and self.user_session.vpn_ip and self.user_session.user_name

    def fqn_dns(self, dns_name):
        return f'{self.user_session.user_name}.{dns_name}'

    @staticmethod
    def device_dns(vpn_hub: str, dns_name: str = None):
        return dns_name or f'device.{vpn_hub}'


class CloudDNSProvider(ABC):

    def __init__(self, project, service_account, **kwargs):
        self.project = project
        self.service_account = service_account

    @abstractmethod
    def sync_ip(self, dns_entries: Sequence[DNSEntry], zone_name: str, dns_name: str, dns_description: str):
        raise NotImplementedError('Must implemented')

    def to_dns(self, dns_entry: DNSEntry, dns_name: str):
        return dns_entry.fqn_dns(dns_name)


class DDNSOpts(VpnDirectory):

    @classmethod
    def get_resource(cls, file_name) -> str:
        return EnvHelper.resource_finder(file_name, os.path.dirname(__file__))


vpn_ddns_opts = vpn_dir_opts_factory(app_dir='/app/vpnbridge', opt_func=DDNSOpts)


class VPNDDNSExecutor(VpnCmdExecutor):

    def __init__(self, vpn_opts: DDNSOpts, server_opts: ServerOpts, hub_pwd):
        super().__init__(vpn_opts)
        self.server_opts = server_opts
        self.hub_pwd = hub_pwd

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def vpn_cmd_opt(self):
        return f'/SERVER {self.server_opts.server} /hub:{self.server_opts.hub} /password:{self.hub_pwd} /CMD'

    def _parse_entry_value(self, idx: int, row: str):
        value = TextHelper.awk(row, sep='|', pos=1)
        return self.decode_host_name(value) if idx == 2 else value

    @staticmethod
    def _parse_row(row: Iterator[Tuple], columns: dict) -> Iterator[dict]:
        return map(lambda each: {columns[idx]: TextHelper.awk(r, sep='|', pos=1) for idx, r in enumerate(each)}, row)

    def list_user_sessions(self) -> Iterator[UserSession]:
        sessions = self.query_sessions()
        mac_ip_table = self.query_mac_ip_table()
        return [s.load_ip(mac_ip_table.get(k)) for k, s in sessions.items() if s is not None and mac_ip_table.get(k)]

    def query_sessions(self) -> dict:
        sessions = self.exec_command('SessionList')
        row = zip(TextHelper.grep(sessions, r'Session Name.+'), TextHelper.grep(sessions, r'User Name.+'))
        return {v.get('session_name'): self._lookup_session(v) for v in
                self._parse_row(row, {0: 'session_name', 1: 'user_name'})}

    def query_mac_ip_table(self) -> dict:
        def _ip_table(key: str, mac_obj: dict, _dhcp_table: dict) -> Optional[MacIp]:
            dhcp = _dhcp_table.get(key)
            return MacIp(**{**mac_obj, **dhcp}) if dhcp else None

        mac_table = self._query_mac_table()
        dhcp_table = self._query_dhcp_table()
        return {v.get('session_name'): _ip_table(k, v, dhcp_table) for k, v in mac_table.items()}

    def _lookup_session(self, user_session: dict) -> Optional[UserSession]:
        if user_session.get('user_name', None) == UserSession.NAT_SESSION_USER:
            return None
        session = self.exec_command(f'SessionGet {user_session.get("session_name")}')
        row = zip(TextHelper.grep(session, r'Client IP Address[^(\n]+\|.+'),
                  TextHelper.grep(session, r'Client Host Name[^(\n]+\|.+'),
                  TextHelper.grep(session, r'Client IP Address.+\(Reported\).+\|.+'),
                  TextHelper.grep(session, r'Client Host Name.+\(Reported\).+\|.+'))
        extra = next(self._parse_row(row, {0: 'public_ip', 1: 'public_hostname', 2: 'local_ip', 3: 'local_hostname'}),
                     None)
        if not extra:
            return None
        return UserSession(**{**user_session, **extra})

    def _query_mac_table(self):
        mac_table = self.exec_command('MacTable')
        row = zip(TextHelper.grep(mac_table, r'Session Name.+'), TextHelper.grep(mac_table, r'MAC Address.+\|.+'))
        return {v['mac']: v for v in self._parse_row(row, {0: 'session_name', 1: 'mac'})}

    def _query_dhcp_table(self):
        dhcp_table = self.exec_command('DhcpTable')
        row = zip(TextHelper.grep(dhcp_table, r'MAC Address.+'), TextHelper.grep(dhcp_table, r'Allocated IP.+'),
                  TextHelper.grep(dhcp_table, r'Client Host Name.+'))
        return {v['mac']: v for v in self._parse_row(row, {0: 'mac', 1: 'vpn_ip', 2: 'hostname'})}


@click.group(name="ddns", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN DNS CLI that sync DNS from VPN server to Cloud DNS
    """
    pass


@cli.command(name="download", help="Download VPN bridge", hidden=True)
@downloader_opt_factory(EnvHelper.resource_finder('.', os.path.dirname(__file__)))
@dev_mode_opts(hidden=False, opt_name=DownloaderOpt.OPT_NAME)
def __download(downloader_opts: DownloaderOpt):
    download(VPNType.BRIDGE, downloader_opts)


@cli.command(name="sync", help="Sync Cloud Private DNS")
@click.option('-ct', '--cloud-type', default=CloudType.GCLOUD.value,
              type=click.Choice([c.value for c in CloudType]), help='DNS server type')
@click.option('-cp', '--cloud-project', required=True, type=str, help='Cloud project id')
@click.option('-sa', '--cloud-svc', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Cloud service account')
@click.option('-zn', '--dns-zone', required=True, type=str, help='DNS Zone name')
@click.option('-zd', '--dns-name', type=str, help='DNS name. Default is "device.<VPN_HUB>"')
@click.option('-zt', '--dns-ttl', type=int, default=DNSEntry.DEFAULT_TTL,
              help='Number of seconds that this DNS can be cached by resolvers')
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_ddns_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def sync(cloud_type: CloudType, cloud_project: str, cloud_svc: str, dns_zone: str, dns_name: str, dns_ttl: int,
         server_opts: ServerOpts, hub_password: str, vpn_opts: DDNSOpts):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, True)
    if cloud_type == CloudType.GCLOUD.value:
        from src.ddns.gcloud_dns import GCloudDNSProvider
        dns_provider = GCloudDNSProvider(cloud_project, cloud_svc, zone_name=dns_zone)
    else:
        raise NotImplementedError(f'Not yet supported cloud {cloud_type}')
    sessions = VPNDDNSExecutor(vpn_opts, server_opts, hub_password).list_user_sessions()
    dns_provider.sync_ip([DNSEntry(s, ttl=dns_ttl) for s in sessions], dns_zone,
                         DNSEntry.device_dns(server_opts.hub, dns_name), f'{server_opts.hub.upper()} devices zone')


@cli.command(name="about", help="Show VPN software info")
@click.option('-l', '--license', 'show_license', default=False, flag_value=True, help='Show licenses')
@vpn_ddns_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
def __about(vpn_opts: DDNSOpts, show_license: bool):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, True, show_license)


@cli.command(name="query", help="Sync Cloud Private DNS", hidden=True)
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_ddns_opts
@dev_mode_opts(VpnDirectory.OPT_NAME, hidden=False)
@verbose_opts
def __query(server_opts: ServerOpts, hub_password: str, vpn_opts: DDNSOpts):
    about.show(vpn_opts, APP_VERSION, HASH_VERSION, True)
    sessions = VPNDDNSExecutor(vpn_opts, server_opts, hub_password).list_user_sessions()
    print(JsonHelper.to_json([DNSEntry(s, vpn_hub=server_opts.hub) for s in sessions]))


@cli.command(name='command', help='Execute Ad-hoc VPN command', hidden=True)
@click.argument("command", type=str, required=True)
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_ddns_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def __execute(server_opts: ServerOpts, hub_password: str, vpn_opts: DDNSOpts, command):
    VPNDDNSExecutor(vpn_opts, server_opts, hub_password).exec_command(command, log_lvl=logger.INFO)


if __name__ == '__main__':
    cli(auto_envvar_prefix='VPN')
