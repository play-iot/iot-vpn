import os
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Iterator

import click

from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils import logger
from src.utils.downloader import downloader_opt_factory, VPNType, DownloaderOpt, download
from src.utils.helper import resource_finder, awk, grep
from src.utils.opts_shared import CLI_CTX_SETTINGS, verbose_opts, dev_mode_opts
from src.utils.opts_vpn import vpn_server_opts, ServerOpts, vpn_dir_opts_factory, VpnDirectory

vpn_dir_opts = vpn_dir_opts_factory(app_dir="/app/vpnbridge")


class CloudType(Enum):
    GCLOUD = 'gcloud'
    AMAZON = 'amazon'
    AZURE = 'azure'


class DNSEntry:
    def __init__(self, mac=None, vpn_ip=None, hostname=None, ttl=None, **kwargs):
        self.mac = mac or kwargs['mac']
        self.vpn_ip = vpn_ip or kwargs['vpn_ip']
        self.hostname = hostname or kwargs['hostname']
        self.ttl = ttl or kwargs['ttl']

    def is_valid(self):
        return self.mac and self.vpn_ip and self.hostname


class CloudDNSProvider(ABC):

    def __init__(self, project, service_account, **kwargs):
        self.project = project
        self.service_account = service_account

    @abstractmethod
    def sync_ip(self, dns_entries, zone_name, dns_name, dns_description):
        raise NotImplementedError('Must implemented')

    @abstractmethod
    def to_dns(self, dns_name, dns_entry: DNSEntry):
        raise NotImplementedError('Must implemented')


class VPNHubExecutor(VpnCmdExecutor):

    def __init__(self, vpn_opts: VpnDirectory, server_opts: ServerOpts, hub_pwd):
        super().__init__(vpn_opts.vpn_dir)
        self.server_opts = server_opts
        self.hub_pwd = hub_pwd

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def vpn_cmd_opt(self):
        return f'/SERVER {self.server_opts.server} /hub:{self.server_opts.hub} /password:{self.hub_pwd} /CMD'


def query_hub(hub_password: str, server_opts: ServerOpts, vpn_opts: VpnDirectory) -> Iterator:
    def parse_entry_value(idx: int, row: str):
        value = awk(row, sep='|', pos=1)
        return VPNHubExecutor.decode_host_name(value) if idx == 2 else value

    # SessionList > SessionGet (user + session + session_name + client_hostname + client_ip_public + client_ip_local)
    # MacTable(session_name + mac) > DhcpTable (mac + vpn_ip)
    dhcp_table = VPNHubExecutor(vpn_opts, server_opts, hub_password).exec_command('DhcpTable')
    raw = zip(grep(dhcp_table, r'MAC Address.+', re.MULTILINE), grep(dhcp_table, r'Allocated IP.+', re.MULTILINE),
              grep(dhcp_table, r'Client Host Name.+', re.MULTILINE))
    keys = {0: 'mac', 1: 'vpn_ip', 2: 'hostname'}
    return map(lambda each: {keys[idx]: parse_entry_value(idx, r) for idx, r in enumerate(each)}, raw)


@click.group(name="ddns", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN DNS CLI that sync DNS from VPN server to Cloud DNS
    """
    pass


@cli.command(name="download", help="Download VPN bridge", hidden=True)
@downloader_opt_factory(resource_finder('.', os.path.dirname(__file__)))
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
@click.option('-zd', '--dns-name', type=str, help='DNS name. Default is <VPN_HUB>.device')
@click.option('-zt', '--dns-ttl', type=int, default=2 * 60,
              help='Number of seconds that this DNS can be cached by resolvers')
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_dir_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def sync(cloud_type: CloudType, cloud_project: str, cloud_svc: str, dns_zone: str, dns_name: str, dns_ttl: int,
         server_opts: ServerOpts, hub_password: str, vpn_opts: VpnDirectory):
    if cloud_type == CloudType.GCLOUD.value:
        from src.ddns.gcloud_dns import GCloudDNSProvider
        dns_provider = GCloudDNSProvider(cloud_project, cloud_svc, zone_name=dns_zone)
    else:
        raise NotImplementedError(f'Not yet supported cloud {cloud_type}')
    res = query_hub(hub_password, server_opts, vpn_opts)
    dns_provider.sync_ip([DNSEntry(ttl=dns_ttl, **r) for r in res], dns_zone,
                         dns_name or f'{server_opts.hub}.device', f'{server_opts.hub.upper()} devices zone')


@cli.command(name="query", help="Sync Cloud Private DNS", hidden=True)
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_dir_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def __query(server_opts: ServerOpts, hub_password: str, vpn_opts: VpnDirectory):
    logger.info(list(query_hub(hub_password, server_opts=server_opts, vpn_opts=vpn_opts)))


if __name__ == '__main__':
    cli(auto_envvar_prefix='VPN')
