from typing import Sequence

from google.cloud._helpers import _rfc3339_to_datetime
from google.cloud.dns import ResourceRecordSet, ManagedZone
from google.cloud.dns.client import Client
from google.oauth2.service_account import Credentials

from src.ddns.cmd_ddns import CloudDNSProvider, DNSEntry
from src.utils import logger
from src.utils.helper import loop_interval


class GCloudDNSProvider(CloudDNSProvider):

    def __init__(self, project, service_account, **kwargs):
        super().__init__(project, service_account, **kwargs)
        self.client = Client(self.project, Credentials.from_service_account_file(self.service_account))
        self.max_retries = kwargs.get('max_retries', 10)
        self.interval = kwargs.get('interval', 1)

    def sync_ip(self, dns_entries: Sequence[DNSEntry], zone_name: str, dns_name: str, dns_description: str = ''):
        logger.info(f'Sync {len(dns_entries)} DNS entries to Zone [{zone_name}] with DNS [{dns_name}]')
        zone = self._ensure_zone_exists(zone_name, dns_name, dns_description)
        changes = zone.changes()
        [changes.delete_record_set(rrs) for rrs in zone.list_resource_record_sets() if rrs.record_type == 'A']
        [changes.add_record_set(
            ResourceRecordSet(self.to_dns(dns, dns_name), 'A', dns.ttl, [dns.vpn_ip], zone)) for dns in
            dns_entries if dns.is_valid()]
        if len(changes.additions) == 0 and len(changes.deletions) == 0:
            logger.info(f'Nothing changes in zone[{zone_name}]')
            return
        logger.info(f'Purge {len(changes.deletions)} DNS records then create {len(changes.additions)} DNS records ' +
                    f'in zone[{zone_name}]')
        changes.create(self.client)
        loop_interval(lambda: changes.status != 'pending', 'Unable sync DNS', pre_func=lambda: changes.reload(),
                      max_retries=self.max_retries, interval=self.interval, exit_if_error=True)
        logger.info(f'Zone Changed: {changes._properties}')

    def to_dns(self, dns_entry: DNSEntry, dns_name: str):
        return super(GCloudDNSProvider, self).to_dns(dns_entry, dns_name) + '.'

    def _ensure_zone_exists(self, zone_name, dns_name, dns_description):
        def create_zone(_client: Client, _zone: ManagedZone):
            path = f'/projects/{_zone.project}/managedZones'
            data = {'name': _zone.name, 'dnsName': _zone.dns_name + '.', 'description': _zone.description,
                    'visibility': 'private'}
            api_response = _client._connection.api_request(method="POST", path=path, data=data)
            _zone._properties.clear()
            cleaned = api_response.copy()
            _zone.dns_name = cleaned.pop("dnsName", None)
            if "creationTime" in cleaned:
                cleaned["creationTime"] = _rfc3339_to_datetime(cleaned["creationTime"])
            _zone._properties.update(cleaned)
            logger.info(f'Created DNS zone: {_zone._properties}')

        zone = self.client.zone(zone_name, dns_name=dns_name)
        if not zone.exists():
            zone.description = dns_description
            create_zone(self.client, zone)
            loop_interval(lambda: zone.created is not None, f'Unable create DNS zone[{zone_name}]',
                          pre_func=lambda: zone.reload(), max_retries=self.max_retries, interval=self.interval,
                          exit_if_error=True)
        return zone
