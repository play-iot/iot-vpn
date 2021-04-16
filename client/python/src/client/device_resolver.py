import fileinput
import os
import re
import shutil
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional, Type

import netifaces

import src.utils.logger as logger
from src.executor.shell_executor import SystemHelper
from src.utils.constants import ErrorCode
from src.utils.helper import FileHelper, grep
from src.utils.opts_shared import UnixServiceOpts


class ServiceStatus(Enum):
    RUNNING = 'active(running)'
    EXITED = 'active(exited)'
    WAITING = 'active(waiting)'
    INACTIVE = 'inactive(dead)'
    UNKNOWN = 'unknown'

    @staticmethod
    def parse(status: str):
        status_ = [e for e in list(ServiceStatus) if e.value == status]
        return status_[0] if len(status_) else ServiceStatus.UNKNOWN

    def is_running(self):
        return self is ServiceStatus.RUNNING

    def is_enabled(self):
        return self in [ServiceStatus.RUNNING, ServiceStatus.EXITED, ServiceStatus.WAITING]


class UnixServiceType(Enum):
    SYSTEMD = 'systemd'
    PROCD = 'procd'


class AppConvention(ABC):

    def __init__(self, resource_dir: str, runtime_dir: str, log_lvl: int = logger.DEBUG, silent: bool = True):
        self.resource_dir = Path(resource_dir)
        self.runtime_dir = Path(runtime_dir)
        self.log_lvl = log_lvl
        self.silent = silent


class UnixService(AppConvention):

    @staticmethod
    @abstractmethod
    def factory(resource_dir: str, runtime_dir: str) -> 'UnixService':
        pass

    @property
    @abstractmethod
    def kind(self) -> UnixServiceType:
        pass

    @abstractmethod
    def create(self, opts: UnixServiceOpts, replacements: dict, auto_restart: bool = False):
        pass

    @abstractmethod
    def remove(self, opts: UnixServiceOpts, force: bool = False):
        pass

    @abstractmethod
    def enable(self, service_name: str):
        pass

    @abstractmethod
    def disable(self, service_name: str):
        pass

    @abstractmethod
    def stop(self, service_name: str):
        pass

    @abstractmethod
    def restart(self, service_name: str, delay: int = 1):
        pass

    @abstractmethod
    def status(self, service_name: str) -> ServiceStatus:
        pass

    @abstractmethod
    def to_service_fqn(self, service_dir: str, service_name: str):
        pass


class IPResolverType(Enum):
    DHCLIENT = 'dhclient'
    UDHCPC = 'udhcpc'


class DHCPReason(Enum):
    """
    https://linux.die.net/man/8/dhclient-script
    """
    MEDIUM = 1
    PREINIT = 2
    BOUND = 3
    RENEW = 4
    REBIND = 5
    REBOOT = 6
    EXPIRE = 7
    FAIL = 8
    STOP = 9
    RELEASE = 10
    NBI = 11
    TIMEOUT = 12
    # MANUAL
    SCAN = 21

    def is_release(self):
        return self in [DHCPReason.RELEASE, DHCPReason.STOP, DHCPReason.FAIL, DHCPReason.EXPIRE]

    def is_ignore(self):
        return self in [DHCPReason.MEDIUM, DHCPReason.PREINIT]

    def is_unreachable(self):
        return self in [DHCPReason.NBI, DHCPReason.TIMEOUT]


class DNSCompatibleMode(Enum):
    PARALLEL = auto()
    PLUGIN = auto()
    ITSELF = auto()

    def is_plugin(self):
        return self is DNSCompatibleMode.PLUGIN


class DNSConfig:
    def __init__(self, identity: str, main_cfg: str, config_dir: str, runtime_resolv: str = None,
                 is_service: bool = True, plugin_dir: str = None, flavour_type: Type['DNSFlavour'] = None):
        self.identity = identity
        self.is_service = is_service
        self.main_cfg = Path(main_cfg)
        self.config_dir = Path(config_dir)
        self.plugin_dir = Path(plugin_dir) if plugin_dir else None
        self.runtime_resolv = Path(runtime_resolv) if runtime_resolv else None
        self.flavour_type = flavour_type

    def to_fqn_cfg(self, cfg_name: str) -> Path:
        return self.config_dir.joinpath(cfg_name)


class DNSFlavour(ABC):
    DNSMASQ_TUNED_CFG = '00-use-dnsmasq.conf'

    def __init__(self, config: DNSConfig, service: UnixService, resource_dir: Path, **kwargs):
        self.config = config
        self.service = service
        self.resource_dir = resource_dir

    @property
    def dnsmasq_compatible(self) -> DNSCompatibleMode:
        return DNSCompatibleMode.PARALLEL

    @property
    def dnsmasq_config_dir(self) -> Optional[Path]:
        """
        :return: an overridden dnsmasq config dir
        """
        return None

    def adapt_dnsmasq(self, vpn_service: str) -> Optional[Path]:
        """
        Adapt DNS flavour to works with dnsmasq
        :param vpn_service: VPN service name
        :return: runtime_resolv_config
        """
        pass

    def setup(self, vpn_service: str, vpn_nameserver_cfg: Path):
        """
        Setup DNS flavour to works with VPN service
        :param vpn_service: VPN service name
        :param vpn_nameserver_cfg: VPN nameserver runtime config
        :return:
        """
        pass

    def tweak_per_nic(self, nic: str):
        """
        Tweak DNS/DHCP flavour config per NIC
        :param nic:
        :return:
        """
        pass

    def update(self, reason: DHCPReason, priv_root_dns: str, nameservers: list, dns_nameserver_config: Path):
        """
        Update DNS configuration on each time IPResolver receive a hook event
        :param reason: DHCP reason
        :param priv_root_dns: Private root DNS
        :param nameservers: Private nameservers
        :param dns_nameserver_config: a runtime DNS nameserver configuration
        :return:
        """
        pass

    def query(self, priv_root_dns: str, dns_nameserver_config: Path) -> list:
        """
        Query current private DNS server
        :param priv_root_dns: Private root DNS
        :param dns_nameserver_config: a runtime DNS nameserver configuration
        :return:
        """
        pass

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        """
        Restore default DNS resolver config
        :param vpn_service: VPN service name
        :param keep_dnsmasq: keep dnsmasq
        :return:
        """
        pass

    def _common_adapt_dnsmasq(self, vpn_service: str):
        identity = self.config.identity
        logger.debug(f'Tweak [{identity}] DNS resolver service to compatible with [dnsmasq] and [{vpn_service}]...')
        FileHelper.mkdirs(self.config.config_dir)
        FileHelper.copy(self.resource_dir.joinpath(f'dnsmasq-{identity}.conf'),
                        self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG), True)
        FileHelper.chmod(self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG), mode=0o0644)
        self.service.restart(identity)
        return self.config.runtime_resolv

    def _common_remove_dnsmasq(self, vpn_service: str, keep_dnsmasq: bool):
        if not keep_dnsmasq:
            cfg = self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG)
            logger.debug(f'Remove [dnsmasq] and [{vpn_service}] plugin[{cfg}]...')
            FileHelper.rm(cfg)
            self.service.restart(self.config.identity)


class MockDNSFlavour(DNSFlavour):

    def __init__(self):
        super().__init__(None, None, None)


class SystemdResolvedFlavour(DNSFlavour):

    def adapt_dnsmasq(self, vpn_service: str) -> Optional[Path]:
        return self._common_adapt_dnsmasq(vpn_service)

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        self._common_remove_dnsmasq(vpn_service, keep_dnsmasq)


class NetworkManagerFlavour(DNSFlavour):

    @property
    def dnsmasq_compatible(self) -> DNSCompatibleMode:
        return DNSCompatibleMode.PLUGIN

    @property
    def dnsmasq_config_dir(self) -> Optional[Path]:
        return Path(self.config.plugin_dir) if self.config.plugin_dir else None

    def adapt_dnsmasq(self, vpn_service: str) -> Optional[Path]:
        return self._common_adapt_dnsmasq(vpn_service)

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        self._common_remove_dnsmasq(vpn_service, keep_dnsmasq)


class ConnmanFlavour(DNSFlavour):

    def tweak_per_nic(self, nic: str):
        restart = False
        with fileinput.FileInput("/etc/connman/main.conf", inplace=True, backup='.bak') as f:
            for line in f:
                if re.match(r"^NetworkInterfaceBlacklist\s*=\s*", line, re.IGNORECASE) and nic not in line:
                    restart = True
                    print(line.strip() + "," + nic)
                else:
                    print(line, end='')
        if restart:
            self.service.restart(self.config.identity)


class DNSMasqFlavour(DNSFlavour):
    DNSMASQ_CONFIG_TMPL = 'dnsmasq-vpn.conf'
    DNSMASQ_TUNED_CFG = '00-use-dnsmasq.conf'
    DNSMASQ_VPN_CFG = '00-use-vpn.conf'
    DNSMASQ_VPN_NS_CFG = '10-vpn-nameserver.conf'

    def __init__(self, config: DNSConfig, service: UnixService, resource_dir: Path, **kwargs):
        super().__init__(config, service, resource_dir, **kwargs)
        self._available = kwargs.get('available', True)
        self.__resolver = kwargs.get('resolver', None)
        cfg_dir = config.config_dir
        self.config.config_dir = self._resolver.dnsmasq_config_dir or cfg_dir if self._resolver else cfg_dir

    @property
    def dnsmasq_compatible(self) -> DNSCompatibleMode:
        return self._resolver.dnsmasq_compatible if self._resolver else DNSCompatibleMode.ITSELF

    @property
    def _resolver(self) -> DNSFlavour:
        return self.__resolver

    @_resolver.setter
    def _resolver(self, resolver: DNSFlavour):
        self.__resolver = resolver

    def setup(self, vpn_service: str, vpn_nameserver_cfg: Path):
        if not self._available:
            logger.error('dnsmasq is not yet installed or is corrupted')
            sys.exit(ErrorCode.MISSING_REQUIREMENT)
        logger.info(f'Generating System DNS config file and configure [dnsmasq]...')
        FileHelper.rm(DNSResolver.DNS_SYSTEM_FILE)
        FileHelper.write_file(DNSResolver.DNS_SYSTEM_FILE, self.__dnsmasq_resolv(vpn_service), mode=0o0644)
        dnsmasq_vpn_cfg = self._dnsmasq_vpn_cfg(vpn_service)
        logger.debug(f'Add dnsmasq config for {vpn_service}[{dnsmasq_vpn_cfg}]...')
        runtime_resolv_cfg = self._resolver.adapt_dnsmasq(vpn_service) if self._resolver else None
        resolv_file = f'resolv-file={str(runtime_resolv_cfg)}' if runtime_resolv_cfg else ''
        FileHelper.copy(self.resource_dir.joinpath(self.DNSMASQ_CONFIG_TMPL), dnsmasq_vpn_cfg, force=True)
        FileHelper.replace_in_file(dnsmasq_vpn_cfg, {'{{DNS_RESOLVED_FILE}}': resolv_file}, backup='')
        FileHelper.chmod(dnsmasq_vpn_cfg, mode=0o0644)
        logger.debug(f'Add dnsmasq nameserver runtime configuration [{vpn_nameserver_cfg}]...')
        if FileHelper.is_readable(vpn_nameserver_cfg):
            FileHelper.touch(vpn_nameserver_cfg, mode=0o0644)
        FileHelper.create_symlink(vpn_nameserver_cfg, self._dnsmasq_vpn_nameserver_cfg, force=True)
        self._restart_dnsmasq()

    def adapt_dnsmasq(self, vpn_service: str) -> Optional[Path]:
        return self._resolver.adapt_dnsmasq(vpn_service) if self._resolver else None

    def tweak_per_nic(self, nic: str):
        if self._resolver:
            self._resolver.tweak_per_nic(nic)

    def update(self, reason: DHCPReason, priv_root_dns: str, nameservers: list, dns_nameserver_config: Path):
        logger.info(f'Update VPN DNS config file on [{reason.name}][{priv_root_dns}] with nameservers {nameservers}...')
        servers = '\n'.join([f'server=/{priv_root_dns}/{ns}' for ns in nameservers])
        FileHelper.write_file(dns_nameserver_config, mode=0o644,
                              content=f'### Generated at [{datetime.now().isoformat()}]\n{servers}\n')
        self._restart_dnsmasq()

    def query(self, priv_root_dns: str, dns_nameserver_config: Path) -> list:
        if not FileHelper.is_readable(dns_nameserver_config):
            return []
        nss = grep(FileHelper.read_file_by_line(dns_nameserver_config, fallback_if_not_exists=''),
                   fr'server=/{priv_root_dns}/.+')
        return [ns[len(f'server='):].strip() for ns in nss]

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        logger.debug(f'Remove dnsmasq nameserver config [{self._dnsmasq_vpn_nameserver_cfg}]')
        FileHelper.rm(self._dnsmasq_vpn_nameserver_cfg)
        if keep_dnsmasq:
            self._restart_dnsmasq()
            return
        logger.debug(f'Remove dnsmasq vpn config [{self._dnsmasq_vpn_cfg(vpn_service)}]')
        FileHelper.rm(self._dnsmasq_vpn_cfg(vpn_service))
        self.service.stop(self.config.identity)
        self.service.disable(self.config.identity)
        if self._resolver:
            self._resolver.restore_config(vpn_service, keep_dnsmasq)

    def _dnsmasq_vpn_cfg(self, vpn_service: str):
        return self.config.to_fqn_cfg(self.DNSMASQ_VPN_CFG.replace('vpn', vpn_service))

    @property
    def _dnsmasq_vpn_nameserver_cfg(self):
        return self.config.to_fqn_cfg(self.DNSMASQ_VPN_NS_CFG)

    @property
    def _is_serviceable(self):
        return self._available and not self.dnsmasq_compatible.is_plugin()

    def _restart_dnsmasq(self):
        if self._is_serviceable:
            self.service.enable(self.config.identity)
            self.service.restart(self.config.identity)

    @staticmethod
    def __dnsmasq_resolv(service_name: str = 'VPN'):
        now = datetime.now().isoformat()
        return f'### Generated by [{service_name}] service and managed by [dnsmasq] at [{now}]\n' \
               f'nameserver 127.0.0.1\n'


class DNSResolverType(Enum):
    CONNMAN = DNSConfig('connman', '/etc/connman/main.conf', '/etc/systemd/system/connman.service.d',
                        flavour_type=ConnmanFlavour)
    """
    https://wiki.archlinux.org/index.php/ConnMan
    https://manpages.debian.org/unstable/connman/connman.conf.5.en.html
    """

    SYSTEMD_RESOLVED = DNSConfig('systemd-resolved', '/etc/systemd/resolved.conf',
                                 '/etc/systemd/resolved.conf.d', '/run/systemd/resolve/resolv.conf',
                                 flavour_type=SystemdResolvedFlavour)
    """
    Ubuntu 18/20 use `systemd-resolved`
    """

    NETWORK_MANAGER = DNSConfig('NetworkManager', '/etc/NetworkManager/NetworkManager.conf',
                                '/etc/NetworkManager/conf.d', plugin_dir='/etc/NetworkManager/dnsmasq.d/',
                                flavour_type=NetworkManagerFlavour)
    """
    Fedora/RedHat/CentOS use `NetworkManager`
    https://wiki.archlinux.org/index.php/NetworkManager#Custom_dnsmasq_configuration
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/networking_guide/getting_started_with_networkmanager
    """

    RESOLVCONF = DNSConfig('resolvconf', '/etc/resolvconf/run/resolv.conf', '/etc/resolvconf/resolv.conf.d',
                           '/etc/resolvconf/resolv.conf.d/original')
    """
    Raspbian use openresolv
    https://manpages.debian.org/buster/openresolv/resolvconf.8.en.html
    https://manpages.debian.org/buster/openresolv/resolvconf.conf.5.en.html
    
    Debian use systemd/resolvconf
    https://manpages.debian.org/buster/resolvconf/resolvconf.8.en.html
    """
    RESOLVCONF_CMD = DNSConfig('resolvconf', '/etc/resolvconf/run/resolv.conf', '/etc/resolvconf/resolv.conf.d',
                               is_service=False)

    DNSMASQ = DNSConfig('dnsmasq', '/etc/dnsmasq.conf', '/etc/dnsmasq.d', flavour_type=DNSMasqFlavour)
    UNKNOWN = None

    @classmethod
    def as_services(cls):
        return (t for t in DNSResolverType if t != DNSResolverType.UNKNOWN and t.config.is_service)

    @property
    def config(self) -> Optional[DNSConfig]:
        return None if self.is_unknown() else self.value

    def is_unknown(self):
        return self is DNSResolverType.UNKNOWN

    def is_dnsmasq(self):
        return self is DNSResolverType.DNSMASQ


class DNSResolver(AppConvention):
    DNS_SYSTEM_FILE = Path('/etc/resolv.conf')
    DNS_ORIGIN_FILE = 'resolv.origin.conf'
    VPN_NAMESERVER_CFG = 'vpn-runtime-nameserver.conf'

    def __init__(self, resource_dir: str, runtime_dir: str, unix_service: UnixService, log_lvl: int = logger.DEBUG,
                 silent: bool = True):
        super(DNSResolver, self).__init__(resource_dir, runtime_dir, log_lvl, silent)
        self.service, self.kind, self._is_dnsmasq = unix_service, DNSResolverType.UNKNOWN, False
        self.dns_origin_cfg = DNSResolver.DNS_SYSTEM_FILE.parent.joinpath(DNSResolver.DNS_ORIGIN_FILE)
        self.dns_nameserver_runtime_cfg = self.runtime_dir.joinpath(self.VPN_NAMESERVER_CFG)

    def probe(self) -> 'DNSResolver':
        self.kind = next(
            (t for t in DNSResolverType.as_services() if self.service.status(t.config.identity).is_enabled()),
            self.kind)
        if self.kind.is_unknown():
            if SystemHelper.verify_command(DNSResolverType.RESOLVCONF_CMD.config.identity):
                self.kind = DNSResolverType.RESOLVCONF_CMD
            else:
                logger.warn('Unknown DNS resolver. DNS VPN IP might be not resolved correctly')
        if self.kind not in [DNSResolverType.DNSMASQ, DNSResolverType.UNKNOWN]:
            dnsmasq_name = DNSResolverType.DNSMASQ.config.identity
            self._is_dnsmasq = self.service.status(dnsmasq_name).is_enabled() or shutil.which(dnsmasq_name) is not None
        logger.debug(f'Current DNS resolver [{self.kind.name}], is dnsmasq available [{self._is_dnsmasq}]')
        return self

    def is_dnsmasq_available(self):
        return self.kind.is_dnsmasq() or self._is_dnsmasq

    def create_config(self, vpn_service: str):
        resolver = self._resolver()
        if not FileHelper.is_readable(self.dns_origin_cfg):
            logger.info(f'Override and backup System DNS config file...')
            FileHelper.backup(DNSResolver.DNS_SYSTEM_FILE, self.dns_origin_cfg, remove=False)
        if not FileHelper.is_readable(self.dns_origin_cfg):
            logger.error(f'Not found origin DNS config file [{self.dns_origin_cfg}]')
            sys.exit(ErrorCode.FILE_CORRUPTED)
        if not FileHelper.is_readable(self.dns_nameserver_runtime_cfg):
            FileHelper.touch(self.dns_nameserver_runtime_cfg, 0o0644)
        resolver.setup(vpn_service, self.dns_nameserver_runtime_cfg)

    def tweak_on_nic(self, nic: str):
        self._resolver().tweak_per_nic(nic)

    def resolve(self, reason: DHCPReason, priv_root_dns: str, new_nameservers: str = None, old_nameservers: str = None):
        resolver = self._resolver()
        if reason.is_release():
            # TODO fix it
            self.restore_config(vpn_service='')
            return
        nss = self.__validate_nameservers(reason, new_nameservers, old_nameservers)
        if nss is None:
            logger.info(f'Skip generating DNS entry in [{reason.name}][{new_nameservers}][{old_nameservers}]')
            return
        resolver.update(reason, priv_root_dns, nss, self.dns_nameserver_runtime_cfg)

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        logger.info(f'Remove VPN nameserver config [{self.VPN_NAMESERVER_CFG}]...')
        self._resolver().restore_config(vpn_service, keep_dnsmasq)
        FileHelper.rm(self.dns_nameserver_runtime_cfg)
        if keep_dnsmasq:
            return
        if FileHelper.is_readable(self.dns_origin_cfg):
            logger.info(f'Restore System DNS config file...')
            FileHelper.backup(self.dns_origin_cfg, DNSResolver.DNS_SYSTEM_FILE)

    def query_vpn_nameservers(self, priv_root_dns: str) -> list:
        return self._resolver().query(priv_root_dns, self.dns_nameserver_runtime_cfg)

    def _resolver(self) -> Optional[DNSFlavour]:
        if self.kind.is_dnsmasq():
            return DNSMasqFlavour(DNSResolverType.DNSMASQ.config, self.service, self.resource_dir,
                                  available=self.is_dnsmasq_available())
        has_flavour = not self.kind.is_unknown() and self.kind.config.flavour_type
        resolver = self.kind.config.flavour_type(self.kind.config, self.service,
                                                 self.resource_dir) if has_flavour else MockDNSFlavour()
        return DNSMasqFlavour(DNSResolverType.DNSMASQ.config, self.service, self.resource_dir, resolver=resolver,
                              available=self.is_dnsmasq_available())

    def __validate_nameservers(self, reason: DHCPReason, new_ns: str = None, old_ns: str = None) -> Optional[list]:
        if reason.is_ignore():
            return None
        if reason is DHCPReason.RENEW and new_ns == old_ns and FileHelper.is_readable(self.dns_nameserver_runtime_cfg):
            return None
        nameservers = old_ns if reason.is_unreachable() else new_ns
        return [ns for ns in nameservers.split(',') if ns][0:2] if nameservers else None


class IPResolver(AppConvention):

    @staticmethod
    @abstractmethod
    def factory(resource_dir: str, runtime_dir: str, log_lvl: int, silent: bool = True) -> 'IPResolver':
        pass

    @property
    @abstractmethod
    def ip_tool(self) -> str:
        pass

    @property
    def pid_file(self):
        return self.runtime_dir.joinpath('vpn_dhclient.pid')

    @property
    def lease_file(self):
        return self.runtime_dir.joinpath('vpn_dhclient.lease')

    @abstractmethod
    def add_hook(self, service_name: str, replacements: dict):
        pass

    @abstractmethod
    def remove_hook(self, service_name: str):
        pass

    @abstractmethod
    def create_config(self, vpn_acc: str, replacements: dict):
        pass

    def lease_ip(self, vpn_acc: str, vpn_nic: str, daemon=True):
        logger.log(self.log_lvl, 'Lease a new VPN IP...')
        SystemHelper.exec_command(f'{self.ip_tool} {self._lease_ip_opt(vpn_acc, vpn_nic, daemon)}',
                                  silent=self.silent, log_lvl=self.log_lvl)

    def release_ip(self, vpn_acc: str, vpn_nic: str):
        logger.log(self.log_lvl, 'Release the current VPN IP...')
        SystemHelper.exec_command(f'{self.ip_tool} {self._release_ip_opt(vpn_acc, vpn_nic)}',
                                  silent=self.silent, log_lvl=self.log_lvl)

    def renew_all_ip(self, delay=1):
        logger.log(self.log_lvl, 'Refresh all IPs...')
        time.sleep(delay)
        SystemHelper.exec_command(f'{self._refresh_all_ip_opt()}', silent=self.silent,
                                  log_lvl=logger.down_lvl(self.log_lvl))

    def cleanup_vpn_ip(self):
        logger.log(self.log_lvl, 'Cleanup all ip lease process for VPN...')
        SystemHelper.ps_kill(f'{self.ip_tool} .* vpn_', silent=self.silent, log_lvl=logger.down_lvl(self.log_lvl))

    def get_vpn_ip(self, nic: str):
        try:
            logger.log(self.log_lvl, f'Query VPN IPv4 on {nic}...')
            return netifaces.ifaddresses(nic)[netifaces.AF_INET]
        except Exception as err:
            logger.warn(f'Not found VPN IP {nic}. Error: {err}')
            return None

    def _to_config_file(self, suffix):
        return self.runtime_dir.joinpath(f'vpn_dhclient.{suffix}.conf')

    @abstractmethod
    def _lease_ip_opt(self, vpn_acc: str, vpn_nic: str, daemon=True) -> str:
        pass

    @abstractmethod
    def _release_ip_opt(self, vpn_acc: str, vpn_nic: str) -> str:
        pass

    @abstractmethod
    def _refresh_all_ip_opt(self) -> str:
        pass

    @abstractmethod
    def _to_hook_file(self, service_name: str) -> str:
        pass


class Systemd(UnixService):
    """
    Systemd service
    """

    SERVICE_FILE_TMPL = 'qweio-vpn.service.tmpl'

    @staticmethod
    def factory(resource_dir, runtime_dir) -> 'UnixService':
        if SystemHelper.verify_command(f'pidof {UnixServiceType.SYSTEMD.value}'):
            return Systemd(resource_dir=resource_dir, runtime_dir=runtime_dir)
        return None

    @property
    def kind(self) -> UnixServiceType:
        return UnixServiceType.SYSTEMD

    def create(self, opts: UnixServiceOpts, replacements: dict, auto_startup: bool = False):
        service_fqn = self.to_service_fqn(opts.service_dir, opts.service_name)
        FileHelper.copy(self.resource_dir.joinpath(Systemd.SERVICE_FILE_TMPL), service_fqn, force=True)
        FileHelper.replace_in_file(service_fqn, replacements, backup='')
        FileHelper.chmod(service_fqn, mode=0o0644)
        logger.info(f'Add new service [{opts.service_name}] in [{service_fqn}]')
        SystemHelper.exec_command("systemctl daemon-reload", silent=True, log_lvl=logger.INFO)
        if auto_startup:
            self.enable(opts.service_name)

    def remove(self, opts: UnixServiceOpts, force: bool = False):
        service_fqn = self.to_service_fqn(opts.service_dir, opts.service_name)
        self.stop(opts.service_name)
        self.disable(opts.service_name)
        if force and os.path.exists(service_fqn):
            logger.info(f'Remove System service [{opts.service_name}]...')
            os.remove(service_fqn)
        SystemHelper.exec_command("systemctl daemon-reload", silent=True, log_lvl=logger.INFO)

    def enable(self, service_name: str):
        logger.info(f'Enable System service [{service_name}]...', )
        SystemHelper.exec_command(f"systemctl enable {service_name}", log_lvl=logger.INFO)

    def disable(self, service_name: str):
        logger.info(f'Disable System service [{service_name}]...', )
        SystemHelper.exec_command(f"systemctl disable {service_name}", silent=True, log_lvl=logger.INFO)

    def stop(self, service_name):
        logger.info(f"Stop System service [{service_name}]...")
        SystemHelper.exec_command(f"systemctl stop {service_name}", silent=True, log_lvl=logger.INFO)

    def restart(self, service_name, delay: int = 1):
        logger.info(f"Restart System service [{service_name}]...")
        SystemHelper.exec_command(f"systemctl restart {service_name}", log_lvl=logger.INFO)
        time.sleep(delay)

    def status(self, service_name: str) -> ServiceStatus:
        status = SystemHelper.exec_command(f"systemctl status {service_name} | grep Active | awk '{{print $2$3}}'",
                                           shell=True, silent=True, log_lvl=logger.DEBUG)
        return ServiceStatus.parse(status)

    def to_service_fqn(self, service_dir: str, service_name: str):
        return os.path.join(service_dir or '/lib/systemd/system', service_name + '.service')


class Procd(UnixService, ABC):
    """
    Procd for OpenWRT: https://openwrt.org/docs/techref/procd
    """

    @staticmethod
    def factory(resource_dir: str, runtime_dir: str) -> 'UnixService':
        if SystemHelper.verify_command(f'pidof {UnixServiceType.PROCD.value}'):
            raise NotImplementedError('Not yet supported OpenWRT')
        return None


class DHCPResolver(IPResolver):
    DHCLIENT_HOOK_TMPL = 'dhclient-vpn.hook.tmpl'
    DHCLIENT_CONFIG_TMPL = 'dhclient-vpn.conf.tmpl'

    @staticmethod
    def factory(resource_dir, runtime_dir: str, log_lvl: int, silent: bool = True) -> 'IPResolver':
        if FileHelper.which(IPResolverType.DHCLIENT.value):
            return DHCPResolver(resource_dir, runtime_dir, log_lvl, silent)
        return None

    @property
    def ip_tool(self) -> str:
        return IPResolverType.DHCLIENT.value

    def create_config(self, vpn_acc: str, replacements: dict):
        config_file = self._to_config_file(vpn_acc)
        logger.log(self.log_lvl, f'Create DHCP client VPN config[{config_file}]...')
        FileHelper.copy(self.resource_dir.joinpath(self.DHCLIENT_CONFIG_TMPL), config_file, force=True)
        FileHelper.replace_in_file(config_file, replacements, backup='')
        FileHelper.chmod(config_file, mode=0o0644)

    def add_hook(self, service_name: str, replacements: dict):
        hook_file = self._to_hook_file(service_name)
        logger.log(self.log_lvl, f'Create DHCP client VPN hook[{hook_file}]...')
        FileHelper.copy(self.resource_dir.joinpath(self.DHCLIENT_HOOK_TMPL), hook_file, force=True)
        FileHelper.replace_in_file(hook_file, replacements, backup='')
        FileHelper.chmod(hook_file, mode=0o0744)

    def remove_hook(self, service_name: str):
        hook_file = self._to_hook_file(service_name)
        logger.log(self.log_lvl, f'Remove DHCP client VPN hook[{hook_file}]...')
        FileHelper.rm(hook_file, force=True)

    def _to_hook_file(self, service_name: str) -> str:
        return os.path.join('/etc/dhcp/dhclient-exit-hooks.d', service_name)

    def _lease_ip_opt(self, vpn_acc: str, vpn_nic: str, daemon=True) -> str:
        opts = f'-nw -lf {self.lease_file} -pf {self.pid_file} -v' if daemon else '-1 -v'
        # opts += f' -cf {self._to_config_file(vpn_acc)}'
        return f'{opts} {vpn_nic}'

    def _release_ip_opt(self, vpn_acc: str, vpn_nic: str) -> str:
        opts = f'-r -lf {self.lease_file} -pf {self.pid_file} -v'
        # opts += f' -cf {self._to_config_file(vpn_acc)}'
        return f'{opts} {vpn_nic}'

    def _refresh_all_ip_opt(self):
        return f'{self.ip_tool} -1 -v'


class UDHCPCResolver(IPResolver, ABC):

    @property
    def ip_tool(self) -> str:
        return IPResolverType.UDHCPC.value


class DeviceResolver:

    def __init__(self):
        self.__service = None
        self.__ip_resolver = None
        self.__dns_resolver = None

    def probe(self, resource_dir: str, runtime_dir: str, log_lvl=logger.DEBUG, silent=True) -> 'DeviceResolver':
        self._service(Systemd.factory(resource_dir, runtime_dir) or Procd.factory(resource_dir, runtime_dir))
        self._ip_resolver(DHCPResolver.factory(resource_dir, runtime_dir, log_lvl, silent))
        self._dns_resolver(DNSResolver(resource_dir, runtime_dir, self.unix_service).probe())
        return self

    @property
    def unix_service(self) -> UnixService:
        return self.__service

    @property
    def ip_resolver(self) -> IPResolver:
        return self.__ip_resolver

    @property
    def dns_resolver(self) -> DNSResolver:
        return self.__dns_resolver

    def _service(self, service: UnixService):
        self.__service = self.__not_null(service, 'INIT system')

    def _ip_resolver(self, resolver: IPResolver):
        self.__ip_resolver = self.__not_null(resolver, 'IP resolver')

    def _dns_resolver(self, resolver: DNSResolver):
        self.__dns_resolver = self.__not_null(resolver, 'DNS resolver')

    def __not_null(self, obj: Any, msg: str):
        if not obj:
            raise NotImplementedError(f'Unknown {msg}')
        return obj