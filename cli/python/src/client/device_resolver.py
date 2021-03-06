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
from typing import Any, Optional, Type, Union

import netifaces

import src.utils.logger as logger
from src.executor.shell_executor import SystemHelper
from src.utils.constants import ErrorCode
from src.utils.helper import FileHelper, TextHelper
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

    def __init__(self, resource_dir: Union[str, Path], runtime_dir: Union[str, Path], log_lvl: int = logger.DEBUG,
                 silent: bool = True):
        self.resource_dir = Path(resource_dir)
        self.runtime_dir = Path(runtime_dir)
        self.log_lvl = log_lvl
        self.silent = silent


class UnixService(AppConvention):

    @staticmethod
    @abstractmethod
    def factory(resource_dir: Union[str, Path], runtime_dir: Union[str, Path]) -> 'UnixService':
        pass

    @property
    @abstractmethod
    def kind(self) -> UnixServiceType:
        pass

    @property
    @abstractmethod
    def standard_service_dir(self) -> str:
        pass

    @abstractmethod
    def create(self, svc_opts: UnixServiceOpts, replacements: dict, auto_restart: bool = False):
        pass

    @abstractmethod
    def remove(self, svc_opts: UnixServiceOpts, force: bool = False):
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

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
        """
        Adapt DNS flavour to works with dnsmasq
        :param origin_resolv_conf: Origin resolv config
        :param vpn_service: VPN service name
        :return: runtime_resolv_config
        """
        pass

    def dnsmasq_options(self) -> Optional[dict]:
        """
        Get the optimization dnsmasq options
        :return: dnsmasq option
        """
        return None

    def setup(self, vpn_service: str, origin_resolv_conf: Path, vpn_resolv_conf: Path,
              vpn_nameserver_hook_conf: Path):
        """
        Setup DNS flavour to works with VPN service
        :param origin_resolv_conf: origin system resolv conf file path
        :param vpn_service: VPN service name
        :param vpn_resolv_conf:  VPN resolv configuration file path
        :param vpn_nameserver_hook_conf: VPN nameserver hook config file path
        """
        pass

    def tweak_per_nic(self, nic: str):
        """
        Tweak DNS/DHCP flavour config per NIC
        :param nic:
        :return: should restart service
        """
        return False

    def update_hook(self, reason: DHCPReason, priv_root_dns: str, nameservers: list, vpn_nameserver_hook_conf: Path):
        """
        Update DNS configuration on each time IPResolver receive a hook event
        :param reason: DHCP reason
        :param priv_root_dns: Private root DNS
        :param nameservers: Private nameservers
        :param vpn_nameserver_hook_conf: VPN nameserver hook config file path
        :return:
        """
        pass

    def reset_hook(self, vpn_nameserver_hook_conf: Path):
        """
        Reset DNS hook configuration due to change VPN account configuration
        :param vpn_nameserver_hook_conf: VPN nameserver hook config file path
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

    def restart(self, **kwargs):
        """
        Restart DNS resolver service
        :return:
        """
        if self.config.is_service:
            self.service.restart(self.config.identity)

    def _common_adapt_dnsmasq(self, vpn_service: str):
        identity = self.config.identity
        logger.debug(f'Adapt [{identity}] DNS resolver service to compatible with [dnsmasq] and [{vpn_service}]...')
        FileHelper.mkdirs(self.config.config_dir)
        FileHelper.copy(self.resource_dir.joinpath(f'dnsmasq-{identity}.conf'),
                        self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG), True)
        FileHelper.chmod(self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG), mode=0o0644)
        return self.config.runtime_resolv

    def _common_remove_dnsmasq(self, vpn_service: str, keep_dnsmasq: bool):
        if not keep_dnsmasq:
            cfg = self.config.to_fqn_cfg(self.DNSMASQ_TUNED_CFG)
            logger.debug(f'Remove [dnsmasq] and [{vpn_service}] plugin[{cfg}]...')
            FileHelper.rm(cfg)


class MockDNSFlavour(DNSFlavour):

    def __init__(self):
        super().__init__(None, None, None)


class OpenResolvFlavour(DNSFlavour):

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
        content = FileHelper.read_file_by_line(self.config.main_cfg)
        resolv = TextHelper.awk(next(iter(TextHelper.grep(content, r'dnsmasq_resolv=.+')), None), sep='=', pos=1)
        return Path(resolv or self.config.runtime_resolv)


class SystemdResolvedFlavour(DNSFlavour):

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
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

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
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
        return restart

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
        return FileHelper.get_target_link(origin_resolv_conf) or self.config.runtime_resolv if \
            FileHelper.is_readable(self.config.runtime_resolv) else origin_resolv_conf

    def dnsmasq_options(self) -> dict:
        return {}


class DNSMasqFlavour(DNSFlavour):
    DNSMASQ_CONFIG_TMPL = 'dnsmasq-vpn.conf'
    DNSMASQ_VPN_CFG = '00-use-vpn.conf'
    DNSMASQ_VPN_NS_HOOK_CFG = '10-vpn-nameserver.conf'

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
        """
        Origin system resolver
        :return: origin system resolver
        """
        return self.__resolver

    @_resolver.setter
    def _resolver(self, resolver: DNSFlavour):
        self.__resolver = resolver

    def setup(self, vpn_service: str, origin_resolv_conf: Path, vpn_resolv_conf: Path, vpn_nameserver_hook_conf: Path):
        if not self._available:
            logger.error('[dnsmasq] is not yet installed or is corrupted')
            sys.exit(ErrorCode.MISSING_REQUIREMENT)
        logger.info('Setup DNS resolver[dnsmasq]...')
        dnsmasq_vpn_cfg = self._dnsmasq_vpn_cfg(vpn_service)
        runtime_resolv_cfg = self.adapt_dnsmasq(origin_resolv_conf, vpn_service)
        dnsmasq_opts = {
            '{{DNS_RESOLVED_FILE}}': self.__build_dnsmasq_conf('resolv-file', runtime_resolv_cfg),
            '{{PORT}}': self.__build_dnsmasq_conf('port', self.dnsmasq_options().get('port', None)),
            '{{CACHE_SIZE}}': self.__build_dnsmasq_conf('cache-size', self.dnsmasq_options().get('cache_size', None))
        }
        logger.debug(f'Add [dnsmasq] config for {vpn_service}[{dnsmasq_vpn_cfg}]...')
        FileHelper.copy(self.resource_dir.joinpath(self.DNSMASQ_CONFIG_TMPL), dnsmasq_vpn_cfg, force=True)
        FileHelper.replace_in_file(dnsmasq_vpn_cfg, dnsmasq_opts, backup='')
        FileHelper.chmod(dnsmasq_vpn_cfg, mode=0o0644)
        logger.debug(f'Symlink [dnsmasq] VPN nameserver runtime configuration [{vpn_nameserver_hook_conf}]...')
        FileHelper.create_symlink(vpn_nameserver_hook_conf, self._dnsmasq_vpn_hook_cfg, force=True)
        logger.info(f'Generate System DNS config file from VPN service...')
        FileHelper.write_file(vpn_resolv_conf, self.__dnsmasq_resolv(vpn_service), mode=0o0644)
        FileHelper.create_symlink(vpn_resolv_conf, DNSResolver.DNS_SYSTEM_FILE, force=True)
        self.service.enable(self.config.identity)

    def adapt_dnsmasq(self, origin_resolv_conf: Path, vpn_service: str) -> Optional[Path]:
        return self._resolver.adapt_dnsmasq(origin_resolv_conf, vpn_service) if self._resolver else None

    def dnsmasq_options(self):
        options = self._resolver.dnsmasq_options() if self._resolver else None
        return {'cache_size': 1500, 'port': 53} if options is None else options

    def tweak_per_nic(self, nic: str):
        return self._resolver.tweak_per_nic(nic) if self._resolver else False

    def update_hook(self, reason: DHCPReason, priv_root_dns: str, nameservers: list, vpn_nameserver_hook_conf: Path):
        logger.info(f'Update VPN DNS config file on [{reason.name}][{priv_root_dns}] with nameservers {nameservers}...')
        servers = '\n'.join([f'server=/{priv_root_dns}/{ns}' for ns in nameservers])
        FileHelper.write_file(vpn_nameserver_hook_conf, mode=0o644,
                              content=f'### Generated at [{datetime.now().isoformat()}]\n{servers}\n')

    def reset_hook(self, vpn_nameserver_hook_conf: Path):
        logger.info(f'Reset VPN DNS config file...')
        if FileHelper.is_writable(vpn_nameserver_hook_conf):
            FileHelper.write_file(vpn_nameserver_hook_conf, mode=0o644, content='')
            FileHelper.create_symlink(vpn_nameserver_hook_conf, self._dnsmasq_vpn_hook_cfg, force=True)
        else:
            FileHelper.rm(self._dnsmasq_vpn_hook_cfg)

    def restore_config(self, vpn_service: str, keep_dnsmasq=True):
        if not keep_dnsmasq:
            logger.debug(f'Remove dnsmasq vpn hook config [{self._dnsmasq_vpn_hook_cfg}]')
            FileHelper.rm(self._dnsmasq_vpn_hook_cfg)
            logger.debug(f'Remove dnsmasq vpn config [{self._dnsmasq_vpn_cfg(vpn_service)}]')
            FileHelper.rm(self._dnsmasq_vpn_cfg(vpn_service))
        if self._resolver:
            self._resolver.restore_config(vpn_service, keep_dnsmasq)

    def restart(self, **kwargs):
        include_all = kwargs.get('_all', False)
        keep_dnsmasq = kwargs.get('keep_dnsmasq', True)
        if not keep_dnsmasq and self._is_serviceable:
            self.service.stop(self.config.identity)
            self.service.disable(self.config.identity)
        if include_all and self._resolver:
            self._resolver.restart()
        if keep_dnsmasq and self._is_serviceable:
            super().restart()

    def _dnsmasq_vpn_cfg(self, vpn_service: str):
        return self.config.to_fqn_cfg(self.DNSMASQ_VPN_CFG.replace('vpn', vpn_service))

    @property
    def _dnsmasq_vpn_hook_cfg(self):
        return self.config.to_fqn_cfg(self.DNSMASQ_VPN_NS_HOOK_CFG)

    @property
    def _is_serviceable(self):
        return self._available and self.dnsmasq_compatible is not DNSCompatibleMode.PLUGIN

    @staticmethod
    def __dnsmasq_resolv(service_name: str = 'VPN'):
        now = datetime.now().isoformat()
        return f'### Generated by [{service_name}] service and managed by [dnsmasq] at [{now}]\n' \
               f'nameserver 127.0.0.1\n'

    @staticmethod
    def __build_dnsmasq_conf(key: str, value: Any):
        return f'{key}={str(value)}' if value else ''


class DNSResolverType(Enum):
    CONNMAN = DNSConfig('connman', '/etc/connman/main.conf', '/etc/systemd/system/connman.service.d',
                        runtime_resolv='/run/connman/resolv.conf', flavour_type=ConnmanFlavour)
    """
    https://wiki.archlinux.org/index.php/ConnMan
    https://manpages.debian.org/unstable/connman/connman.conf.5.en.html
    """

    SYSTEMD_RESOLVED = DNSConfig('systemd-resolved', '/etc/systemd/resolved.conf',
                                 '/etc/systemd/resolved.conf.d', runtime_resolv='/run/systemd/resolve/resolv.conf',
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
                           runtime_resolv='/etc/resolvconf/resolv.conf.d/original')
    """    
    Debian use systemd/resolvconf
    https://manpages.debian.org/buster/resolvconf/resolvconf.8.en.html
    """

    OPEN_RESOLV = DNSConfig('resolvconf', '/etc/resolvconf.conf', '/etc/resolvconf/update.d',
                            runtime_resolv='/var/run/dnsmasq/resolv.conf', is_service=False,
                            flavour_type=OpenResolvFlavour)
    """
    Raspbian use openresolv
    https://manpages.debian.org/buster/openresolv/resolvconf.8.en.html
    https://manpages.debian.org/buster/openresolv/resolvconf.conf.5.en.html
    """

    DNSMASQ = DNSConfig('dnsmasq', '/etc/dnsmasq.conf', '/etc/dnsmasq.d', flavour_type=DNSMasqFlavour)
    """
    dnsmasq
    https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
    """

    UNKNOWN = None

    @classmethod
    def as_services(cls):
        return (t for t in DNSResolverType if not t.is_unknown() and t.config.is_service)

    @classmethod
    def as_command(cls):
        return (t for t in DNSResolverType if not t.is_unknown() and not t.config.is_service)

    @property
    def config(self) -> Optional[DNSConfig]:
        return None if self.is_unknown() else self.value

    def is_unknown(self):
        return self is DNSResolverType.UNKNOWN

    def is_dnsmasq(self):
        return self is DNSResolverType.DNSMASQ

    def might_be_command(self):
        return self.is_unknown() or self.is_dnsmasq()


class DNSResolver(AppConvention):
    DNS_SYSTEM_FILE = Path('/etc/resolv.conf')
    DNS_ORIGIN_FILE = 'resolv.origin.conf'
    VPN_DNS_RESOLV_CFG = 'resolv.vpn.conf'
    VPN_NAMESERVER_HOOK_CFG = 'vpn-runtime-nameserver.conf'
    CONNMAN_DHCP = 'connman-dhcp'

    def __init__(self, resource_dir: Union[str, Path], runtime_dir: Union[str, Path], unix_service: UnixService,
                 log_lvl: int = logger.DEBUG, silent: bool = True):
        super(DNSResolver, self).__init__(resource_dir, runtime_dir, log_lvl, silent)
        self.service, self.kind, self._is_dnsmasq = unix_service, DNSResolverType.UNKNOWN, False
        self.origin_resolv_cfg = DNSResolver.DNS_SYSTEM_FILE.parent.joinpath(DNSResolver.DNS_ORIGIN_FILE)
        self.vpn_resolv_cfg = DNSResolver.DNS_SYSTEM_FILE.parent.joinpath(DNSResolver.VPN_DNS_RESOLV_CFG)
        self.vpn_hook_cfg = self.runtime_dir.joinpath(self.VPN_NAMESERVER_HOOK_CFG)
        self.connman_dhcp = self.runtime_dir.joinpath(self.CONNMAN_DHCP)

    def probe(self) -> 'DNSResolver':
        self.kind = next(
            (t for t in DNSResolverType.as_services() if self.service.status(t.config.identity).is_enabled()),
            self.kind)
        if self.kind.might_be_command():
            self.kind = next(t for t in DNSResolverType.as_command() if SystemHelper.verify_command(t.config.identity))
        if self.kind.is_unknown():
            logger.warn('Unknown DNS resolver. DNS VPN IP might be not resolved correctly')
        if self.kind not in [DNSResolverType.DNSMASQ, DNSResolverType.UNKNOWN]:
            dnsmasq_name = DNSResolverType.DNSMASQ.config.identity
            self._is_dnsmasq = self.service.status(dnsmasq_name).is_enabled() or shutil.which(dnsmasq_name) is not None
        logger.debug(f'Current DNS resolver [{self.kind.name}], is dnsmasq available [{self._is_dnsmasq}]')
        return self

    def is_connman(self) -> bool:
        return self.kind is DNSResolverType.CONNMAN

    def is_enable_connman_dhcp(self) -> bool:
        yes_ = ('true', 't', 'yes', '1')
        return self.is_connman() and FileHelper.read_file_by_line(self.connman_dhcp,
                                                                  fallback_if_not_exists='0').lower() in yes_

    def is_dnsmasq_available(self):
        return self.kind.is_dnsmasq() or self._is_dnsmasq

    def create_config(self, vpn_service: str, auto_connman_dhcp: bool):
        if self.is_connman():
            FileHelper.write_file(self.connman_dhcp, str(auto_connman_dhcp))
            return
        if not FileHelper.is_readable(self.origin_resolv_cfg):
            logger.info(f'Backup System DNS config file to [{self.origin_resolv_cfg}]...')
            FileHelper.backup(DNSResolver.DNS_SYSTEM_FILE, self.origin_resolv_cfg, remove=False)
        if not FileHelper.is_readable(self.origin_resolv_cfg):
            logger.error(f'Not found origin DNS config file [{self.origin_resolv_cfg}]')
            sys.exit(ErrorCode.FILE_CORRUPTED)
        if not FileHelper.is_readable(self.vpn_hook_cfg):
            FileHelper.touch(self.vpn_hook_cfg, 0o0644)
        self._resolver().setup(vpn_service, self.origin_resolv_cfg, self.vpn_resolv_cfg, self.vpn_hook_cfg)
        self._resolver().restart(_all=True)

    def cleanup_config(self, vpn_service: str, keep_dnsmasq=True):
        if self.is_connman():
            return
        resolver = self._resolver()
        if keep_dnsmasq:
            resolver.reset_hook(self.vpn_hook_cfg)
        elif FileHelper.is_readable(self.origin_resolv_cfg):
            logger.info(f'Restore System DNS config file...')
            FileHelper.backup(self.origin_resolv_cfg, DNSResolver.DNS_SYSTEM_FILE)
            FileHelper.rm(self.vpn_resolv_cfg)
        resolver.restore_config(vpn_service, keep_dnsmasq)
        resolver.restart(_all=not keep_dnsmasq, keep_dnsmasq=keep_dnsmasq)

    def tweak_on_nic(self, nic: str):
        if self._resolver().tweak_per_nic(nic):
            self._resolver().restart(_all=True)

    def resolve(self, vpn_service: str, reason: DHCPReason, priv_root_dns: str, new_nameservers: str = None,
                old_nameservers: str = None):
        if reason.is_release():
            self.cleanup_config(vpn_service=vpn_service)
            return
        nss = self.__validate_nameservers(reason, new_nameservers, old_nameservers)
        if nss is None:
            logger.info(f'Skip generating DNS entry in [{reason.name}][{new_nameservers}][{old_nameservers}]')
            return
        self._resolver().update_hook(reason, priv_root_dns, nss, self.vpn_hook_cfg)
        self.restart()

    def restart(self):
        self._resolver().restart(_all=self.is_connman(), keep_dnsmasq=True)

    def _resolver(self) -> DNSFlavour:
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
        if reason is DHCPReason.RENEW and new_ns == old_ns and FileHelper.is_readable(self.vpn_hook_cfg):
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

    @abstractmethod
    def add_hook(self, service_name: str, replacements: dict):
        pass

    @abstractmethod
    def remove_hook(self, service_name: str):
        pass

    @abstractmethod
    def create_config(self, vpn_acc: str, replacements: dict):
        pass

    def lease_ip(self, vpn_acc: str, vpn_nic: str, daemon=False, is_execute=True):
        logger.log(self.log_lvl, 'Lease a new VPN IP...')
        command = f'{self.ip_tool} {self._lease_ip_opt(vpn_acc, vpn_nic, daemon)}'
        if is_execute:
            SystemHelper.exec_command(command, silent=self.silent, log_lvl=logger.down_lvl(self.log_lvl))
        return command

    def release_ip(self, vpn_acc: str, vpn_nic: str):
        logger.log(self.log_lvl, 'Release the current VPN IP...')
        SystemHelper.exec_command(f'{self.ip_tool} {self._release_ip_opt(vpn_acc, vpn_nic)}',
                                  silent=self.silent, log_lvl=logger.down_lvl(self.log_lvl))

    def renew_all_ip(self, delay=1, silent=False):
        logger.log(self.log_lvl, 'Refresh all IPs...')
        time.sleep(delay)
        SystemHelper.exec_command(f'{self._refresh_all_ip_opt()}', silent=silent or self.silent,
                                  log_lvl=logger.down_lvl(self.log_lvl))

    def cleanup_zombie(self, process):
        logger.decrease(self.log_lvl, 'Cleanup the IP lease zombie processes...')
        SystemHelper.kill_by_process(f'{self.ip_tool}.*{process}.*', silent=True, log_lvl=self.log_lvl)

    def get_vpn_ip(self, nic: str, lenient=True):
        try:
            logger.log(self.log_lvl, f'Query VPN IPv4 on {nic}...')
            return netifaces.ifaddresses(nic)[netifaces.AF_INET]
        except Exception as err:
            if lenient:
                logger.debug(f'Not found VPN IP {nic}. Error: {err}')
                return None
            raise err

    def _to_config_file(self, suffix):
        return self.runtime_dir.joinpath(f'vpn_dhclient.{suffix}.conf')

    @abstractmethod
    def _lease_ip_opt(self, vpn_acc: str, vpn_nic: str, daemon=False) -> str:
        pass

    @abstractmethod
    def _release_ip_opt(self, vpn_acc: str, vpn_nic: str) -> str:
        pass

    @abstractmethod
    def _refresh_all_ip_opt(self) -> str:
        pass

    @abstractmethod
    def _to_hook_file(self, service_name: str, is_enter_hook=False) -> str:
        pass


class Systemd(UnixService):
    """
    Systemd service
    """

    SERVICE_FILE_TMPL = 'playio-vpn.service.tmpl'

    @staticmethod
    def factory(resource_dir: Union[str, Path], runtime_dir: Union[str, Path]) -> 'UnixService':
        if SystemHelper.verify_command(f'pidof {UnixServiceType.SYSTEMD.value}'):
            return Systemd(resource_dir=resource_dir, runtime_dir=runtime_dir)
        return None

    @property
    def kind(self) -> UnixServiceType:
        return UnixServiceType.SYSTEMD

    @property
    def standard_service_dir(self) -> str:
        return '/etc/systemd/system'

    def create(self, svc_opts: UnixServiceOpts, replacements: dict, auto_startup: bool = False):
        service_fqn = self.to_service_fqn(svc_opts.service_dir, svc_opts.service_name)
        logger.info(f'Add new service [{svc_opts.service_name}] in [{service_fqn}]...')
        FileHelper.copy(self.resource_dir.joinpath(Systemd.SERVICE_FILE_TMPL), service_fqn, force=True)
        FileHelper.replace_in_file(service_fqn, replacements, backup='')
        FileHelper.chmod(service_fqn, mode=0o0644)
        SystemHelper.exec_command("systemctl daemon-reload", silent=True, log_lvl=logger.INFO)
        if auto_startup:
            self.enable(svc_opts.service_name)

    def remove(self, svc_opts: UnixServiceOpts, force: bool = False):
        service_fqn = self.to_service_fqn(svc_opts.service_dir, svc_opts.service_name)
        self.stop(svc_opts.service_name)
        self.disable(svc_opts.service_name)
        if force and FileHelper.is_exists(service_fqn):
            logger.info(f'Remove System service [{svc_opts.service_name}]...')
            FileHelper.rm(service_fqn)
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
                                           shell=True, silent=True, log_lvl=logger.TRACE)
        return ServiceStatus.parse(status)

    def to_service_fqn(self, service_dir: str, service_name: str):
        return os.path.join(service_dir, f'{service_name}.service')


class Procd(UnixService, ABC):
    """
    Procd for OpenWRT: https://openwrt.org/docs/techref/procd
    """

    @staticmethod
    def factory(resource_dir: Union[str, Path], runtime_dir: Union[str, Path]) -> 'UnixService':
        if SystemHelper.verify_command(f'pidof {UnixServiceType.PROCD.value}'):
            raise NotImplementedError('Not yet supported OpenWRT')
        return None


class DHCPResolver(IPResolver):
    ENTER_HOOKS_DIR = '/etc/dhcp/dhclient-enter-hooks.d'
    EXIT_HOOKS_DIR = '/etc/dhcp/dhclient-exit-hooks.d'
    DHCLIENT_EXIT_HOOK_TMPL = 'dhclient-vpn.exit.hook.tmpl'
    DHCLIENT_CONFIG_TMPL = 'dhclient-vpn.conf.tmpl'

    @staticmethod
    def factory(resource_dir: Union[str, Path], runtime_dir: Union[str, Path], log_lvl: int,
                silent: bool = True) -> 'IPResolver':
        if SystemHelper.which(IPResolverType.DHCLIENT.value):
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
        exit_hook_file = self._to_hook_file(service_name)
        logger.log(self.log_lvl, f'Create DHCP client VPN hook[{exit_hook_file}]...')
        FileHelper.copy(self.resource_dir.joinpath(self.DHCLIENT_EXIT_HOOK_TMPL), exit_hook_file, force=True)
        FileHelper.replace_in_file(exit_hook_file, replacements, backup='')
        FileHelper.chmod(exit_hook_file, mode=0o0744)

    def remove_hook(self, service_name: str):
        exit_hook_file = self._to_hook_file(service_name)
        logger.log(self.log_lvl, f'Remove DHCP client VPN hook[{exit_hook_file}]...')
        FileHelper.rm(exit_hook_file, force=True)

    def _to_hook_file(self, service_name: str, is_enter_hook=False) -> str:
        return os.path.join(DHCPResolver.ENTER_HOOKS_DIR if is_enter_hook else DHCPResolver.EXIT_HOOKS_DIR,
                            service_name)

    def _lease_ip_opt(self, vpn_acc: str, vpn_nic: str, daemon=False) -> str:
        opts = f'-nw' if daemon else f'-1'
        return f'--no-pid -v {opts} {vpn_nic}'

    def _release_ip_opt(self, vpn_acc: str, vpn_nic: str) -> str:
        return f'-r -v {vpn_nic}'

    def _refresh_all_ip_opt(self):
        return f'{self.ip_tool} -1 -v'


class UDHCPCResolver(IPResolver, ABC):

    @property
    def ip_tool(self) -> str:
        return IPResolverType.UDHCPC.value


class PackageManager(ABC):

    @property
    @abstractmethod
    def tool(self) -> str:
        pass

    def install(self, package):
        SystemHelper.exec_command(f'{self.tool} install {package} -y', log_lvl=logger.INFO, silent=True)


class YumPM(PackageManager):

    @property
    def tool(self) -> str:
        return 'yum'


class AptPM(PackageManager):

    @property
    def tool(self) -> str:
        return 'apt'


class DeviceResolver:

    def __init__(self):
        self.__service = None
        self.__ip_resolver = None
        self.__dns_resolver = None

    def probe(self, resource_dir: Union[str, Path], runtime_dir: Union[str, Path], log_lvl=logger.DEBUG,
              silent=True) -> 'DeviceResolver':
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

    @property
    def pm(self) -> Optional[PackageManager]:
        if SystemHelper.which(AptPM().tool):
            return AptPM()
        if SystemHelper.which(YumPM().tool):
            return YumPM()
        return None

    def install_dnsmasq(self, auto_install: bool = False):
        if not auto_install:
            logger.error('dnsmasq is not yet installed. Please install [dnsmasq] depends on your distro')
            sys.exit(ErrorCode.MISSING_REQUIREMENT)
        logger.info('Try to install [dnsmasq]...')
        pm = self.pm
        if not pm:
            logger.error('Unknown package manager. Please install [dnsmasq] by yourself')
            sys.exit(ErrorCode.MISSING_REQUIREMENT)
        pm.install('dnsmasq')
        self._dns_resolver(self.dns_resolver.probe())

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
