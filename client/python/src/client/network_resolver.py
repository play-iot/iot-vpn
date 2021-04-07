import fileinput
import re
import time

from src.executor.shell_executor import SystemHelper, ServiceStatus
from src.utils import logger as logger


class DNSResolver:
    is_connman = False
    is_dnsmasq = False
    is_systemd_resolved = False
    is_network_manager = False
    is_resolvconf = False

    @classmethod
    def probe(cls):
        if SystemHelper.status_service("connman.service") is ServiceStatus.RUNNING:
            cls.is_connman = True
        if SystemHelper.status_service("dnsmasq.service") is ServiceStatus.RUNNING:
            cls.is_dnsmasq = True
        if SystemHelper.status_service("systemd-resolved.service") is ServiceStatus.RUNNING:
            cls.is_systemd_resolved = True
        if SystemHelper.status_service("NetworkManager.service") is ServiceStatus.RUNNING:
            cls.is_network_manager = True
        if SystemHelper.status_service("resolvconf.service") is ServiceStatus.RUNNING or SystemHelper.verify_command("resolvconf"):
            cls.is_resolvconf = True
        return cls

    @classmethod
    def resolve(cls, nic: str):
        if cls.is_connman:
            cls.__tweak_connman(nic)
        if cls.is_dnsmasq:
            cls.__tweak_dnsmasq(nic)
        if cls.is_systemd_resolved:
            cls.__tweak_systemd_resolved(nic)
        if cls.is_network_manager:
            cls.__tweak_network_manager(nic)
        if cls.is_resolvconf:
            cls.__tweak_resolvconf(nic)

    @classmethod
    def __tweak_connman(cls, nic):
        restart = False
        with fileinput.FileInput("/etc/connman/main.conf", inplace=True, backup='.bak') as f:
            for line in f:
                if re.match(r"^NetworkInterfaceBlacklist\s*=\s*", line, re.IGNORECASE) and nic not in line:
                    restart = True
                    print(line.strip() + "," + nic)
                else:
                    print(line, end='')
        if restart:
            SystemHelper.restart_service("connman")

    @classmethod
    def __tweak_systemd_resolved(cls, nic):
        pass

    @classmethod
    def __tweak_network_manager(cls, nic):
        pass

    @classmethod
    def __tweak_dnsmasq(cls, nic):
        pass

    @classmethod
    def __tweak_resolvconf(cls, nic):
        pass


class IPResolver:

    def __init__(self, pid_file: str, lease_file: str, log_lvl: int, silent: bool = True):
        self.log_lvl = log_lvl
        self.silent = silent
        self.opts = f'-lf {lease_file} -pf {pid_file} -v'

    def renew_ip(self, nic: str, daemon=False):
        logger.log(self.log_lvl, 'Lease a new VPN IP...')
        opt = '-nw' if daemon else '-1'
        SystemHelper.exec_command(f'dhclient {self.opts} {opt} {nic}', silent=self.silent, log_lvl=self.log_lvl)

    def release_ip(self, nic):
        logger.log(self.log_lvl, 'Release the current VPN IP...')
        SystemHelper.exec_command(f'dhclient {self.opts} -r {nic}', silent=self.silent, log_lvl=self.log_lvl)

    def renew_all_ip(self, delay=1):
        logger.log(self.log_lvl, 'Renew all IPs...')
        time.sleep(delay)
        SystemHelper.exec_command(f'dhclient -1 -v', silent=self.silent, log_lvl=logger.down_lvl(self.log_lvl))

    def cleanup_vpn_ip(self, delay=1):
        logger.log(self.log_lvl, 'Cleanup all dhclient for VPN...')
        SystemHelper.ps_kill('dhclient .* vpn_', silent=self.silent, log_lvl=logger.down_lvl(self.log_lvl))
        self.renew_all_ip(delay)

    def add_hooks(self):
        a = '/etc/dhcp/dhclient-exit-hooks.d'
