import fileinput
import re

from src.executor.shell_executor import SystemHelper, ServiceStatus


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
