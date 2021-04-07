import errno
import os
import re
import socket
import subprocess
import sys
import time
from enum import Enum
from subprocess import CompletedProcess
from typing import Union

from src.utils import logger as logger
from src.utils.helper import is_py3_5, DEFAULT_ENCODING, FileHelper, tweak_os_env

TWEAK_ENV = tweak_os_env()


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


class SystemHelper(object):

    @staticmethod
    def verify_command(command: str, shell=False, log_lvl=logger.DEBUG) -> bool:
        try:
            SystemHelper.exec_command(command, shell=shell, silent=True, log_lvl=log_lvl)
            return True
        except:
            return False

    @staticmethod
    def exec_command(command: str, shell=False, silent=False, log_lvl=logger.DEBUG) -> str:
        logger.decrease(log_lvl, "Execute command: %s", command)
        list_cmd = command.split(" | ") if not shell else [command]
        length = len(list_cmd)
        prev = None
        for idx, cmd in enumerate(list_cmd, 1):
            logger.trace("\tsub_command::%s::%s", cmd, prev)
            kwargs = {} if is_py3_5() else {"encoding": "utf-8"}
            complete = subprocess.run(cmd.split() if not shell else cmd, input=prev, env=TWEAK_ENV, shell=shell,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
            ret = complete.returncode
            lvl = (logger.TRACE if idx < length else logger.DEBUG) if ret == 0 or silent else logger.ERROR
            try:
                prev = SystemHelper.__handle_command_result(complete, silent, lvl)
            except RuntimeError as _:
                if not silent:
                    logger.error('Failed when executing command %s', cmd)
                    sys.exit(ret)
            finally:
                ret_val = ("0. Actual: %s" % ret) if silent and ret != 0 else ret
                logger.decrease(log_lvl, "%sReturn code: %s", "\t" if idx < length else "", ret_val)
        if prev:
            logger.log(log_lvl, "\t%s", prev)
        return prev

    @staticmethod
    def __handle_command_result(complete: Union[CompletedProcess, dict], silent=False, log_level=logger.TRACE):
        stdout = complete.stdout if isinstance(complete, CompletedProcess) else complete['stdout']
        stderr = complete.stderr if isinstance(complete, CompletedProcess) else complete['stderr']
        ret = complete.returncode if isinstance(complete, CompletedProcess) else complete['returncode']
        if ret == 0 or ret is None:
            return stdout.strip() if not is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip()
        if not silent:
            logger.log(log_level, "+" * 40)
            logger.log(log_level, "\tcommand: %s", " ".join(complete.args))
            logger.log(log_level, "-" * 40)
            logger.log(log_level, "\tstdout: %s",
                       stdout.strip() if not is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip())
            logger.log(log_level, "-" * 40)
            logger.log(log_level, "\tstderr: %s",
                       stderr.strip() if not is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip())
            logger.log(log_level, "+" * 40)
        raise RuntimeError()

    @staticmethod
    def create_service(service_name: str, is_start: bool = False):
        logger.info("Enable System service '%s'...", service_name)
        SystemHelper.exec_command("systemctl enable %s" % service_name, log_lvl=logger.INFO)
        if is_start:
            SystemHelper.restart_service(service_name)

    @staticmethod
    def stop_service(service_name: str):
        logger.info("Stop System service '%s'...", service_name)
        SystemHelper.exec_command("systemctl stop %s" % service_name, silent=True, log_lvl=logger.INFO)

    @staticmethod
    def disable_service(service_name: str, service_fqn: str, force: bool = False):
        logger.info(f"Disable System service '{service_name}'...")
        SystemHelper.exec_command("systemctl stop %s" % service_name, silent=True, log_lvl=logger.INFO)
        SystemHelper.exec_command("systemctl disable %s" % service_name, silent=True, log_lvl=logger.INFO)
        if force and os.path.exists(service_fqn):
            logger.info("Remove System service '%s'...", service_name)
            os.remove(service_fqn)
        SystemHelper.exec_command("systemctl daemon-reload", silent=True, log_lvl=logger.INFO)

    @staticmethod
    def restart_service(service_name: str, delay: int = 1):
        logger.info("Restart System service '%s'...", service_name)
        SystemHelper.exec_command("systemctl restart %s" % service_name, log_lvl=logger.INFO)
        time.sleep(delay)

    @staticmethod
    def status_service(service_name: str) -> ServiceStatus:
        status = SystemHelper.exec_command(f"systemctl status {service_name} | grep Active | awk '{{print $2$3}}'",
                                           shell=True, silent=True, log_lvl=logger.DEBUG)
        return ServiceStatus.parse(status)

    @staticmethod
    def ps_kill(process_name: str, silent=True, log_lvl=logger.DEBUG):
        pid = SystemHelper.exec_command(f"ps aux | grep -e '{process_name}' | awk '{{print $2}}'", shell=True,
                                        silent=silent, log_lvl=log_lvl)
        if pid:
            SystemHelper.exec_command(f'kill -9 {pid}', silent=silent, log_lvl=log_lvl)

    @staticmethod
    def is_pid_exists(pid: int):
        """Check whether pid exists in the current process table."""
        if pid == 0:
            # According to "man 2 kill" PID 0 has a special meaning:
            # it refers to <<every process in the process group of the
            # calling process>> so we don't want to go any further.
            # If we get here it means this UNIX platform *does* have
            # a process with id 0.
            return True
        try:
            os.kill(pid, 0)
        except OSError as err:
            if err.errno == errno.ESRCH:
                # ESRCH == No such process
                return False
            elif err.errno == errno.EPERM:
                # EPERM clearly means there's a process to deny access to
                return True
            else:
                # According to "man 2 kill" possible error values are
                # (EINVAL, EPERM, ESRCH) therefore we should never get
                # here. If we do let's be explicit in considering this
                # an error.
                raise err
        else:
            return True

    @staticmethod
    def change_host_name(hostname: str, log_lvl=logger.DEBUG):
        prev_regex = re.escape('127.0.1.1') + r'\s+' + re.escape(socket.gethostname()) + r'.*'
        SystemHelper.exec_command(f'hostnamectl set-hostname {hostname}', log_lvl=logger.down_lvl(log_lvl))
        FileHelper.replace_in_file('/etc/hosts', {prev_regex: f'127.0.1.1    {hostname}'}, regex=True)
        SystemHelper.exec_command(f'hostnamectl', silent=True, log_lvl=log_lvl)
        logger.sep(level=log_lvl, quantity=20)
        SystemHelper.exec_command(f'cat /etc/hosts', silent=True, log_lvl=log_lvl)
        logger.sep(level=log_lvl)
