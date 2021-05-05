import errno
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
from subprocess import CompletedProcess
from typing import Union

from src.utils import logger as logger
from src.utils.helper import DEFAULT_ENCODING, FileHelper, EnvHelper

TWEAK_ENV = EnvHelper.tweak_os_env()


class SystemHelper(object):

    @staticmethod
    def verify_command(command: str, shell=False, log_lvl=logger.DEBUG) -> bool:
        try:
            SystemHelper.exec_command(command, shell=shell, silent=True, log_lvl=logger.down_lvl(log_lvl))
            return True
        except:
            return False

    @staticmethod
    def which(command):
        return True if shutil.which(command) else False

    @staticmethod
    def exec_command(command: str, shell=False, silent=False, log_lvl=logger.DEBUG) -> str:
        logger.decrease(log_lvl, "Execute command: %s", command)
        list_cmd = command.split(" | ") if not shell else [command]
        length = len(list_cmd)
        prev = None
        for idx, cmd in enumerate(list_cmd, 1):
            logger.trace("\tsub_command::%s::%s", cmd, prev)
            kwargs = {} if EnvHelper.is_py3_5() else {"encoding": "utf-8"}
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
            return stdout.strip() if not EnvHelper.is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip()
        if not silent:
            logger.log(log_level, "+" * 40)
            logger.log(log_level, "\tcommand: %s", " ".join(complete.args))
            logger.log(log_level, "-" * 40)
            logger.log(log_level, "\tstdout: %s",
                       stdout.strip() if not EnvHelper.is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip())
            logger.log(log_level, "-" * 40)
            logger.log(log_level, "\tstderr: %s",
                       stderr.strip() if not EnvHelper.is_py3_5() else stdout.decode(DEFAULT_ENCODING).strip())
            logger.log(log_level, "+" * 40)
        raise RuntimeError()

    @staticmethod
    def kill_by_process(process_name: str, silent=True, log_lvl=logger.DEBUG):
        pid = SystemHelper.exec_command(f"ps aux | grep -e '{process_name}' | awk '{{print $2}}'", shell=True,
                                        silent=silent, log_lvl=logger.down_lvl(log_lvl))
        if pid:
            SystemHelper.kill_by_pid(pid.split('\n'), silent=silent, log_lvl=logger.down_lvl(log_lvl))

    @staticmethod
    def kill_by_pid(pid: list, _signal=signal.SIGTERM, silent=True, log_lvl=logger.DEBUG):
        for p in pid or []:
            try:
                logger.log(log_lvl, f'Kill PID [{p}::{_signal}]...')
                os.kill(int(p), _signal)
            except OSError as err:
                SystemHelper.handle_kill_error(err, silent)
            except ValueError as err:
                logger.decrease(log_lvl, f'Error PID [{p}]. Error: {err}')

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
            return SystemHelper.handle_kill_error(err)
        else:
            return True

    @staticmethod
    def handle_kill_error(err: OSError, silent=True):
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
            if not silent:
                raise err
            return False

    @staticmethod
    def change_host_name(hostname: str, log_lvl=logger.DEBUG):
        prev_regex = re.escape('127.0.1.1') + r'\s+' + re.escape(socket.gethostname()) + r'.*'
        SystemHelper.exec_command(f'hostnamectl set-hostname {hostname}', log_lvl=logger.down_lvl(log_lvl))
        FileHelper.replace_in_file('/etc/hosts', {prev_regex: f'127.0.1.1    {hostname}'}, regex=True)
        SystemHelper.exec_command(f'hostnamectl', silent=True, log_lvl=log_lvl)
        logger.sep(level=log_lvl, quantity=20)
        SystemHelper.exec_command(f'cat /etc/hosts', silent=True, log_lvl=log_lvl)
        logger.sep(level=log_lvl)
