import sys
from abc import ABC, abstractmethod
from typing import Union, Sequence, Dict

from src.executor.shell_executor import SystemHelper
from src.utils import logger as logger
from src.utils.constants import ErrorCode
from src.utils.helper import FileHelper, TextHelper, EnvHelper
from src.utils.opts_vpn import VpnOpts


class VpnCmdExecutor(ABC):

    def __init__(self, vpn_opts: VpnOpts):
        self._vpn_opts = vpn_opts

    @property
    def opts(self) -> VpnOpts:
        return self._vpn_opts

    @property
    def vpn_dir(self):
        return self.opts.vpn_dir

    def is_installed(self, silent=False, log_lvl=logger.DEBUG):
        if FileHelper.is_dir(self.opts.vpn_dir) and FileHelper.is_executable(self.opts.vpncmd) and self._is_install():
            return True
        _, cmd = EnvHelper.build_executable_command()
        msg = self._not_install_error_msg(cmd)
        if silent:
            logger.decrease(log_lvl, msg)
            return False
        logger.error(msg)
        sys.exit(ErrorCode.VPN_NOT_YET_INSTALLED)

    @abstractmethod
    def vpn_cmd_opt(self):
        pass

    @abstractmethod
    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    @abstractmethod
    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def exec_command(self, commands: Union[str, Sequence[str], Dict[str, str]], params: Union[str, Sequence[str]] = "",
                     silent=False, log_lvl=logger.DEBUG, **kwargs):
        try:
            self.pre_exec(silent, logger.down_lvl(log_lvl), **kwargs)
            return self._run(commands, log_lvl, params, silent)
        finally:
            self.post_exec(silent, logger.down_lvl(log_lvl), **kwargs)

    def _run(self, commands, log_lvl, params, silent):
        if not self.is_installed(silent):
            return None
        d, kv, output = None, True, ''
        if isinstance(commands, str):
            if isinstance(params, (list, tuple)):
                d, kv = {p: commands for p in params}, False
            else:
                d = {commands: params}
        else:
            d = commands if type(commands) is dict else {k: params for k in commands}
        for k, v in d.items():
            c, p = (k, v) if kv else (v, k)
            logger.decrease(log_lvl, f"Execute VPN Command '{c if ' ' not in c else c.split()[0]}'")
            o = SystemHelper.exec_command(f'{self.opts.vpncmd} {self.vpn_cmd_opt()} {c} {p}', silent=silent,
                                          log_lvl=logger.down_lvl(log_lvl))
            o = self._optimize_command_result(o)
            logger.log(log_lvl, o)
            logger.sep(log_lvl)
            output += o
        return output

    def _is_install(self) -> bool:
        return True

    def _not_install_error_msg(self, cmd) -> str:
        return f'Missing VPN installation'

    def _optimize_command_result(self, output):
        return output

    @staticmethod
    def generate_host_name(hub: str, user: str, log_lvl=logger.DEBUG):
        hostname = TextHelper.encode_base64(hub + '::' + user, url_safe=True, without_padding=True)
        logger.log(log_lvl, f"Generate hostname from VPN hub and VPN user to '{hostname}'")
        return hostname

    @staticmethod
    def decode_host_name(hostname: str) -> str:
        value = TextHelper.decode_base64(hostname, url_safe=True, without_padding=True, lenient=True)
        if '::' not in value:
            return value
        try:
            return value.split('::')[1]
        except:
            logger.warn(f'Hostname is invalid {value}')
        return value
