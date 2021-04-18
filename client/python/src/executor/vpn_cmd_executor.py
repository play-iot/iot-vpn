import os
from abc import ABC, abstractmethod
from typing import TypeVar
from typing import Union, Sequence, Dict

from src.executor.shell_executor import SystemHelper
from src.utils import logger as logger
from src.utils.helper import encode_base64, decode_base64
from src.utils.opts_vpn import VpnDirectory

VpnOpts = TypeVar("VpnOpts", bound=VpnDirectory)


class VpnCmdExecutor(ABC):

    def __init__(self, vpn_opts: VpnOpts):
        self._vpn_opts = vpn_opts

    @property
    def opts(self) -> VpnOpts:
        return self._vpn_opts

    @property
    def vpn_dir(self):
        return self.opts.vpn_dir

    @property
    def vpn_cmd(self):
        return self.opts.vpncmd

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
        if not self.vpn_cmd or not os.path.exists(self.vpn_cmd):
            if silent is False:
                raise RuntimeError('vpncmd does not exist')
            return None
        d, kv, o = None, True, None
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
            o = SystemHelper.exec_command(f'{self.vpn_cmd} {self.vpn_cmd_opt()} {c} {p}', silent=silent,
                                          log_lvl=log_lvl)
            logger.sep(log_lvl)
        return o

    @staticmethod
    def generate_host_name(hub: str, user: str, log_lvl=logger.DEBUG):
        hostname = encode_base64(hub + '::' + user, url_safe=True, without_padding=True)
        logger.log(log_lvl, f"Generate hostname from VPN hub and VPN user to '{hostname}'")
        return hostname

    @staticmethod
    def decode_host_name(hostname: str) -> str:
        value = decode_base64(hostname, url_safe=True, without_padding=True, lenient=True)
        if '::' not in value:
            return value
        try:
            return value.split('::')[1]
        except:
            logger.warn(f'Hostname is invalid {value}')
        return value
