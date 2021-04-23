import functools
import os
from abc import abstractmethod
from pathlib import Path
from typing import TypeVar

import click

from src.utils.constants import AppEnv
from src.utils.helper import FileHelper, awk, grep
from src.utils.opts_shared import DevModeDir


class AuthOpts(object):
    def __init__(self, auth_type: str, user: str):
        self.auth_type = auth_type
        if not user:
            raise click.BadParameter("Missing user")
        self.user = user

    def setup(self, account: str) -> dict:
        raise NotImplementedError("Not yet supported")


class BasicAuthOpts(AuthOpts):

    def __init__(self, auth_type: str, user: str, password: str):
        super().__init__(auth_type, user)
        if not password:
            raise click.BadParameter("Missing password")
        self.password = password

    def setup(self, account: str) -> dict:
        _type = "standard" if self.auth_type == "password" else "radius"
        return {'AccountPasswordSet': f'{account} /PASSWORD:{self.password} /TYPE:{_type}'}


class CertAuthOpts(AuthOpts):

    def __init__(self, auth_type: str, user: str, cert_key: str, private_key: str):
        super().__init__(auth_type, user)
        if not cert_key or not private_key:
            raise click.BadParameter("Missing Cert key or Private key")
        self.cert_key = cert_key
        self.private_key = private_key

    def setup(self, account: str) -> dict:
        return {'AccountCertSet': f'{account} /LOADCERT:{self.cert_key} /LOADKEY:{self.private_key}'}


class ServerOpts(object):
    def __init__(self, host: str, hub: str, port: int = 443):
        if not host:
            raise click.BadParameter("Missing VPN Host")
        if not hub:
            raise click.BadParameter("Missing VPN Hub")
        self.server = host + ":" + str(port)
        self.hub = hub


def vpn_server_opts(func):
    @click.option("-sh", "--host", type=str, required=True, help="VPN server host")
    @click.option("-sp", "--port", type=click.IntRange(1, 65535), default=443, show_default=True,
                  help="VPN server port")
    @click.option("-su", "--hub", type=str, required=True, help="VPN customer hub")
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        kwargs["server_opts"] = ServerOpts(kwargs.pop("host", None), kwargs.pop("hub", None), kwargs.pop("port", 443))
        return func(*args, **kwargs)

    return wrapper


def vpn_auth_opts(func):
    @click.option("-ct", "--auth-type", type=click.Choice(["password", "cert"]), default="password",
                  required=True, help="VPN Client Authentication type")
    @click.option("-cu", "--user", type=str, required=True, help="VPN Client User to access VPN server")
    @click.option("-cp", "--password", type=str, help="VPN Client Password to access VPN server")
    @click.option("-cck", "--cert-key", type=click.Path(exists=True, resolve_path=True),
                  help="VPN Client Cert to access VPN server")
    @click.option("-cpk", "--private-key", type=click.Path(exists=True, resolve_path=True),
                  help="VPN Client Private Key to access VPN server")
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        auth_type = kwargs.pop("auth_type")
        password = kwargs.pop("password")
        cert_key = kwargs.pop("cert_key")
        private_key = kwargs.pop("private_key")
        if auth_type == "password":
            kwargs["auth_opts"] = BasicAuthOpts(auth_type, kwargs.pop("user"), password)
        elif auth_type == "cert":
            kwargs["auth_opts"] = CertAuthOpts(auth_type, kwargs.pop("user"), cert_key, private_key)
        else:
            raise click.BadArgumentUsage("Not support Auth type %s" % auth_type)
        return func(*args, **kwargs)

    return wrapper


class VpnDirectory(DevModeDir):
    CORE_VERSION_FILE = 'vpn-version.txt'
    OPT_NAME = 'vpn_opts'
    RUNTIME_FOLDER = 'runtime'
    PROFILE_D_ENV = f'/etc/profile.d/{AppEnv.BRAND}-vpn.sh'

    def __init__(self, app_dir: str):
        self.vpn_dir = Path(app_dir)

    @property
    def vpncmd(self) -> Path:
        return self.vpn_dir.joinpath('vpncmd')

    @property
    def runtime_dir(self) -> Path:
        return self.vpn_dir.joinpath(self.RUNTIME_FOLDER)

    @classmethod
    def resource_dir(cls) -> str:
        return cls.get_resource('.')

    @classmethod
    @abstractmethod
    def get_resource(cls, file_name) -> str:
        pass

    def reload(self, vpn_dir):
        self.vpn_dir = Path(vpn_dir)
        return self

    def get_vpn_version(self, fallback='unknown'):
        return FileHelper.read_file_by_line(self.vpn_dir.joinpath(self.CORE_VERSION_FILE)) or fallback

    def export_env(self):
        FileHelper.write_file(VpnDirectory.PROFILE_D_ENV, f'export {AppEnv.VPN_HOME_ENV}="{self.vpn_dir}"',
                              mode=0o0644)

    @staticmethod
    def remove_env():
        FileHelper.rm(VpnDirectory.PROFILE_D_ENV)

    @staticmethod
    def read_env():
        content = FileHelper.read_file_by_line(VpnDirectory.PROFILE_D_ENV)
        env = awk(next(iter(grep(content, rf'{AppEnv.VPN_HOME_ENV}.+')), None), sep='=', pos=1)
        return None if not env else env.replace('"', "")


def vpn_dir_opts_factory(app_dir: str, opt_func=VpnDirectory):
    def dir_opts(func):
        @click.option("-dd", "--vpn-dir", type=str,
                      default=lambda: os.environ.get(AppEnv.VPN_HOME_ENV, VpnDirectory.read_env() or app_dir),
                      show_default=f'"{app_dir}" or from "env.{AppEnv.VPN_HOME_ENV}"',
                      help=f'VPN installation directory')
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs[VpnDirectory.OPT_NAME] = opt_func(kwargs.pop('vpn_dir'))
            return func(*args, **kwargs)

        return wrapper

    return dir_opts


VpnOpts = TypeVar("VpnOpts", bound=VpnDirectory)
