import functools
import os

import click

from src.utils.helper import FileHelper
from src.utils.opts_shared import DevModeDir


class AuthOpts(object):
    def __init__(self, auth_type: str, user: str):
        self.auth_type = auth_type
        if not user:
            raise click.BadParameter("Missing user")
        self.user = user

    def setup(self, account: str):
        raise NotImplementedError("Not yet supported")


class BasicAuthOpts(AuthOpts):

    def __init__(self, auth_type: str, user: str, password: str):
        super().__init__(auth_type, user)
        if not password:
            raise click.BadParameter("Missing password")
        self.password = password

    def setup(self, account: str):
        _type = "standard" if self.auth_type == "password" else "radius"
        return "AccountPasswordSet", "%s /PASSWORD:%s /TYPE:%s" % (account, self.password, _type)


class CertAuthOpts(AuthOpts):

    def __init__(self, auth_type: str, user: str, cert_key: str, private_key: str):
        super().__init__(auth_type, user)
        if not cert_key or not private_key:
            raise click.BadParameter("Missing Cert key or Private key")
        self.cert_key = cert_key
        self.private_key = private_key

    def setup(self, account: str):
        return "AccountCertSet", "%s /LOADCERT:%s /LOADKEY:%s" % (account, self.cert_key, self.private_key)


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
    @click.option("-ct", "--auth-type", type=click.Choice(["password", "cert", "radius"]), default="password",
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
        if auth_type in ["password", "radius"]:
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

    def __init__(self, app_dir: str):
        self.vpn_dir = app_dir

    @staticmethod
    def vpn_cmd(vpn_dir: str):
        return os.path.join(vpn_dir, 'vpncmd')

    @property
    def vpncmd(self):
        return VpnDirectory.vpn_cmd(self.vpn_dir)

    @property
    def runtime_dir(self):
        return os.path.join(self.vpn_dir, self.RUNTIME_FOLDER)

    def reload(self, vpn_dir):
        self.vpn_dir = vpn_dir
        return self

    def get_vpn_version(self, fallback='unknown'):
        return FileHelper.read_file_by_line(os.path.join(self.vpn_dir, self.CORE_VERSION_FILE)) or fallback


def vpn_dir_opts_factory(app_dir: str, opt_func=VpnDirectory):
    def dir_opts(func):
        @click.option("-dd", "--vpn-dir", type=str, default=app_dir, help="VPN installation directory")
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs[VpnDirectory.OPT_NAME] = opt_func(kwargs.pop('vpn_dir'))
            return func(*args, **kwargs)

        return wrapper

    return dir_opts
