import functools
import os
import sys
from abc import ABC, abstractmethod
from functools import partial

import click

from src.utils import logger
from src.utils.helper import EnvHelper

CLI_CTX_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=120)
click.option = partial(click.option, show_default=True)


def permission(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if os.getuid() != 0:
            logger.error("You need root privileges to run this script")
            sys.exit(100)
        return func(*args, **kwargs)

    return wrapper


def verbose_opts(func):
    @click.option("-v", "--verbose", count=True, default=0, help="Enables verbose mode", show_default=False)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.config_logger(kwargs.pop("verbose", 0))
        return func(*args, **kwargs)

    return wrapper


class OutputOpts(object):
    def __init__(self, output_dir: str, output_file: str):
        self.dir = output_dir
        self.file = output_file
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

    def to_file(self, ext: str = ""):
        return os.path.join(self.dir, self.file + "." + ext)

    def make_file(self, another: str):
        return os.path.join(self.dir, another)


def out_dir_opts_factory(file_name):
    def dir_opts(func):
        @click.option("-of", "--output-file", type=str, default=file_name, help="Output file")
        @click.option("-od", "--output-dir", type=click.Path(file_okay=False, writable=True),
                      default=os.path.join(os.getcwd(), "output"), help="Output directory")
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs["output_opts"] = OutputOpts(kwargs.pop("output_dir", None), kwargs.pop("output_file", None))
            return func(*args, **kwargs)

        return wrapper

    return dir_opts


class UnixServiceOpts:

    def __init__(self, service_dir, service_name):
        self.service_dir = service_dir
        self.service_name = service_name


def unix_service_opts(service_name: str):
    def _inner(func):
        @click.option('-dn', '--service-name', type=str, default=service_name, help='VPN Service name')
        @click.option('-ds', '--service-dir', type=str, help='Linux Service directory')
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs['svc_opts'] = UnixServiceOpts(kwargs.pop('service_dir'), kwargs.pop('service_name'))
            return func(*args, **kwargs)

        return wrapper

    return _inner


class DevModeDir(ABC):
    @abstractmethod
    def reload(self, dev_dir):
        pass


def dev_mode_opts(opt_name: str, hidden=True):
    def _inner_opts(func):
        @click.option("--dev", type=bool, flag_value=True, help='Developer mode. Unpack VPN zip to debug folder',
                      hidden=hidden)
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            opts = kwargs[opt_name]
            dev = kwargs.pop('dev')
            if dev and not EnvHelper.is_binary_mode():
                dev_dir = EnvHelper.get_dev_dir()
                logger.warn(f'[DEV MODE] Reload vpn_dir to {dev_dir}')
                kwargs[opt_name] = opts.reload(dev_dir)
            return func(*args, **kwargs)

        return wrapper

    return _inner_opts
