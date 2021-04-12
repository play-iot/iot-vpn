import functools
import os
import re
from enum import Enum

import click
import requests

from src.executor.shell_executor import SystemHelper
from src.utils import logger
from src.utils.constants import Versions
from src.utils.helper import FileHelper
from src.utils.opts_shared import verbose_opts, DevModeDir
from src.utils.opts_vpn import VpnDirectory

BLF = '/usr/local/bin'
BF = '/usr/bin'


class VPNType(Enum):
    SERVER = 'server'
    CLIENT = 'client'
    BRIDGE = 'bridge'


class DownloaderOpt(DevModeDir):
    OPT_NAME = 'downloader_opts'

    def __init__(self, platform: str, arch: str, vpn_version: str, ghrd_version: str, output_dir: str, no_zip: bool,
                 keep_tmp: bool):
        self.platform = platform
        self.arch = arch
        self.vpn_version = vpn_version
        self.ghrd_version = ghrd_version
        self.output_dir = output_dir
        self.no_zip = no_zip
        self.keep_tmp = keep_tmp

    @property
    def tmp_dir(self):
        return os.path.join(self.output_dir, 'tmp')

    def reload(self, dev_dir):
        self.output_dir = dev_dir
        return self


def _prepare(ghrd: str):
    logger.info("Prepare download tool...")
    try:
        SystemHelper.exec_command("ghrd -v", silent=True, log_lvl=logger.DEBUG)
    except Exception as _:
        f1 = os.path.join(BLF, 'ghrd')
        f2 = os.path.join(BF, 'ghrd')
        FileHelper.remove_files([f1, f2])
        content = requests.get(Versions.GHRD_LINK.format(ghrd), allow_redirects=True).content
        FileHelper.write_binary_file(f1, content, symlink=f2)


def _download_2_unzip(tmp_dir: str, _arch: str, _version: str, _type: VPNType) -> str:
    logger.info("Start downloading...")
    regex_name = f'.*softether-vpn{_type.value}.*{_arch}.*'
    result = SystemHelper.exec_command(
        "ghrd -x -a %s -r %s -o %s %s" % (regex_name, _version, tmp_dir, Versions.VPN_REPO),
        log_lvl=logger.INFO)
    zip_file = re.findall("File: ([^\\s]*)", result, re.MULTILINE)[0]
    logger.info(f'Unzip vpn {_type.value}...')
    vpnclient = os.path.join(tmp_dir, f'vpn{_type.value}')
    FileHelper.unpack_archive(zip_file, tmp_dir)
    FileHelper.write_file(os.path.join(vpnclient, VpnDirectory.CORE_VERSION_FILE), _version)
    return vpnclient


def _compile(_folder: str, _type: VPNType):
    logger.info(f'Compiling vpn {_type.value}...')
    SystemHelper.exec_command(f'yes 1 | make -C {_folder}', shell=True, log_lvl=logger.DEBUG)
    rm_files = [os.path.join(_folder, f) for f in ['code', 'lib', '.install.sh', 'Makefile', 'Authors.txt']]
    FileHelper.remove_files(rm_files + FileHelper.find_files(_folder, 'ReadMeFirst_Important*'))
    return _folder


def download(vpn_type: VPNType, opt: DownloaderOpt):
    arch = Versions.PLATFORMS[opt.platform] if opt.platform else opt.arch
    if not arch:
        logger.error(f'Unsupported platform {opt.platform}')
    _prepare(opt.ghrd_version)
    FileHelper.remove_files(opt.tmp_dir)
    FileHelper.create_folders(opt.tmp_dir)
    out = _compile(_download_2_unzip(opt.tmp_dir, arch, opt.vpn_version, vpn_type), vpn_type)
    if not opt.no_zip:
        FileHelper.make_archive(out, opt.output_dir)
    else:
        FileHelper.copy(out, opt.output_dir, force=True)
    if not opt.keep_tmp:
        FileHelper.remove_files(opt.tmp_dir)
    logger.done()


def downloader_opt_factory(output_dir: str):
    def downloader_opts(func):
        @click.option("-p", "--platform", type=click.Choice(Versions.PLATFORMS.keys()), help="Build Platform Arch")
        @click.option("-a", "--arch", type=click.Choice(Versions.ARCHES), default="linux-x64",
                      help="Device Platform Arch")
        @click.option("-cv", "--vpn-version", type=str, default=Versions.VPN_VERSION, help="VPN Client version")
        @click.option("-gv", "--ghrd-version", type=str, default=Versions.GHRD_VERSION, help="GHRD version")
        @click.option("-o", "--output", type=str, default=output_dir, help="Output for VPN client artifact")
        @click.option("--no-zip", default=False, is_flag=True, help="No zip")
        @click.option("--keep-tmp", default=False, is_flag=True, help="Keep temp compile folder")
        @verbose_opts
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs[DownloaderOpt.OPT_NAME] = DownloaderOpt(kwargs.pop('platform'), kwargs.pop('arch'),
                                                           kwargs.pop('vpn_version'), kwargs.pop('ghrd_version'),
                                                           kwargs.pop('output'), kwargs.pop('no_zip'),
                                                           kwargs.pop('keep_tmp'))
            return func(*args, **kwargs)

        return wrapper

    return downloader_opts
