from src.utils import logger
from src.utils.constants import Versions
from src.utils.helper import FileHelper
from src.utils.opts_vpn import VpnOpts


def show(vpn_opts: VpnOpts, version: str, sha: str, show_brand=False, show_license=False):
    brand = FileHelper.read_file_by_line(vpn_opts.get_resource('banner.txt'))
    if brand and show_brand:
        print(brand)
    logger.info(f'VPN version : {vpn_opts.get_vpn_version(Versions.VPN_VERSION)}')
    logger.info(f'CLI version : {version}')
    logger.info(f'Hash version: {sha}')
    logger.sep(logger.INFO, 55)
    if show_license:
        print(FileHelper.read_file_by_line(vpn_opts.get_resource('LICENSE_BUNDLE.md'), fallback_if_not_exists=''))
