from src.utils import logger
from src.utils.constants import Versions
from src.utils.helper import FileHelper, JsonHelper
from src.utils.opts_vpn import VpnOpts


def show(vpn_opts: VpnOpts, version: str, sha: str, show_brand=False, show_license=False, is_json=False):
    if show_brand and not is_json:
        brand = FileHelper.read_file_by_line(vpn_opts.get_resource('banner.txt'))
        brand and print(brand)

    ver = {
        "vpn_version": vpn_opts.get_vpn_version(Versions.VPN_VERSION),
        "cli_version": version,
        "hash_version": sha
    }
    if is_json:
        print(JsonHelper.to_json(ver))
    else:
        logger.info(f'VPN version : {ver.get("vpn_version")}')
        logger.info(f'CLI version : {ver.get("cli_version")}')
        logger.info(f'Hash version: {ver.get("hash_version")}')
        logger.sep(logger.INFO, 55)
        if show_license:
            print(FileHelper.read_file_by_line(vpn_opts.get_resource('LICENSE_BUNDLE.md'), fallback_if_not_exists=''))
