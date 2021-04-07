class ErrorCode:
    NOT_FOUND_VPN_BINARY = 100
    INVALID_ARGUMENT = 2
    VPN_SERVICE_IS_NOT_WORKING = 10
    FILE_NOT_FOUND = 7


class Versions:
    VPN_VERSION = 'v4.29-9680-rtm'  # Default version
    VPN_REPO = 'SoftEtherVPN/SoftEtherVPN_Stable'

    GHRD_VERSION = 'v1.1.2'
    GHRD_LINK = 'https://github.com/zero88/gh-release-downloader/releases/download/{}/ghrd'

    PLATFORMS = {'linux/arm/32-eabi': 'arm_eabi-32', 'linux/arm/v7': 'arm-32', 'linux/arm/v6': 'arm-32',
                 'linux/mips': 'mips_el-32', 'linux/386': 'linux-x86', 'linux/amd64': 'linux-x64',
                 'linux/arm64': None}
    ARCHES = [a for a in PLATFORMS.values() if a]