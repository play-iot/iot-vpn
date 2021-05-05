import os
from typing import Iterator, Tuple

import click

from src.executor.vpn_cmd_executor import VpnCmdExecutor
from src.utils import logger
from src.utils.downloader import downloader_opt_factory, VPNType, DownloaderOpt, download
from src.utils.helper import TextHelper, EnvHelper, JsonHelper, FileHelper
from src.utils.opts_shared import CLI_CTX_SETTINGS, verbose_opts, dev_mode_opts, out_dir_opts_factory, OutputOpts
from src.utils.opts_vpn import vpn_server_opts, ServerOpts, vpn_dir_opts_factory, VpnDirectory


class ToolOpts(VpnDirectory):

    @classmethod
    def get_resource(cls, file_name) -> str:
        return EnvHelper.resource_finder(file_name, os.path.dirname(__file__))


vpn_auth_cli_opts = vpn_dir_opts_factory(app_dir='/app/vpnserver', opt_func=ToolOpts)


class VPNAuthExecutor(VpnCmdExecutor):

    def __init__(self, vpn_opts: ToolOpts, server_opts: ServerOpts, hub_pwd):
        super().__init__(vpn_opts)
        self.server_opts = server_opts
        self.hub_pwd = hub_pwd

    def pre_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def post_exec(self, silent=False, log_lvl=logger.DEBUG, **kwargs):
        pass

    def vpn_cmd_opt(self):
        return f'/SERVER {self.server_opts.server} /hub:{self.server_opts.hub} /password:{self.hub_pwd}'

    def _parse_entry_value(self, idx: int, row: str):
        value = TextHelper.awk(row, sep='|', pos=1)
        return self.decode_host_name(value) if idx == 2 else value

    @staticmethod
    def _parse_row(row: Iterator[Tuple], columns: dict) -> Iterator[dict]:
        return map(lambda each: {columns[idx]: TextHelper.awk(r, sep='|', pos=1) for idx, r in enumerate(each)}, row)


@click.group(name="auth", context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    VPN Auth tool that create new VPN user/group and assign policy/group user
    """
    pass


@cli.command(name="download", help="Download VPN server", hidden=True)
@downloader_opt_factory(EnvHelper.resource_finder('.', os.path.dirname(__file__)))
@dev_mode_opts(hidden=False, opt_name=DownloaderOpt.OPT_NAME)
def __download(downloader_opts: DownloaderOpt):
    download(VPNType.SERVER, downloader_opts)


@cli.command(name='command', help='Execute Ad-hoc VPN command', hidden=True)
@click.argument("command", type=str, required=True)
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@vpn_auth_cli_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def __execute(server_opts: ServerOpts, hub_password: str, vpn_opts: ToolOpts, command):
    VPNAuthExecutor(vpn_opts, server_opts, hub_password).exec_command(f'/CMD {command}', log_lvl=logger.INFO)


@cli.command(name='import', help='Import signed certification to add new VPN accounts')
@vpn_server_opts
@click.option('-pw', '--hub-password', type=str, prompt=True, hide_input=True, help='VPN Hub admin password')
@click.option('-g', '--group', type=str, help='VPN Hub account group')
@click.option('--signed-certs', 'certs_file', type=click.Path(exists=True, dir_okay=False, resolve_path=True),
              required=True, help='Path to signed certification file')
@out_dir_opts_factory("credentials")
@vpn_auth_cli_opts
@dev_mode_opts(VpnDirectory.OPT_NAME)
@verbose_opts
def __import(server_opts: ServerOpts, hub_password: str, vpn_opts: ToolOpts, group: str, certs_file: str,
             output_opts: OutputOpts):
    executor = VPNAuthExecutor(vpn_opts, server_opts, hub_password)
    data = JsonHelper.read(certs_file, strict=False)
    tmp_dir = FileHelper.tmp_dir('vpn_auth')
    command_file = FileHelper.touch(tmp_dir.joinpath('vpncmd.txt'))
    vpn_acc = {}
    for k, v in data.items():
        cert_file = tmp_dir.joinpath(f'{k}.cert')
        FileHelper.write_file(cert_file, v['cert_key'])
        commands = [f'CAAdd /{cert_file}', f'UserCreate {k} /GROUP:{group or "none"} /RealName:none /Note:none',
                    f'UserSignedSet {k} /CN:{v["fqdn"]} /SERIAL:{v["serial_number"]}']
        vpn_acc[k] = {
            'vpn_server': server_opts.host,
            'vpn_port': server_opts.port,
            'vpn_hub': server_opts.hub,
            'vpn_account': server_opts.hub,
            'vpn_auth_type': 'cert',
            'vpn_user': k,
            'vpn_cert_key': v['cert_key'],
            'vpn_private_key': v['private_key'],
        }
        FileHelper.write_file(command_file, '\n'.join(commands) + '\n', append=True)
    executor.exec_command(f'/IN:{command_file}', log_lvl=logger.INFO)
    logger.sep(logger.INFO)
    out = output_opts.make_file(f'{server_opts.hub}-{output_opts.to_file("json")}')
    logger.info(f'Export VPN accounts to {out}...')
    JsonHelper.dump(out, vpn_acc)
    logger.done()


if __name__ == '__main__':
    cli(auto_envvar_prefix='VPN')
