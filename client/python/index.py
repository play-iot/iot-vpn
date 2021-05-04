#!/usr/bin/python3

import os

import click
import sys

import src.utils.logger as logger
from src.utils.opts_shared import CLI_CTX_SETTINGS

SOURCE = 'src'
SOURCE_FOLDER = os.path.join(os.path.dirname(__file__), SOURCE)
CMD_FOLDERS = {os.path.abspath(os.path.join(SOURCE_FOLDER, k)): k for k in ['client', 'command', 'ddns', 'auth']}


def to_module(args: list):
    args.insert(0, SOURCE)
    return '.'.join(args)


class DynamicCLI(click.MultiCommand):
    commands = {}

    def __init__(self, **kwargs):
        super().__init__(no_args_is_help=True, **kwargs)
        for folder in CMD_FOLDERS.keys():
            for filename in os.listdir(folder):
                if filename.endswith('.py') and filename.startswith('cmd_'):
                    self.commands[filename[4:-3]] = CMD_FOLDERS[folder]

    def list_commands(self, ctx):
        return sorted(self.commands.keys())

    def get_command(self, ctx, cmd_name):
        name = cmd_name.encode('ascii', 'replace') if sys.version_info[0] == 2 else cmd_name
        try:
            module = self.commands.get(name)
            if module is None:
                logger.error(f'Unsupported command "{name}"')
                click.echo(click.get_current_context().get_help())
                sys.exit(10)
            return __import__(to_module([module, 'cmd_' + name]), None, None, ['cli']).cli
        except ImportError as err:
            logger.error("Load command failed {}::{}".format(name, str(err)))
            sys.exit(10)


@click.command(cls=DynamicCLI, context_settings=CLI_CTX_SETTINGS)
def cli():
    """VPN CLI tool"""
    pass


if __name__ == '__main__':
    cli(auto_envvar_prefix='VPN')
