#!/usr/bin/env python
import os
import random
import sys

import click
import netifaces

import src.utils.logger as logger
from src.utils.opts_shared import CLI_CTX_SETTINGS


def random_mac(oui: list, uaa=False, multicast=False):
    mac = oui + [random.randrange(256) for _ in range(6 - len(oui))]
    if multicast:
        mac[0] |= 1  # set bit 0
    else:
        mac[0] &= ~1  # clear bit 0
    if uaa:
        mac[0] &= ~(1 << 1)  # clear bit 1
    else:
        mac[0] |= 1 << 1  # set bit 1
    return mac


def generate_random(oui: list, quantity: int, uaa=False, multicast=False):
    return (random_mac(oui, uaa, multicast) for _ in range(quantity))


def increase(mac: list, idx: int):
    f0 = mac[idx] + 1
    mac[idx] = f0
    if f0 <= 255:
        return mac
    mac[idx] = 0
    up = idx - 1
    return mac if len(mac) + 1 + up == 0 else increase(mac, up)


def generate_sequence(oui: list, seq: list, quantity: int):
    length = len(oui) + len(seq)
    if length < 6:
        logger.error(f'Combination between OUI and next MAC sequence is invalid [{oui + seq}]')
        sys.exit(10)
    mac = oui + (seq if length == 6 else seq[len(oui):6])
    return (increase(mac, -1) for _ in range(quantity))


def out(data, overwrite=False, output='-'):
    if output == '-':
        for d in data:
            logger.info(d)
    else:
        with open(output, 'w+' if overwrite else 'a+') as f:
            for d in data:
                f.write(d + '\n')
        logger.success(f'Output: {output}')


@click.group(context_settings=CLI_CTX_SETTINGS, help='MAC generator')
def cli():
    pass


@cli.command(name="generate", help="Generate MAC")
@click.argument("output", type=str, default='-')
@click.option("-n", "--quantity", type=int, default='1', help='The quantity that you need')
@click.option("-o", "--overwrite", default=False, flag_value=True, help='Append to file')
@click.option("--asix1", type=str, default=None, flag_value='F8:E4:3B', help='First ASIX: "F8:E4:3B"')
@click.option("--asix2", type=str, default=None, flag_value='00:0E:C6', help='Second ASIX: "00:0E:C6"')
@click.option("--oui", type=str, help='Enforces a specific an organization unique identifier (like F8:E4:3B for ASIX)')
@click.option("--seq", type=str, default=None, help='From last sequence. Use with --asix1/--asix2/--oui')
@click.option("--rand", type=str, default=False, flag_value=True, help='Random MAC instead of sequence')
@click.option("--uaa", type=bool, default=False, flag_value=True,
              help='Generates a universally administered address (instead of LAA otherwise)')
@click.option("--multicast", type=bool, default=False, flag_value=True,
              help='Generates a multicast MAC (instead of unicast otherwise)')
@click.option("--byte-fmt", type=str, default='%02x', help='The byte format. Set to %02X for uppercase hex formatting.')
@click.option("--sep", type=str, default=':', help='The byte separator character')
def __generate(quantity, seq, rand, output, overwrite, asix1, asix2, oui, uaa, multicast, byte_fmt, sep):
    check = len(list(filter(lambda x: x, [asix1, asix2, oui])))
    if check > 1:
        logger.error('Option [asix1, asix2, oui] is mutually exclusive with each another')
        sys.exit(2)
    if seq and rand:
        logger.error('Option [seq, rand] is mutually exclusive with each another')
        sys.exit(2)
    oui = asix1 or asix2 or oui
    oui = [int(c, base=16) for c in oui.split(sep)] if type(oui) == str else (oui or [])
    seq = [0 for _ in range(5 - len(oui))] + [-1] if seq is None else [int(c, base=16) for c in seq.split(sep)]
    gen = generate_random(oui, quantity, uaa, multicast) if rand else generate_sequence(oui, seq, quantity)
    out((sep.join(byte_fmt % b for b in each) for each in gen), overwrite, output)


@cli.command(name='last', help='Get last MAC sequence in given file')
@click.argument('file', type=click.Path(exists=True))
def __last(file):
    with open(file, 'rb') as f:
        f.seek(-2, os.SEEK_END)
        while f.read(1) != b'\n':
            f.seek(-2, os.SEEK_CUR)
        last_line = f.readline().decode()
        logger.info(last_line.strip())


@cli.command(name='validate', help='Validate MAC duplication in given file')
@click.argument('file', type=click.File(mode='r', encoding='utf-8'))
def __validate(file):
    keys, n, d = {}, 0, 0
    for row in file:
        n += 1
        keys[row] = keys[row] + [n] if row in keys else [n]
    for k, v in keys.items():
        if len(v) > 1:
            logger.warn(f'Duplicated key: {k.strip()} in lines {v}')
            d += 1
    if d == 0:
        logger.success('No duplication')
        sys.exit(0)
    logger.error(f'Duplicated {d} keys')
    sys.exit(20)


@cli.command(name='copy', help='Copy MAC with override OUI')
@click.argument('nic', type=str, default='eth0')
@click.option('--asix1', type=str, default=None, flag_value='F8:E4:3B', help='First ASIX: "F8:E4:3B"')
@click.option('--asix2', type=str, default=None, flag_value='00:0E:C6', help='Second ASIX: "00:0E:C6"')
@click.option('--oui', type=str, help='Enforces a specific an organization unique identifier (like F8:E4:3B for ASIX)')
@click.option("--byte-fmt", type=str, default='%02x', show_default=True,
              help='The byte format. Set to %02X for uppercase hex formatting.')
@click.option("--sep", type=str, default=':', help='The byte separator character')
def __copy(nic, asix1, asix2, oui, byte_fmt, sep):
    check = len(list(filter(lambda x: x, [asix1, asix2, oui])))
    if check > 1:
        logger.error('Option [asix1, asix2, oui] is mutually exclusive with each another')
        sys.exit(2)
    if check == 0:
        logger.error('Provide at least one option [asix1, asix2, oui]')
        sys.exit(2)
    try:
        nic_mac = netifaces.ifaddresses(nic)[netifaces.AF_LINK][0]['addr']
    except:
        logger.error(f'Not found NIC {nic} or MAC address of NIC {nic}')
        sys.exit(10)
    in_oui = asix1 or asix2 or oui
    oui = [int(c, base=16) for c in in_oui.split(sep)] if type(in_oui) == str else (in_oui or [])
    mac = [int(c, base=16) for c in nic_mac.split(':')] if type(nic_mac) == str else (nic_mac or [])
    mac = oui + mac[len(oui):6]
    if len(mac) != 6:
        logger.error(f'Combination between OUI and MAC is invalid [{in_oui},{nic_mac}]')
        sys.exit(10)
    logger.success(sep.join(byte_fmt % b for b in mac))


if __name__ == "__main__":
    cli()
