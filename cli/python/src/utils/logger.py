from logging import ERROR, WARN, INFO, DEBUG, addLevelName, getLevelName

import click

OKEY = 60
TRACE = 5
addLevelName(OKEY, 'OKEY')
addLevelName(WARN, 'WARN')
addLevelName(TRACE, 'TRACE')
LEVEL = INFO


def error(message, *args):
    __log(ERROR, __format(message, *args), 'red')


def warn(message, *args):
    __log(WARN, __format(message, *args), 'yellow')


def info(message, *args):
    __log(INFO, __format(message, *args), 'blue')


def debug(message, *args):
    __log(DEBUG, __format(message, *args), 'bright_yellow')


def success(message, *args):
    __log(OKEY, __format(message, *args), 'green')


def trace(message, *args):
    __log(TRACE, __format(message, *args), 'magenta')


def sep(level, quantity=85):
    if level >= LEVEL:
        click.echo('-' * quantity)


def down_lvl(level):
    return level - 1


def decrease(level, message, *args):
    """
    Log with decrease log level to lower
    """
    log(down_lvl(level), message, *args)


def log(level, message, *args):
    def bw(lvl, one, two):
        return one <= lvl < two

    if level >= OKEY:
        success(message, *args)
    elif bw(level, ERROR, OKEY):
        error(message, *args)
    elif bw(level, WARN, ERROR):
        warn(message, *args)
    elif bw(level, INFO, WARN):
        info(message, *args)
    elif bw(level, DEBUG, INFO):
        debug(message, *args)
    else:
        trace(message, *args)


def done():
    success('DONE')


def __log(level, message, color):
    if level < LEVEL or message is None:
        return
    click.echo(click.style('{:<5}: '.format(getLevelName(level)), fg=color) + message)


def __format(message, *args):
    return message % args if message else None


def config_logger(verbose: int = 0):
    global LEVEL
    LEVEL = TRACE if verbose > 1 else DEBUG if verbose == 1 else INFO
