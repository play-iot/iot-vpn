import base64
import fileinput
import glob
import json
import os
import platform
import re
import shutil
import stat
import sys
import time
from distutils.dir_util import copy_tree
from itertools import islice
from pathlib import Path
from typing import Sequence, Union, Any, Optional, Iterator, TextIO, Callable

import src.utils.logger as logger
from src.utils.constants import ErrorCode

DEFAULT_ENCODING = "UTF-8"
PY_VERSION = platform.sys.version_info


def get_base_path(base=None):
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        return sys._MEIPASS
    except Exception as _:
        return base or os.getcwd()


def is_binary_mode():
    try:
        sys._MEIPASS
        return True
    except:
        return False


def tweak_os_env():
    env = dict(os.environ)
    lp_key = 'LD_LIBRARY_PATH'  # for GNU/Linux and *BSD.
    lp_orig = env.get(lp_key + '_ORIG')
    if lp_orig is not None:
        env[lp_key] = lp_orig  # restore the original, unmodified value
    else:
        env.pop(lp_key, None)
    return env


def resource_finder(relative_path, base=None, resource_dir="resources"):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    return os.path.join(get_base_path(base), resource_dir, relative_path)


def get_dev_dir():
    return Path(os.path.dirname(__file__)).parent.joinpath('debug')


def build_executable_command():
    executable = sys.executable
    if getattr(sys, 'frozen', False):
        return str(Path(executable).parent.absolute()), executable
    params = sys.argv[0:2] if sys.argv[0] == 'index.py' else sys.argv[0]
    # params.insert(0, os.path.join(Path(sys.argv[0]).relative_to(working_dir)))
    return os.getcwd(), f'{executable} {" ".join(params)}'


class FileHelper(object):

    @staticmethod
    def create_folders(folders: Union[str, Path, list], mode=0o0755):
        folders = folders if isinstance(folders, list) else [folders]
        [Path(f).mkdir(parents=True, exist_ok=True, mode=mode) for f in folders]

    @staticmethod
    def create_file(path, mode=0o0664):
        with open(path, 'w') as _:
            os.chmod(path, mode)

    @staticmethod
    def write_file(path, content, mode=0o0664, log_lvl=logger.DEBUG):
        logger.log(log_lvl, "Dump to file: " + path)
        with open(path, 'w+') as fp:
            fp.write(content)
            os.chmod(path, mode)

    @staticmethod
    def write_binary_file(path, content, mode=0o0755, symlink=None):
        with open(path, 'wb') as f:
            f.write(content)
            os.chmod(path, mode)
            if symlink:
                os.symlink(path, symlink)

    @staticmethod
    def json_to_file(path, content, log_lvl=logger.DEBUG):
        logger.log(log_lvl, "Dump json to file: " + path)
        with open(path, 'w+') as fp:
            json.dump(content, fp, indent=2)

    @staticmethod
    def remove_files(files: Union[str, list], force=True, recursive=True):
        def rm_dir(_f, _recursive):
            if not _recursive:
                raise RuntimeError(f'{_f} is folder, need to enable recursive to cleanup')
            shutil.rmtree(_f, ignore_errors=True)

        files = files if isinstance(files, list) else [files]
        [os.remove(f) if os.path.isfile(f) else rm_dir(f, recursive) for f in files if os.path.exists(f) and force]

    @staticmethod
    def chmod(paths: Union[str, Sequence[str]], mode):
        paths = [paths] if isinstance(paths, str) else paths
        [os.chmod(p, mode=mode) for p in paths if os.path.exists(p)]

    @staticmethod
    def is_dir(path: Union[str, Path]) -> bool:
        return Path(path).is_dir()

    @staticmethod
    def is_symlink(path: Union[str, Path]) -> bool:
        return Path(path).is_symlink()

    @staticmethod
    def get_target_link(path: Union[str, Path]):
        p = Path(path)
        if not FileHelper.is_symlink(p):
            return None
        return p.readlink()

    @staticmethod
    def create_symlink(path: Union[str, Path], link: Union[str, Path], force=True):
        p = Path(path)
        lk = Path(link)
        if not p.exists():
            raise RuntimeError('Given file is not existed')
        if lk.exists():
            if FileHelper.is_dir(lk):
                raise RuntimeError('Given target link is directory')
            if not force:
                raise RuntimeError('Given target is existed')
            os.remove(lk)
        lk.symlink_to(p)

    @staticmethod
    def is_file_readable(path: Union[str, Path]) -> bool:
        p = Path(path)
        return p.is_file() and FileHelper.stat(os.lstat(p)[stat.ST_MODE], [stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH])

    @staticmethod
    def is_file_writable(path: Union[str, Path]) -> bool:
        p = Path(path)
        return p.is_file() and FileHelper.stat(os.lstat(p)[stat.ST_MODE], [stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH])

    @staticmethod
    def is_executable(path: Union[str, Path]) -> bool:
        p = Path(path)
        return p.is_file() and FileHelper.stat(os.lstat(p)[stat.ST_MODE], [stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH])

    @staticmethod
    def stat(mode, checks: list) -> bool:
        return True if next(filter(lambda x: mode & x, checks), None) else False

    @staticmethod
    def read_file_by_line(path: Union[str, Path], line=-1, fallback_if_not_exists=None):
        if FileHelper.is_file_readable(path):
            count = 0
            with open(path, 'r') as fp:
                if line == -1:
                    return fp.read().replace('\n', '')
                for line in fp:
                    count += 1
                    if count == line:
                        return fp.readline().strip()
                return fallback_if_not_exists
        return fallback_if_not_exists

    @staticmethod
    def find_files(_dir: str, glob_path: str) -> list:
        return glob.glob(os.path.join(_dir, glob_path))

    @staticmethod
    def replace_in_file(filename: str, replacements: dict, backup='.bak', regex=False) -> bool:
        has_replaced = False
        with fileinput.FileInput(filename, inplace=True, backup=backup) as file:
            for line in file:
                for k, v in replacements.items():
                    if not regex or re.match(k, line):
                        old = line
                        line = line.replace(k, v) if not regex else re.sub(k, v, line)
                        has_replaced = has_replaced or old == line
                print(line, end='')
        return has_replaced

    @staticmethod
    def unpack_archive(file: str, dest: str):
        shutil.unpack_archive(file, dest)

    @staticmethod
    def make_archive(folder: Union[str, Path], into: str, name: str = None, _format='zip') -> str:
        to = Path(folder)
        if not FileHelper.is_dir(to):
            raise RuntimeError('Archive folder is not existed')
        name = name or to.name
        into = os.path.join(into, name)
        return shutil.make_archive(into, root_dir=to, base_dir='.', format=_format, logger=logger)

    @staticmethod
    def copy(file_or_folder: Union[str, Path], dest: Union[str, Path]):
        p = Path(file_or_folder)
        t = Path(dest)
        if not p.exists():
            raise RuntimeError(f'Given file {file_or_folder} is not existed')
        if FileHelper.is_dir(t):
            FileHelper.create_folders(t)
        else:
            if t.exists():
                raise RuntimeError(f'Destination {dest} is existed')
            FileHelper.create_folders(t.parent)
        if p.is_dir():
            copy_tree(str(p.absolute()), str(t.absolute()))
        else:
            shutil.copy(p, t)

    @staticmethod
    def copy_advanced(src: Union[str, Path], dest: Union[str, Path], force=False) -> str:
        """
        Advanced copy given path with metadata and symlink to destination
        :param src: given path
        :param dest: given destination
        :param force: force flag to decide removing dest if exists
        :return: the file destination
        """
        p = Path(src)
        t = Path(dest)
        if p.is_dir():
            raise RuntimeError('Unsupported advance copy directory')
        if t.is_dir():
            raise RuntimeError(f'Destination {dest} is folder')
        if t.exists():
            if not force:
                raise RuntimeError(f'Destination {dest} is existed')
            os.remove(t)
        return shutil.copy2(p, t, follow_symlinks=True)

    @staticmethod
    def backup(src: Union[str, Path], dest: Union[str, Path] = None, remove=True, force=True) -> str:
        """
        Backup
        :param src: given path
        :param dest: given destination or backup to same given source with suffix '.bak'
        :param remove: remove flag to decide removing source after backup
        :param force: force flag to decide removing dest if exists
        :return: the file destination
        """
        p = Path(src)
        t = Path(dest) if dest else p.parent.joinpath(p.name + '.bak')
        o = FileHelper.copy_advanced(p, t, force)
        if remove:
            os.remove(p)
        return o


def check_supported_python_version():
    is_unsupported = True if PY_VERSION.major == 2 else PY_VERSION.minor < 5
    if is_unsupported:
        raise NotImplementedError("Not support Python version less than 3.5")


def is_py3_5():
    return PY_VERSION.major == 3 and PY_VERSION.minor == 5


def encode_base64(value: Union[Any, bytes], url_safe=False, without_padding=False) -> str:
    if not isinstance(value, bytes):
        value = str(value).encode(DEFAULT_ENCODING)
    v = base64.urlsafe_b64encode(value) if url_safe else base64.b64encode(value)
    v = v.decode(DEFAULT_ENCODING)
    return v.rstrip("=") if without_padding else v


def decode_base64(value: str, url_safe=False, without_padding=False, lenient=False) -> str:
    v = value + ("=" * (4 - (len(value) % 4))) if without_padding else value
    try:
        v = base64.urlsafe_b64decode(v) if url_safe else base64.b64decode(v)
        return v.decode(DEFAULT_ENCODING)
    except (TypeError, ValueError, UnicodeError) as err:
        if lenient:
            logger.debug(f'Failed when decoding base64. Value[{value}]. Error[{err}]')
            return value
        raise


def grep(value: str, pattern: str) -> list:
    if not value:
        return []
    return re.findall(pattern, value, flags=re.M)


def awk(value: str, sep=' ', pos=-1) -> Optional[Union[str, list]]:
    if not value:
        return None
    if not sep:
        return value
    v = value.split(sep)
    if pos == -1:
        return v
    if pos < len(v):
        return v[pos]
    return None


def tail(file: str, prev=1, _buffer=1024, follow=True) -> Iterator[str]:
    def _last(_f: TextIO, _l: int):
        while True:
            try:
                _f.seek(-1 * _buffer, os.SEEK_END)
            except IOError:
                _f.seek(0)
            found = _f.readlines()
            if len(found) >= _l or _f.tell() == 0:
                return found[-_l:], _f.tell()

    if not os.path.exists(file):
        yield f'File {file} is not existed'
        sys.exit(ErrorCode.FILE_NOT_FOUND)
    with open(file, 'r') as fp:
        _lines, _pos = _last(fp, prev)
    yield from _lines
    if not follow:
        return
    with open(file, 'r') as fp:
        interval = 0.2
        fp.seek(0, os.SEEK_END)
        while True:
            rd = fp.read()
            cur = fp.tell()
            if not rd or cur == _pos:
                time.sleep(interval)
                fp.seek(_pos - cur, os.SEEK_SET)
            else:
                _pos = cur
                yield rd


def tree(dir_path: Union[str, Path], level: int = -1, limit_to_directories: bool = False,
         length_limit: int = 1000, printer: Callable[[bool, str], None] = None):
    space = '    '
    branch = '│   '
    tee = '├── '
    last = '└── '
    dir_path = Path(dir_path)
    files = 0
    directories = 0

    def inner(_dir_path: Path, prefix: str = '', _level=-1):
        nonlocal files, directories
        if not _level:
            return
        if limit_to_directories:
            contents = [d for d in _dir_path.iterdir() if d.is_dir()]
        else:
            contents = list(_dir_path.iterdir())
        pointers = [tee] * (len(contents) - 1) + [last]
        for pointer, path in zip(pointers, contents):
            if path.is_dir():
                yield prefix + pointer + path.name
                directories += 1
                extension = branch if pointer == tee else space
                yield from inner(path, prefix=prefix + extension, _level=_level - 1)
            elif not limit_to_directories:
                yield prefix + pointer + path.name
                files += 1

    if printer:
        printer(True, dir_path.name)
    print(dir_path.name)
    iterator = inner(dir_path, _level=level)
    for line in islice(iterator, length_limit):
        print(line)
    if next(iterator, None):
        print(f'... length_limit, {length_limit}, reached, counted:')
    print(f'\n{directories} directories' + (f', {files} files' if files else ''))
