"""Bounded parsing, portable paths and content identities."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from datetime import datetime, timezone


class Blocked(ValueError):
    """A safe, non-sensitive explanation for a fail-closed decision."""


def require(value, message):
    if not value:
        raise Blocked(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse(data, limit=4 * 1024 * 1024):
    require(isinstance(data, (str, bytes)) and len(data) <= limit, "JSON input exceeds its limit")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise Blocked("non-finite JSON value")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("malformed JSON input") from exc


def fields(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value)
            and set(value) <= set(required) | set(optional), "missing or unknown contract fields")


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, "integer outside allowed bounds")
    return value


def number(value, low, high):
    require(type(value) in (int, float) and math.isfinite(value) and low <= value <= high,
            "number outside allowed bounds")
    return value


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value),
            "invalid component identifier")
    return value


def text(value, limit=4096):
    require(isinstance(value, str) and 0 < len(value) <= limit and "\x00" not in value,
            "invalid text field")
    return value


def relpath(value):
    text(value, 512)
    path = PurePosixPath(value)
    require(bool(path.parts) and not path.is_absolute() and path.as_posix() == value
            and all(part not in ("", ".", "..") for part in path.parts)
            and not any(c in value for c in ('\\', ':', '\x00', '\r', '\n', '*', '?', '"', '<', '>', '|')),
            "unsafe relative path")
    for part in path.parts:
        require(not part.endswith((".", " ")) and not re.fullmatch(
            r"(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", part),
            "nonportable relative path")
    return value


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "links and special files are not permitted")
    return info


def read_file(root, relative, limit=8 * 1024 * 1024):
    relpath(relative)
    root = Path(root).absolute()
    require(root == root.resolve(strict=True), "input root is not canonical or contains a link")
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        info = current.lstat()
        require(not current.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                "links and reparse points are not permitted")
    require(current.resolve(strict=True).is_relative_to(root), "path escapes allowed root")
    regular(current)
    if os.name == "nt":
        value = _windows_read(root, relative, limit)
    else:
        # Keep traversal anchored to descriptors; never follow a swapped link.
        descriptor = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in root.parts[1:] + PurePosixPath(relative).parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            fd = os.open(PurePosixPath(relative).name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                        "input must be a regular file without hard links")
                require(before.st_size <= limit, "file exceeds its size limit")
                value = stream.read(before.st_size + 1)
                after = os.fstat(stream.fileno())
                require(len(value) == before.st_size
                        and (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
                        "input changed during capture")
        finally:
            os.close(descriptor)
    require(len(value) <= limit, "file exceeds its size limit")
    return value


def _windows_read(root, relative, limit):
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt

    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p,
                                   w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]

    class Info(c.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                    ("accessed", w.FILETIME), ("written", w.FILETIME),
                    ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
                    ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]

    kernel.GetFileInformationByHandle.argtypes = [w.HANDLE, c.POINTER(Info)]

    def open_handle(path, directory):
        handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3,
            0x00200000 | (0x02000000 if directory else 0), None)
        require(handle != w.HANDLE(-1).value, "cannot capture input without concurrent writers")
        return handle

    def final_path(handle):
        buffer = c.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        require(0 < length < len(buffer), "cannot resolve opened input")
        return buffer.value.rstrip("\\").casefold()

    root_handle = open_handle(root, True)
    file_handle = None
    try:
        root_actual = final_path(root_handle)
        displayed = root_actual[8:] if root_actual.startswith("\\\\?\\unc\\") else root_actual[4:]
        if root_actual.startswith("\\\\?\\unc\\"):
            displayed = "\\\\" + displayed
        require(displayed == str(root).rstrip("\\").casefold(), "opened input root changed identity")
        root_info = Info()
        require(kernel.GetFileInformationByHandle(root_handle, c.byref(root_info))
                and root_info.attributes & 0x10 and not root_info.attributes & 0x400,
                "input root is a reparse point or not a directory")
        file_handle = open_handle(root / relative, False)
        expected = root_actual + "\\" + relative.replace("/", "\\").casefold()
        require(final_path(file_handle) == expected, "opened input escapes its exact allowed path")
        info = Info()
        require(kernel.GetFileInformationByHandle(file_handle, c.byref(info))
                and not info.attributes & (0x400 | 0x10) and info.links == 1,
                "input must be a regular file without reparse points or hard links")
        size = (info.size_high << 32) | info.size_low
        require(size <= limit, "file exceeds its size limit")
        fd = msvcrt.open_osfhandle(file_handle, os.O_RDONLY | os.O_BINARY)
        file_handle = None  # The Python file object now owns this handle.
        with os.fdopen(fd, "rb") as stream:
            value = stream.read(size + 1)
            require(len(value) == size, "input changed during capture")
            return value
    finally:
        if file_handle is not None:
            kernel.CloseHandle(file_handle)
        kernel.CloseHandle(root_handle)


def timestamp(value):
    try:
        result = datetime.fromisoformat(text(value).replace("Z", "+00:00"))
        require(result.tzinfo is not None, "timestamp must include a timezone")
        return result.timestamp()
    except (ValueError, OverflowError) as exc:
        raise Blocked("invalid timestamp") from exc


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def portable_tree(root, limit=512 * 1024 * 1024):
    """Hash a stable owned tree; refuse link aliases and extra special files."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "object directory is unavailable")
    entries = {}
    total = 0
    aliases = set()
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            item = Path(base) / name
            relative = item.relative_to(root).as_posix()
            relpath(relative)
            info = item.lstat()
            require(not item.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "object contains a link or reparse point")
            require(relative.casefold() not in aliases, "case-colliding object paths")
            aliases.add(relative.casefold())
            if name in files:
                regular(item)
                total += info.st_size
                require(total <= limit and len(entries) < 4096, "object exceeds its limits")
                entries[relative] = sha256(read_file(root, relative, limit))
    return dict(sorted(entries.items()))
