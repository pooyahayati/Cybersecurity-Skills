"""Private controller directories on POSIX and Windows; no shell commands."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from .common import Blocked, require


def _windows_directory(path, create):
    import ctypes as c
    from ctypes import wintypes as w

    kernel = c.WinDLL("kernel32", use_last_error=True)
    adv = c.WinDLL("advapi32", use_last_error=True)
    pointer = c.c_void_p
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.LocalFree.argtypes = [pointer]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, pointer, w.DWORD, c.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [pointer, c.POINTER(w.LPWSTR)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR, w.DWORD, c.POINTER(pointer), c.POINTER(w.DWORD)]
    adv.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD,
        c.POINTER(pointer), c.POINTER(pointer), c.POINTER(pointer),
        c.POINTER(pointer), c.POINTER(pointer)]
    adv.GetNamedSecurityInfoW.restype = w.DWORD
    adv.GetSecurityDescriptorControl.argtypes = [pointer, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
    adv.GetAclInformation.argtypes = [pointer, pointer, w.DWORD, c.c_int]
    adv.GetAce.argtypes = [pointer, w.DWORD, c.POINTER(pointer)]

    def sid_string(sid):
        value = w.LPWSTR()
        require(adv.ConvertSidToStringSidW(sid, c.byref(value)), "cannot inspect Windows identity")
        try:
            return value.value
        finally:
            kernel.LocalFree(c.cast(value, pointer))

    token = w.HANDLE()
    require(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)),
            "cannot inspect controller account")
    try:
        length = w.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, c.byref(length))
        require(0 < length.value < 65536, "invalid Windows identity size")
        buffer = c.create_string_buffer(length.value)
        require(adv.GetTokenInformation(token, 1, buffer, length, c.byref(length)),
                "cannot read controller account")
        sid = sid_string(c.cast(buffer, c.POINTER(pointer))[0])
    finally:
        kernel.CloseHandle(token)

    if create:
        class Attributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", pointer), ("inherit", w.BOOL)]

        descriptor = pointer()
        # Protect the DACL from parent inheritance before any key/data exists.
        sddl = f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"
        require(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, c.byref(descriptor), None), "cannot create private Windows ACL")
        try:
            attributes = Attributes(c.sizeof(Attributes), descriptor, False)
            kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, c.POINTER(Attributes)]
            require(kernel.CreateDirectoryW(str(path), c.byref(attributes)),
                    "cannot create private controller directory")
        finally:
            kernel.LocalFree(descriptor)

    owner, dacl, descriptor = pointer(), pointer(), pointer()
    require(adv.GetNamedSecurityInfoW(str(path), 1, 5, c.byref(owner), None,
                                    c.byref(dacl), None, c.byref(descriptor)) == 0,
            "cannot verify controller directory ACL")
    try:
        require(sid_string(owner) == sid and bool(dacl), "controller directory has wrong owner or ACL")
        control, revision = w.WORD(), w.DWORD()
        require(adv.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision))
                and control.value & 0x1000, "controller ACL must be protected")

        class AclSize(c.Structure):
            _fields_ = [("count", w.DWORD), ("used", w.DWORD), ("free", w.DWORD)]

        info = AclSize()
        require(adv.GetAclInformation(dacl, c.byref(info), c.sizeof(info), 2)
                and 1 <= info.count <= 2, "unexpected controller access entries")
        seen = set()
        for index in range(info.count):
            ace = pointer()
            require(adv.GetAce(dacl, index, c.byref(ace)), "unreadable controller access entry")
            require(c.c_ubyte.from_address(ace.value).value == 0, "unexpected controller access type")
            ace_sid = sid_string(pointer(ace.value + 8))
            mask = c.c_uint32.from_address(ace.value + 4).value
            require(ace_sid in (sid, "S-1-5-18") and mask == 0x1F01FF,
                    "controller directory grants unexpected access")
            seen.add(ace_sid)
        require(sid in seen, "controller account lacks private access")
    finally:
        kernel.LocalFree(descriptor)


def private_directory(path, create=False):
    path = Path(path).absolute()
    require(path.parent.is_dir() and path.parent.resolve() == path.parent,
            "controller parent must exist without link aliases")
    if create:
        require(not path.exists() and not path.is_symlink(), "controller directory already exists")
    else:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
                and not getattr(info, "st_file_attributes", 0) & 0x400,
                "controller directory cannot be a link")
    if os.name == "nt":
        _windows_directory(path, create)
    else:
        if create:
            path.mkdir(mode=0o700)
        info = path.stat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "controller directory must be owned by this account with mode 0700")
    return path
