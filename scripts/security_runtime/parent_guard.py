"""Kernel-enforced lifetime binding for a network worker and its controller."""

import ctypes as c
import os
import sys

from .common import integer,require


def windows_api():
    from ctypes import wintypes as w
    class Basic(c.Structure):
        _fields_=[('process_time',c.c_longlong),('job_time',c.c_longlong),('flags',w.DWORD),
            ('minimum',c.c_size_t),('maximum',c.c_size_t),('active',w.DWORD),('affinity',c.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
    class IO(c.Structure):
        _fields_=[(name,c.c_ulonglong) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    class Extended(c.Structure):
        _fields_=[('basic',Basic),('io',IO),('process_memory',c.c_size_t),('job_memory',c.c_size_t),('peak_process',c.c_size_t),('peak_job',c.c_size_t)]
    kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[c.c_void_p,w.LPCWSTR];kernel.CreateJobObjectW.restype=w.HANDLE
    kernel.SetInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD]
    kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
    kernel.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p]
    kernel.CloseHandle.argtypes=[w.HANDLE]
    return kernel,Extended


def attach_windows(process):
    if os.name!='nt':return None
    kernel,Extended=windows_api()
    handle=kernel.CreateJobObjectW(None,None)
    require(handle,'controller lifetime job unavailable')
    try:
        limits=Extended();limits.basic.flags=0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        require(kernel.SetInformationJobObject(handle,9,c.byref(limits),c.sizeof(limits)),'controller lifetime limit unavailable')
        require(kernel.AssignProcessToJobObject(handle,int(process._handle)),'worker cannot be bound to controller lifetime')
        return (kernel,handle)
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def close_windows(binding):
    if binding:binding[0].CloseHandle(binding[1])


def bind_worker(expected_parent):
    integer(expected_parent,1,2**31-1)
    require(os.getppid()==expected_parent,'controller disappeared before worker admission')
    if sys.platform.startswith('linux'):
        libc=c.CDLL(None,use_errno=True)
        require(libc.prctl(1,9,0,0,0)==0,'parent-death signal unavailable')
        require(os.getppid()==expected_parent,'controller disappeared during worker admission')
    elif os.name=='nt':
        kernel,Extended=windows_api();limits=Extended()
        require(kernel.QueryInformationJobObject(None,9,c.byref(limits),c.sizeof(limits),None)
                and limits.basic.flags & 0x2000,'controller lifetime job is not enforced')
    else:
        require(False,'network worker requires supported kernel lifetime controls')
