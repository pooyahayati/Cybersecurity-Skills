"""Bound subprocess output without buffering an untrusted stream in memory."""

from __future__ import annotations

import hashlib
import subprocess
import threading
import time

from .common import Blocked, require


def bounded_process(argv, env, timeout, limit, *, guard=None, sink=None, capture=True, input_data=None, max_input_bytes=8192, kill_with_parent=False):
    require(type(max_input_bytes) is int and 1<=max_input_bytes<=131072, 'invalid process input bound')
    require(input_data is None or isinstance(input_data, bytes) and len(input_data) <= max_input_bytes,
            "process input exceeds its limit")
    process = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    lifetime=None
    if kill_with_parent:
        from .parent_guard import attach_windows
        try:lifetime=attach_windows(process)
        except BaseException:
            process.kill();process.wait(timeout=10)
            for stream in (process.stdin,process.stdout):
                if stream is not None:stream.close()
            raise
    started = time.monotonic()
    content, count, fingerprint = bytearray(), [0], hashlib.sha256()
    overflow, read_error = threading.Event(), threading.Event()

    def drain():
        try:
            with process.stdout:
                while block := process.stdout.read1(4096):
                    available = max(0, limit - count[0])
                    kept = block[:available]
                    count[0] += len(block)
                    fingerprint.update(kept)
                    if capture:
                        content.extend(kept)
                    if sink is not None:
                        sink.write(kept)
                    if count[0] > limit:
                        overflow.set()
        except (OSError, ValueError):
            read_error.set()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()

    def feed():
        try:
            with process.stdin:
                process.stdin.write(input_data)
                process.stdin.flush()
        except (OSError, ValueError):
            read_error.set()

    writer = threading.Thread(target=feed, daemon=True) if input_data is not None else None
    if writer:
        writer.start()
    problem = None
    try:
        while process.poll() is None:
            require(not overflow.is_set(), "process output limit exceeded")
            require(not read_error.is_set(), "cannot retain bounded execution evidence")
            require(time.monotonic() - started <= timeout, "process deadline exceeded")
            if guard is not None:
                guard()
            time.sleep(0.05)
    except BaseException as exc:
        problem = exc
        process.kill()
    finally:
        process.wait(timeout=10)
        if lifetime:
            from .parent_guard import close_windows
            close_windows(lifetime)
        reader.join(timeout=10)
        if writer:
            writer.join(timeout=10)
    require(not reader.is_alive(), "process output stream did not close")
    require(writer is None or not writer.is_alive(), "process input stream did not close")
    if problem is not None:
        raise problem
    require(not overflow.is_set(), "process output limit exceeded")
    require(not read_error.is_set(), "cannot retain bounded execution evidence")
    if guard is not None:
        guard()
    return {"exit_code": process.returncode, "bytes": count[0],
            "sha256": fingerprint.hexdigest(), "elapsed_seconds": time.monotonic() - started,
            "content": bytes(content)}
