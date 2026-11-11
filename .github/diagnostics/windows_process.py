"""Synthetic Windows timing diagnosis; never substitutes for required checks."""
import contextlib
import ctypes
import gc
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'tests'), str(ROOT / 'scripts')]
SUITE = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
import test_m4_delivery as target
import m4_support
import security_runtime.process as process_module
import security_runtime.web as web_module

REPORT = {'scope': 'Synthetic read-only diagnostics; original tests and all runtime source bytes unchanged. Observation wrappers may affect timing. Observed poll times do not establish OS exit time.', 'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'python': sys.version, 'platform': platform.platform(), 'python_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(), 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'workflow_sha256': hashlib.sha256((ROOT / '.github/workflows/validate.yml').read_bytes()).hexdigest(), 'phases': []}
BASE = '2fedb6353563dca9ea3f981445f83a28c284026f'
original_paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', BASE], cwd=ROOT, text=True).splitlines()
source_checks = {}
for relative in original_paths:
    if relative == '.github/workflows/validate.yml': continue
    raw = subprocess.check_output(['git', 'show', BASE + ':' + relative], cwd=ROOT)
    actual = (ROOT / relative).read_bytes()
    # Git checkout line-ending conversion is permitted; underlying Git blobs
    # and normalized runtime text remain identical to the frozen candidate.
    current_blob = subprocess.check_output(['git', 'rev-parse', 'HEAD:' + relative], cwd=ROOT, text=True).strip()
    base_blob = subprocess.check_output(['git', 'rev-parse', BASE + ':' + relative], cwd=ROOT, text=True).strip()
    assert current_blob == base_blob and actual.replace(b'\r\n', b'\n') == raw.replace(b'\r\n', b'\n'), relative
    source_checks[relative] = hashlib.sha256(raw).hexdigest()
REPORT['frozen_source_binding'] = {'base': BASE, 'original_files_matched': len(source_checks), 'git_blob_sha256': source_checks, 'excluded': ['.github/workflows/validate.yml'], 'added_diagnostic_path': '.github/diagnostics/windows_process.py'}
CURRENT = [None]
TEST = [None]
ALL_ROWS = []
START = time.monotonic()

def event(row, kind, **values):
    if row is not None:
        if len(row['events']) < 512:
            row['events'].append({'at': time.monotonic() - START, 'kind': kind, 'thread': threading.current_thread().name, **values})
        else:
            row['events_truncated'] = True

original_execute = m4_support.RuntimeWorld.execute
original_guard = web_module.WebController.guard
original_tree = web_module.selected_tree
original_server = m4_support.Server.__init__
original_popen = subprocess.Popen

class ObservedPopen(original_popen):
    def __init__(self, argv, *args, **kwargs):
        self.diag_row = CURRENT[0] if isinstance(argv, (list, tuple)) and any(str(a).endswith('web_worker.py') for a in argv) else None
        self.diag_child = None
        if self.diag_row is not None:
            self.diag_child = {'poll_count': 0, 'max_poll_gap': 0, 'last_poll': None, 'first_live': None, 'last_live': None, 'first_exit': None}
            self.diag_row['children'].append(self.diag_child)
        event(self.diag_row, 'popen_begin')
        try:
            super().__init__(argv, *args, **kwargs)
        finally:
            event(self.diag_row, 'popen_end')
    def poll(self):
        result = super().poll()
        at = time.monotonic() - START
        child = self.diag_child
        if child is not None:
            child['poll_count'] += 1
            if child['last_poll'] is not None:
                child['max_poll_gap'] = max(child['max_poll_gap'], at - child['last_poll'])
            child['last_poll'] = at
            observation = {'at': at, 'thread': threading.current_thread().name, 'return_code': result}
            if result is None:
                if child['first_live'] is None: child['first_live'] = observation
                child['last_live'] = observation
            elif child['first_exit'] is None:
                child['first_exit'] = observation
        return result
    def kill(self):
        event(self.diag_row, 'kill_begin')
        try: return super().kill()
        finally: event(self.diag_row, 'kill_end')
    def wait(self, *args, **kwargs):
        result = super().wait(*args, **kwargs)
        event(self.diag_row, 'wait_return', return_code=result)
        return result

def execute(world, route='read', *args, **kwargs):
    allowed = {'owner-identity', 'owner-read', 'outsider-identity', 'outsider-read', 'tenant-identity', 'tenant-read', 'anonymous-read', 'read'}
    row = {'test': TEST[0], 'route': route if route in allowed else 'other-synthetic-route', 'events': [], 'children': [], 'calls_before': len(world.server.calls), 'events_truncated': False}
    ALL_ROWS.append(row)
    previous = CURRENT[0]
    CURRENT[0] = row
    event(row, 'execute_begin')
    try:
        value = original_execute(world, route, *args, **kwargs)
        row['outcome'] = 'returned'
        return value
    except BaseException as error:
        row['outcome'] = type(error).__name__
        # Exceptions are propagated unchanged; no credential/value is serialized.
        raise
    finally:
        event(row, 'execute_end')
        row['calls_after'] = len(world.server.calls)
        row['active_threads_at_end'] = [t.name for t in threading.enumerate()]
        CURRENT[0] = previous

def guard(self, *args, **kwargs):
    row = CURRENT[0]
    event(row, 'guard_begin')
    try: return original_guard(self, *args, **kwargs)
    finally: event(row, 'guard_end')

def tree(*args, **kwargs):
    row = CURRENT[0]
    event(row, 'selected_tree_begin')
    try: return original_tree(*args, **kwargs)
    finally: event(row, 'selected_tree_end')

def server(self, *args, **kwargs):
    original_server(self, *args, **kwargs)
    actual = self.http.RequestHandlerClass.do_GET
    def get(request):
        row = CURRENT[0]
        event(row, 'http_get_begin')
        try: return actual(request)
        finally: event(row, 'http_get_end')
    self.http.RequestHandlerClass.do_GET = get
    self.http.RequestHandlerClass.do_HEAD = get

def counters():
    return {'ctypes_pointer_cache': len(getattr(ctypes, '_pointer_type_cache', {})), 'gc_count': list(gc.get_count()), 'gc_stats': gc.get_stats()}

def gc_observer(phase, info):
    event(CURRENT[0], 'gc_' + phase, generation=info.get('generation'), collected=info.get('collected'), uncollectable=info.get('uncollectable'))

class DiagnosticResult(unittest.TextTestResult):
    def startTest(self, test):
        TEST[0] = test.id()
        self.diagnostic_start = time.monotonic()
        self.diagnostic_counters = counters()
        self.diagnostic_stack = contextlib.ExitStack()
        if test.id().startswith('test_m4_delivery.DeliveryTests.'):
            gc.callbacks.append(gc_observer)
            self.diagnostic_stack.callback(gc.callbacks.remove, gc_observer)
            for owner, attribute, replacement in [(m4_support.RuntimeWorld, 'execute', execute), (web_module.WebController, 'guard', guard), (web_module, 'selected_tree', tree), (m4_support.Server, '__init__', server), (process_module.subprocess, 'Popen', ObservedPopen)]:
                self.diagnostic_stack.enter_context(patch.object(owner, attribute, replacement))
        return super().startTest(test)
    def stopTest(self, test):
        try:
            self.diagnostic_stack.close()
            REPORT['ordered_tests'].append({'test': test.id(), 'seconds': time.monotonic()-self.diagnostic_start, 'counters_before': self.diagnostic_counters, 'counters_after': counters()})
            return super().stopTest(test)
        finally: TEST[0] = None

REPORT['ordered_tests'] = []
REPORT['diagnostic_scope'] = 'Original discovery order and full suite; wrappers active only during DeliveryTests; no preceding warm-up phase or altered deadlines.'
started = time.monotonic()
try:
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=DiagnosticResult).run(SUITE)
    REPORT['result'] = {'tests': result.testsRun, 'success': result.wasSuccessful(), 'errors': len(result.errors), 'failures': len(result.failures), 'seconds': time.monotonic()-started}
finally:
    REPORT['route_observations'] = ALL_ROWS
    REPORT['wrappers_restored'] = m4_support.RuntimeWorld.execute is original_execute and web_module.WebController.guard is original_guard and web_module.selected_tree is original_tree and m4_support.Server.__init__ is original_server and subprocess.Popen is original_popen and gc_observer not in gc.callbacks
    print('DIAGNOSTIC_REPORT ' + json.dumps(REPORT, sort_keys=True), flush=True)
raise SystemExit(0 if result.wasSuccessful() and REPORT['wrappers_restored'] else 1)
