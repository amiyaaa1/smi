#!/usr/bin/env python3
import atexit
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple


class ManagedBrowserRuntime:
    def __init__(self, profile_dir: str = '', logger: Optional[Callable[[str], None]] = None):
        self.profile_dir = str(profile_dir or '').strip()
        self.logger = logger or (lambda _message: None)
        self.context = None
        self._cleaned = False
        self._registered = False
        self._previous_handlers: Dict[int, object] = {}
        self._register_exit_hooks()

    def set_profile_dir(self, profile_dir: str) -> None:
        self.profile_dir = str(profile_dir or '').strip()

    def set_context(self, context) -> None:
        self.context = context

    def remove_profile_locks(self) -> None:
        if not self.profile_dir:
            return
        for name in ('SingletonLock', 'SingletonCookie', 'SingletonSocket'):
            path = Path(self.profile_dir) / name
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                pass

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True

        self._close_context()
        time.sleep(0.5)

        related_pids = self._find_related_pids()
        if related_pids:
            self._terminate_pids(related_pids, signal.SIGTERM)
            time.sleep(0.8)
            remaining = {pid for pid in related_pids if Path(f'/proc/{pid}').exists()}
            if remaining:
                self._terminate_pids(remaining, signal.SIGKILL)

        self.remove_profile_locks()

    def _register_exit_hooks(self) -> None:
        if self._registered:
            return
        self._registered = True
        atexit.register(self.cleanup)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            try:
                self._previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except Exception:
                continue

    def _handle_signal(self, signum, _frame) -> None:
        self.logger(f'[browser-cleanup] received signal {signum}, closing browser runtime')
        try:
            self.cleanup()
        finally:
            raise SystemExit(128 + int(signum))

    def _close_context(self) -> None:
        context = self.context
        self.context = None
        if context is None:
            return
        try:
            context.close()
        except Exception as exc:
            self.logger(f'[browser-cleanup] context.close failed: {exc}')

    def _find_related_pids(self) -> Set[int]:
        current_pid = os.getpid()
        rows = self._process_rows()
        children = self._descendant_pids(current_pid, rows)
        profile_related = set()
        if self.profile_dir:
            profile_marker = self.profile_dir
            for pid, _ppid, cmd in rows:
                if pid == current_pid:
                    continue
                if profile_marker in cmd:
                    profile_related.add(pid)
        return {pid for pid in (children | profile_related) if pid != current_pid}

    def _process_rows(self) -> List[Tuple[int, int, str]]:
        try:
            proc = subprocess.run(
                ['ps', '-eo', 'pid=,ppid=,cmd='],
                capture_output=True,
                text=True,
                check=True,
            )
        except Exception as exc:
            self.logger(f'[browser-cleanup] ps failed: {exc}')
            return []

        rows: List[Tuple[int, int, str]] = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 3:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
            except ValueError:
                continue
            rows.append((pid, ppid, parts[2]))
        return rows

    def _descendant_pids(self, root_pid: int, rows: List[Tuple[int, int, str]]) -> Set[int]:
        by_parent: Dict[int, Set[int]] = {}
        for pid, ppid, _cmd in rows:
            by_parent.setdefault(ppid, set()).add(pid)

        pending = list(by_parent.get(root_pid, set()))
        seen: Set[int] = set()
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            pending.extend(by_parent.get(pid, set()))
        return seen

    def _terminate_pids(self, pids: Set[int], sig) -> None:
        for pid in sorted({pid for pid in pids if pid > 1}):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                continue
            except Exception as exc:
                self.logger(f'[browser-cleanup] kill {pid} with {sig} failed: {exc}')
