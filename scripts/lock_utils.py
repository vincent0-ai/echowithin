"""
Concurrency lock utilities for background tasks.
Provides non-blocking distributed locking via Redis with an automatic
PID-file fallback when Redis is unavailable.
"""

import os
import sys
import time
import tempfile


def _is_pid_running(pid: int) -> bool:
    """Check whether a process with the given PID is currently active."""
    if pid <= 0:
        return False
    if sys.platform == 'win32':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        SYNCHRONIZE = 0x00100000
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                kernel32.CloseHandle(handle)
                STILL_ACTIVE = 259
                return exit_code.value == STILL_ACTIVE
            kernel32.CloseHandle(handle)
            return False
        ERROR_ACCESS_DENIED = 5
        if kernel32.GetLastError() == ERROR_ACCESS_DENIED:
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except (OSError, ProcessLookupError):
            return False


class TaskLock:
    """
    A non-blocking concurrency guard for long-running background tasks.
    
    Attempts to acquire a lock via Redis first (non-blocking NX with TTL).
    If Redis is unreachable or unconfigured, falls back to a PID lockfile in tempdir.
    """

    def __init__(self, name: str, ttl_seconds: int = 1800):
        self.name = name
        self.ttl_seconds = ttl_seconds
        self.lock_key = f"lock:{name}"
        self.token = f"{os.getpid()}:{time.time()}"
        self.pid_file = os.path.join(tempfile.gettempdir(), f"echowithin_{name}.pid")
        self.acquired = False
        self._using_redis = False
        self.redis_client = None

    def _get_redis_client(self):
        """Try to get an active Redis client with a fast timeout."""
        # 1. Check if database/main module is already imported
        try:
            if 'database' in sys.modules:
                db_mod = sys.modules['database']
                if getattr(db_mod, 'redis_cache', None) is not None:
                    db_mod.redis_cache.ping()
                    return db_mod.redis_cache
            if 'main' in sys.modules:
                m_mod = sys.modules['main']
                if getattr(m_mod, 'redis_cache', None) is not None:
                    m_mod.redis_cache.ping()
                    return m_mod.redis_cache
        except Exception:
            pass

        # 2. Standalone connection attempt
        try:
            import socket
            import redis
            from urllib.parse import urlparse

            redis_url = os.environ.get('REDIS_URL') or os.environ.get('RQ_REDIS_URL')
            if redis_url:
                parsed = urlparse(redis_url)
                host = parsed.hostname or '127.0.0.1'
                port = parsed.port or 6379
            else:
                host = os.environ.get('REDIS_HOST', '127.0.0.1')
                if host == 'localhost':
                    host = '127.0.0.1'
                port_str = os.environ.get('REDIS_PORT', '6379')
                try:
                    port = int(port_str)
                except ValueError:
                    port = 6379

            # Fast socket probe (< 0.2s) before initializing redis-py
            s = socket.socket()
            s.settimeout(0.2)
            res = s.connect_ex((host, port))
            s.close()
            if res != 0:
                return None

            if redis_url:
                r = redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5, retry_on_timeout=False)
            else:
                password = os.environ.get('REDIS_PASSWORD') or None
                r = redis.Redis(host=host, port=port, password=password, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5, retry_on_timeout=False)
            r.ping()
            return r
        except Exception:
            return None

    def acquire(self) -> bool:
        """
        Attempt to acquire the lock non-blockingly.
        Returns True if acquired, False if another process holds the lock.
        """
        if self.acquired:
            return True

        # Try Redis first
        self.redis_client = self._get_redis_client()
        if self.redis_client is not None:
            try:
                res = self.redis_client.set(self.lock_key, self.token, nx=True, ex=self.ttl_seconds)
                if res:
                    self.acquired = True
                    self._using_redis = True
                    return True
                else:
                    self.acquired = False
                    return False
            except Exception:
                # Redis error mid-operation, fall back to PID file
                self.redis_client = None

        # PID file fallback
        self.acquired = self._acquire_pid_file()
        self._using_redis = False
        return self.acquired

    def _acquire_pid_file(self) -> bool:
        now = time.time()
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, 'r') as f:
                    content = f.read().strip()
                parts = content.split(':')
                if len(parts) >= 2:
                    pid = int(parts[0])
                    ts = float(parts[1])
                    age = now - ts
                    if age < self.ttl_seconds and _is_pid_running(pid):
                        return False
                elif len(parts) == 1 and parts[0].isdigit():
                    pid = int(parts[0])
                    if _is_pid_running(pid):
                        return False
            except Exception:
                pass

            # Stale lock: clean up
            try:
                os.remove(self.pid_file)
            except OSError:
                pass

        try:
            fd = os.open(self.pid_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, 'w') as f:
                f.write(f"{os.getpid()}:{now}\n")
            return True
        except OSError:
            return False

    def release(self):
        """Release the lock if held by this instance."""
        if not self.acquired:
            return

        if self._using_redis and self.redis_client:
            try:
                lua = """
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                """
                self.redis_client.eval(lua, 1, self.lock_key, self.token)
            except Exception:
                pass
        else:
            if os.path.exists(self.pid_file):
                try:
                    with open(self.pid_file, 'r') as f:
                        content = f.read().strip()
                    if content.startswith(f"{os.getpid()}:"):
                        os.remove(self.pid_file)
                except Exception:
                    pass

        self.acquired = False

    def __enter__(self):
        self.acquire()
        return self.acquired

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
