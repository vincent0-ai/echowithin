import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

from scripts.lock_utils import TaskLock, _is_pid_running
from scripts.backup_to_atlas import run_backup
from scripts.calendar_reminders import run_calendar_reminders


def test_is_pid_running_current():
    assert _is_pid_running(os.getpid()) is True


def test_is_pid_running_invalid():
    assert _is_pid_running(0) is False
    assert _is_pid_running(-1) is False
    assert _is_pid_running(99999999) is False


def test_task_lock_acquire_and_release():
    lock = TaskLock("unit_test_lock_1", ttl_seconds=10)
    try:
        assert lock.acquire() is True
        assert lock.acquired is True

        # Second lock with same name should fail to acquire
        lock2 = TaskLock("unit_test_lock_1", ttl_seconds=10)
        assert lock2.acquire() is False
        assert lock2.acquired is False
    finally:
        lock.release()

    # After release, lock2 can acquire
    assert lock2.acquire() is True
    lock2.release()


def test_task_lock_context_manager():
    with TaskLock("unit_test_ctx_lock", ttl_seconds=10) as acquired1:
        assert acquired1 is True
        with TaskLock("unit_test_ctx_lock", ttl_seconds=10) as acquired2:
            assert acquired2 is False

    # After exit, lock can be acquired again
    with TaskLock("unit_test_ctx_lock", ttl_seconds=10) as acquired3:
        assert acquired3 is True


def test_backup_to_atlas_skips_when_locked():
    # Hold lock artificially
    outer_lock = TaskLock("backup_to_atlas", ttl_seconds=60)
    assert outer_lock.acquire() is True
    try:
        with patch("scripts.backup_to_atlas._run_backup_internal") as mock_internal:
            result = run_backup()
            assert result is True
            # Internal backup must NOT be called because lock was held
            mock_internal.assert_not_called()
    finally:
        outer_lock.release()


def test_calendar_reminders_skips_when_locked():
    # Hold lock artificially
    outer_lock = TaskLock("calendar_reminders", ttl_seconds=60)
    assert outer_lock.acquire() is True
    try:
        with patch("scripts.calendar_reminders._run_calendar_reminders_internal") as mock_internal:
            result = run_calendar_reminders()
            assert result == 0
            # Internal reminders check must NOT be called because lock was held
            mock_internal.assert_not_called()
    finally:
        outer_lock.release()
