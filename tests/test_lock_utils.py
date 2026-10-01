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


def test_send_ntfy_alert_sanitizes_title(monkeypatch):
    from scripts.backup_to_atlas import send_ntfy_alert
    monkeypatch.setenv("NTFY_TOPIC", "test-topic")
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(ok=True)
        send_ntfy_alert("Test body", title="🚨 CRITICAL: Test Alert 🚨")
        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        # Title must be pure ASCII without unicode emoji to prevent latin-1 encoding errors
        assert "🚨" not in headers["Title"]
        assert "CRITICAL: Test Alert" in headers["Title"]


def test_circuit_breaker_notices_account_deletion(monkeypatch):
    from bson.objectid import ObjectId
    from scripts.backup_to_atlas import _run_backup_internal

    monkeypatch.setenv("MONGODB_CONNECTION", "mongodb://mock-local:27017")
    monkeypatch.setenv("ATLAS_MONGODB_CONNECTION", "mongodb://mock-atlas:27017")

    user_a = ObjectId()
    user_deleted = ObjectId()

    mock_local_client = MagicMock()
    mock_atlas_client = MagicMock()

    mock_local_db = MagicMock()
    mock_atlas_db = MagicMock()

    mock_local_client.__getitem__.return_value = mock_local_db
    mock_atlas_client.__getitem__.return_value = mock_atlas_db

    mock_users_l = MagicMock()
    mock_posts_l = MagicMock()
    mock_comments_l = MagicMock()
    colls_l = {'users': mock_users_l, 'posts': mock_posts_l, 'comments': mock_comments_l}
    mock_local_db.__getitem__.side_effect = lambda k: colls_l[k]

    mock_users_a = MagicMock()
    mock_posts_a = MagicMock()
    mock_comments_a = MagicMock()
    colls_a = {'users': mock_users_a, 'posts': mock_posts_a, 'comments': mock_comments_a, '_backup_meta': MagicMock()}
    mock_atlas_db.__getitem__.side_effect = lambda k: colls_a[k]

    mock_local_db.list_collection_names.return_value = ['users', 'posts', 'comments']
    mock_atlas_db.list_collection_names.return_value = ['users', 'posts', 'comments']

    # Local has 1 user, Atlas had 2 users (user_deleted was deleted!)
    mock_users_l.find.return_value = [{'_id': user_a}]
    mock_users_a.find.return_value = [{'_id': user_a}, {'_id': user_deleted}]

    # Total local docs = 40 (dropped > 50%), Total Atlas docs = 100
    mock_users_l.count_documents.return_value = 1
    mock_posts_l.count_documents.return_value = 19
    mock_comments_l.count_documents.return_value = 20

    mock_users_a.count_documents.return_value = 2
    mock_posts_a.count_documents.return_value = 48
    mock_comments_a.count_documents.return_value = 50

    mock_posts_l.find.return_value = []
    mock_comments_l.find.return_value = []
    mock_posts_a.find.return_value = []
    mock_comments_a.find.return_value = []

    colls_a['_backup_meta'].find_one.return_value = None

    with patch("pymongo.MongoClient", side_effect=[mock_local_client, mock_atlas_client]), \
         patch("scripts.backup_to_atlas.send_ntfy_alert") as mock_alert:

        result = _run_backup_internal()
        # Since an account deletion was detected, backup must proceed without breaking!
        assert result is True
        # Informational alert sent, not critical failure
        mock_alert.assert_called_once()
        assert "Account Deletion" in mock_alert.call_args[1]["title"]

