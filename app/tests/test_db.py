from unittest.mock import MagicMock, patch, call
import pytest
import psycopg2

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pool(rows=None, rowcount=1):
    """Build a mock pool + conn + cursor returning given rows."""
    pool = MagicMock()
    conn = MagicMock()
    cursor = MagicMock()

    pool.getconn.return_value = conn
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    cursor.fetchall.return_value = rows or []
    cursor.fetchone.return_value = rows[0] if rows else None
    cursor.rowcount = rowcount
    return pool, conn, cursor


# ---------------------------------------------------------------------------
# Tests execute()
# ---------------------------------------------------------------------------

def test_db_execute_calls_sql_with_params():
    pool, conn, cursor = _make_pool()
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        db.execute("INSERT INTO servers (hostname) VALUES (%s)", ("host1",))
    cursor.execute.assert_called_once_with(
        "INSERT INTO servers (hostname) VALUES (%s)", ("host1",)
    )


def test_db_execute_commits_on_success():
    pool, conn, cursor = _make_pool()
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        db.execute("DELETE FROM servers WHERE id = %s", ("uuid",))
    conn.commit.assert_called_once()


def test_db_execute_rollback_on_exception():
    pool, conn, cursor = _make_pool()
    cursor.execute.side_effect = psycopg2.DatabaseError("constraint violation")
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        with pytest.raises(psycopg2.DatabaseError):
            db.execute("INSERT INTO servers (hostname) VALUES (%s)", ("dup",))
    conn.rollback.assert_called_once()


# ---------------------------------------------------------------------------
# Tests query()
# ---------------------------------------------------------------------------

def test_db_query_returns_list_of_dicts():
    row1 = {"hostname": "srv-01", "is_active": True}
    row2 = {"hostname": "srv-02", "is_active": False}
    pool, conn, cursor = _make_pool(rows=[row1, row2])
    cursor.fetchall.return_value = [row1, row2]
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        result = db.query("SELECT hostname, is_active FROM servers")
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["hostname"] == "srv-01"


def test_db_query_returns_empty_list_when_no_rows():
    pool, conn, cursor = _make_pool(rows=[])
    cursor.fetchall.return_value = []
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        result = db.query("SELECT * FROM servers WHERE is_active = %s", (False,))
    assert result == []


# ---------------------------------------------------------------------------
# Tests query_one()
# ---------------------------------------------------------------------------

def test_db_query_one_returns_dict_when_found():
    row = {"id": "uuid-1", "hostname": "srv-01"}
    pool, conn, cursor = _make_pool(rows=[row])
    cursor.fetchone.return_value = row
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        result = db.query_one(
            "SELECT id, hostname FROM servers WHERE hostname = %s", ("srv-01",)
        )
    assert result == {"id": "uuid-1", "hostname": "srv-01"}


def test_db_query_one_returns_none_when_not_found():
    pool, conn, cursor = _make_pool(rows=[])
    cursor.fetchone.return_value = None
    with patch("db._get_pool", return_value=pool):
        db._pool = None
        result = db.query_one(
            "SELECT * FROM servers WHERE hostname = %s", ("ghost",)
        )
    assert result is None
