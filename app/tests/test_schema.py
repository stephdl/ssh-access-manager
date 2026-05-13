"""Assert sql/schema.sql against a real Postgres 18 instance.

These tests exist because pytest's mocked DB layer cannot validate the
structural properties of the schema itself: GENERATED columns, composite
primary keys, CHECK constraints, unique indexes that span partitions of
data (active/disabled servers), and ON DELETE actions on foreign keys.

The tests are skipped when SCHEMA_TEST_DSN is not set, so the default
local pytest run remains a no-op. CI sets it to point at a postgres:18
service container — see .github/workflows/ci.yml.

Each test starts a fresh transaction and rolls it back at the end, so
tests are independent and order-insensitive.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

psycopg2 = pytest.importorskip("psycopg2")
import psycopg2.errors as pgerr  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "sql" / "schema.sql"


def _dsn() -> str:
    dsn = os.environ.get("SCHEMA_TEST_DSN")
    if not dsn:
        pytest.skip("SCHEMA_TEST_DSN not set — schema tests need a real Postgres 18")
    return dsn


@pytest.fixture(scope="module")
def schema_applied():
    """Apply sql/schema.sql to a fresh public schema once per module."""
    dsn = _dsn()
    with psycopg2.connect(dsn) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_PATH.read_text())
    return dsn


@pytest.fixture
def conn(schema_applied):
    """One connection per test, wrapped in a transaction that always rolls back."""
    c = psycopg2.connect(schema_applied)
    try:
        yield c
    finally:
        c.rollback()
        c.close()


@pytest.fixture
def cur(conn):
    with conn.cursor() as cursor:
        yield cursor


# ---------------------------------------------------------------------------
# Helpers — minimal row inserts keeping FK-required columns satisfied.
# ---------------------------------------------------------------------------
def _insert_server(cur, hostname="srv-1", ip="10.0.0.1"):
    cur.execute(
        "INSERT INTO servers (hostname, ip_address, environment) "
        "VALUES (%s, %s, 'lab') RETURNING id",
        (hostname, ip),
    )
    return cur.fetchone()[0]


def _insert_admin(cur, username="admin1", email="a@example.com", role="sysadmin"):
    cur.execute(
        "INSERT INTO administrators (username, email, password_hash, role) "
        "VALUES (%s, %s, 'x', %s) RETURNING id",
        (username, email, role),
    )
    return cur.fetchone()[0]


def _insert_key(cur, fingerprint, key_type="ssh-ed25519", bits=None, public_key="ssh-ed25519 AAAA"):
    cur.execute(
        "INSERT INTO ssh_keys (fingerprint, key_type, key_size_bits, public_key) "
        "VALUES (%s, %s, %s, %s) RETURNING id, is_compliant",
        (fingerprint, key_type, bits, public_key),
    )
    return cur.fetchone()


# ---------------------------------------------------------------------------
# ssh_keys.is_compliant — GENERATED ALWAYS AS STORED
# ---------------------------------------------------------------------------
class TestIsCompliantGeneratedColumn:
    def test_ed25519_is_compliant_true(self, cur):
        _, is_compliant = _insert_key(cur, "SHA256:aaa")
        assert is_compliant is True

    def test_rsa_below_4096_is_not_compliant(self, cur):
        _, is_compliant = _insert_key(cur, "SHA256:bbb", key_type="ssh-rsa", bits=2048)
        assert is_compliant is False

    def test_rsa_4096_is_compliant(self, cur):
        _, is_compliant = _insert_key(cur, "SHA256:ccc", key_type="ssh-rsa", bits=4096)
        assert is_compliant is True

    def test_ecdsa_is_not_compliant(self, cur):
        _, is_compliant = _insert_key(
            cur, "SHA256:ddd", key_type="ecdsa-sha2-nistp256", bits=256
        )
        assert is_compliant is False

    def test_is_compliant_cannot_be_written_explicitly(self, cur):
        with pytest.raises(pgerr.GeneratedAlways):
            cur.execute(
                "INSERT INTO ssh_keys (fingerprint, key_type, public_key, is_compliant) "
                "VALUES ('SHA256:eee', 'ssh-ed25519', 'ssh-ed25519 AAAA', FALSE)"
            )


# ---------------------------------------------------------------------------
# key_authorizations — composite PK (key_id, server_id, unix_user) (#185)
# ---------------------------------------------------------------------------
class TestKeyAuthorizationsCompositePK:
    def test_same_key_two_unix_users_on_same_server_allowed(self, cur):
        server_id = _insert_server(cur)
        key_id, _ = _insert_key(cur, "SHA256:k1")
        cur.execute(
            "INSERT INTO key_authorizations (key_id, server_id, unix_user, status) "
            "VALUES (%s, %s, 'alice', 'ACTIVE')",
            (key_id, server_id),
        )
        cur.execute(
            "INSERT INTO key_authorizations (key_id, server_id, unix_user, status) "
            "VALUES (%s, %s, 'bob', 'ACTIVE')",
            (key_id, server_id),
        )
        cur.execute(
            "SELECT count(*) FROM key_authorizations WHERE key_id=%s", (key_id,)
        )
        assert cur.fetchone()[0] == 2

    def test_duplicate_triplet_is_rejected(self, conn):
        with conn.cursor() as cur:
            server_id = _insert_server(cur)
            key_id, _ = _insert_key(cur, "SHA256:k2")
            cur.execute(
                "INSERT INTO key_authorizations (key_id, server_id, unix_user, status) "
                "VALUES (%s, %s, 'alice', 'ACTIVE')",
                (key_id, server_id),
            )
            with pytest.raises(pgerr.UniqueViolation):
                cur.execute(
                    "INSERT INTO key_authorizations (key_id, server_id, unix_user, status) "
                    "VALUES (%s, %s, 'alice', 'ACTIVE')",
                    (key_id, server_id),
                )


# ---------------------------------------------------------------------------
# servers_ip_unique — unique GLOBAL across active AND disabled servers
# ---------------------------------------------------------------------------
class TestServersIpUnique:
    def test_two_active_servers_with_same_ip_rejected(self, conn):
        with conn.cursor() as cur:
            _insert_server(cur, hostname="srv-a", ip="10.1.1.1")
            with pytest.raises(pgerr.UniqueViolation):
                _insert_server(cur, hostname="srv-b", ip="10.1.1.1")

    def test_disabled_server_still_blocks_ip_reuse(self, conn):
        with conn.cursor() as cur:
            _insert_server(cur, hostname="srv-c", ip="10.1.1.2")
            cur.execute("UPDATE servers SET is_active=FALSE WHERE hostname='srv-c'")
            with pytest.raises(pgerr.UniqueViolation):
                _insert_server(cur, hostname="srv-d", ip="10.1.1.2")


# ---------------------------------------------------------------------------
# CHECK constraints
# ---------------------------------------------------------------------------
class TestCheckConstraints:
    def test_sam_group_rejects_invalid_value(self, conn):
        with conn.cursor() as cur:
            server_id = _insert_server(cur)
            key_id, _ = _insert_key(cur, "SHA256:cg1")
            with pytest.raises(pgerr.CheckViolation):
                cur.execute(
                    "INSERT INTO key_authorizations "
                    "(key_id, server_id, unix_user, status, sam_group) "
                    "VALUES (%s, %s, 'alice', 'ACTIVE', 'wheel')",
                    (key_id, server_id),
                )

    @pytest.mark.parametrize("group", ["sam-operator", "sam-pkg", "sam-root"])
    def test_sam_group_accepts_valid_values(self, conn, group):
        with conn.cursor() as cur:
            server_id = _insert_server(cur, hostname=f"srv-{group}", ip=f"10.2.0.{hash(group) % 200 + 1}")
            key_id, _ = _insert_key(cur, f"SHA256:{group}")
            cur.execute(
                "INSERT INTO key_authorizations "
                "(key_id, server_id, unix_user, status, sam_group) "
                "VALUES (%s, %s, 'alice', 'ACTIVE', %s)",
                (key_id, server_id, group),
            )

    def test_admin_role_rejects_invalid(self, conn):
        with conn.cursor() as cur, pytest.raises(pgerr.CheckViolation):
            _insert_admin(cur, role="superuser")

    @pytest.mark.parametrize("role", ["sysadmin", "operator", "viewer"])
    def test_admin_role_accepts_valid(self, conn, role):
        with conn.cursor() as cur:
            _insert_admin(cur, username=f"u-{role}", email=f"{role}@x", role=role)

    def test_environment_rejects_invalid(self, conn):
        with conn.cursor() as cur, pytest.raises(pgerr.CheckViolation):
            cur.execute(
                "INSERT INTO servers (hostname, ip_address, environment) "
                "VALUES ('srv-env', '10.3.0.1', 'qa')"
            )

    def test_key_type_rejects_unknown(self, conn):
        with conn.cursor() as cur, pytest.raises(pgerr.CheckViolation):
            _insert_key(cur, "SHA256:kt", key_type="ssh-dss")


# ---------------------------------------------------------------------------
# FK ON DELETE SET NULL — audit trail is never destroyed by admin deletion
# ---------------------------------------------------------------------------
class TestForeignKeyOnDelete:
    def test_deleting_admin_nulls_revoked_by(self, conn):
        with conn.cursor() as cur:
            server_id = _insert_server(cur, hostname="srv-fk", ip="10.4.0.1")
            admin_id = _insert_admin(cur, username="adm-fk", email="adm@x")
            key_id, _ = _insert_key(cur, "SHA256:fk1")
            cur.execute(
                "INSERT INTO key_authorizations "
                "(key_id, server_id, unix_user, status, revoked_by) "
                "VALUES (%s, %s, 'alice', 'REVOKED', %s)",
                (key_id, server_id, admin_id),
            )
            cur.execute("DELETE FROM administrators WHERE id=%s", (admin_id,))
            cur.execute(
                "SELECT revoked_by FROM key_authorizations "
                "WHERE key_id=%s AND server_id=%s AND unix_user='alice'",
                (key_id, server_id),
            )
            assert cur.fetchone()[0] is None

    def test_deleting_admin_preserves_audit_log_row(self, conn):
        with conn.cursor() as cur:
            admin_id = _insert_admin(cur, username="adm-au", email="au@x")
            cur.execute(
                "INSERT INTO audit_log (action, performed_by, details) "
                "VALUES ('ADMIN_ADDED', %s, '{}')",
                (admin_id,),
            )
            cur.execute("DELETE FROM administrators WHERE id=%s", (admin_id,))
            cur.execute(
                "SELECT performed_by FROM audit_log WHERE action='ADMIN_ADDED'"
            )
            rows = cur.fetchall()
            assert len(rows) == 1
            assert rows[0][0] is None


# ---------------------------------------------------------------------------
# audit_log.action CHECK — unknown actions must be rejected
# ---------------------------------------------------------------------------
class TestAuditLogActionCheck:
    def test_unknown_action_is_rejected(self, conn):
        with conn.cursor() as cur, pytest.raises(pgerr.CheckViolation):
            cur.execute(
                "INSERT INTO audit_log (action, details) VALUES ('NOT_AN_ACTION', '{}')"
            )

    @pytest.mark.parametrize(
        "action",
        ["KEY_REVOKED", "LOGIN_FAILED", "ANOMALY_DETECTED", "SERVER_RENAMED", "GROUP_GRANTED"],
    )
    def test_documented_actions_accepted(self, conn, action):
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (action, details) VALUES (%s, '{}')", (action,)
            )
