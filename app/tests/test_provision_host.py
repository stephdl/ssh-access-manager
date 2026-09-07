"""Assert the sudoers generation in provision-host.sh.

The collector sudoers file lands in /etc/sudoers.d/ under a name with no
dot, so sudo parses it on every invocation. A malformed rule there breaks
sudo host-wide — including the sudo an operator would need to repair it.
The script therefore stages the file, validates it with `visudo -c`, and
only then installs it.

These tests drive the script's `--print-sudoers` mode, which emits the
rules on stdout without touching the host, so they run unprivileged.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "provision-host.sh"

# Helpers SAM invokes directly via `sudo <helper> [args]`. The rule carries
# no argument list: sudoers allows any arguments when a Cmnd is listed
# without them, which is what sam-add and sam-revoke need.
DIRECT_HELPERS = [
    "sam-collect",
    "sam-revoke",
    "sam-add",
    "sam-lock-user",
    "sam-unlock-user",
    "sam-sessions",
]

# Helpers SAM uploads to the collector home and installs with a pinned
# `install` invocation during self-update.
INSTALLED_HELPERS = DIRECT_HELPERS + [
    "sam-grant-group",
    "sam-revoke-group",
    "sam-self-update",
]


def print_sudoers(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", str(SCRIPT), "--print-sudoers", *args],
        capture_output=True,
        text=True,
    )


def test_script_is_valid_posix_shell():
    result = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_print_sudoers_does_not_need_root():
    result = print_sudoers()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()


def test_every_direct_helper_has_an_unrestricted_rule():
    rules = print_sudoers().stdout
    for helper in DIRECT_HELPERS:
        expected = f"audit-collector ALL=(root) NOPASSWD: /usr/local/bin/{helper}\n"
        assert expected in rules, helper


def test_every_installed_helper_has_a_pinned_install_rule():
    rules = print_sudoers().stdout
    for helper in INSTALLED_HELPERS:
        expected = (
            "audit-collector ALL=(root) NOPASSWD: /usr/bin/install "
            "-m 750 -o root -g root "
            f"/home/audit-collector/{helper} /usr/local/bin/{helper}\n"
        )
        assert expected in rules, helper


def test_group_helpers_and_self_update_accept_arguments():
    rules = print_sudoers().stdout
    for rule in (
        "/usr/local/bin/sam-grant-group *",
        "/usr/local/bin/sam-revoke-group *",
        "/usr/local/bin/sam-self-update *",
    ):
        assert f"audit-collector ALL=(root) NOPASSWD: {rule}\n" in rules, rule


def test_sshd_config_dump_is_pinned_to_dash_t():
    rules = print_sudoers().stdout
    sshd_rules = [ln for ln in rules.splitlines() if "sshd" in ln]
    assert len(sshd_rules) == 1
    assert sshd_rules[0].endswith("sshd -T")


def test_every_rule_requires_no_password_and_targets_root():
    for line in print_sudoers().stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        assert line.startswith("audit-collector ALL=(root) NOPASSWD: "), line


def test_custom_collector_user_is_used_in_every_rule():
    result = print_sudoers("sam-probe")
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        if line.startswith("#"):
            continue
        assert line.startswith("sam-probe ")
    assert "audit-collector" not in result.stdout


@pytest.mark.parametrize(
    "bad_user",
    [
        "bad%user",       # eaten by the printf format string
        "bad user",       # forges a second field in the rule
        "bad\nuser",      # forges an entire extra rule
        "Bad-User",       # uppercase is not a valid Unix account name here
        "bad/user",
    ],
)
def test_invalid_collector_user_is_refused(bad_user):
    result = print_sudoers(bad_user)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid collector user" in result.stderr


def test_empty_user_argument_falls_back_to_the_default():
    # `${2:-audit-collector}` treats an empty argument as absent, which is
    # what SAM relies on when SSH_USER is unset.
    result = print_sudoers("")
    assert result.returncode == 0
    assert "audit-collector ALL=(root)" in result.stdout


@pytest.mark.skipif(shutil.which("visudo") is None, reason="visudo not available")
def test_generated_rules_pass_visudo(tmp_path):
    rules = tmp_path / "sam-collector"
    rules.write_text(print_sudoers().stdout)
    result = subprocess.run(
        ["visudo", "-c", "-f", str(rules)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


class TestInstallIsGuarded:
    """The live sudoers file must never be written to directly.

    These read the script source rather than executing it: the install path
    needs root and a real /etc/sudoers.d, so the guarantee is asserted
    structurally.
    """

    @property
    def source(self) -> str:
        return SCRIPT.read_text()

    def test_rules_are_staged_in_a_dotted_tmp_file(self):
        # sudo ignores filenames containing a dot, so the staged file is
        # inert even while it sits in /etc/sudoers.d.
        assert 'SUDOERS_TMP="${SUDOERS_FILE}.tmp"' in self.source
        assert '_sudoers_rules "${COLLECTOR_USER}" "${SSHD}" > "${SUDOERS_TMP}"' in self.source

    def test_no_rule_is_ever_appended_to_the_live_file(self):
        assert '>> "${SUDOERS_FILE}"' not in self.source
        assert '> "${SUDOERS_FILE}"' not in self.source

    def test_validation_precedes_installation(self):
        source = self.source
        validate = source.index('"${VISUDO}" -c -f "${SUDOERS_TMP}"')
        install = source.index('install -m 440 -o root -g root "${SUDOERS_TMP}"')
        assert validate < install

    def test_invalid_rules_abort_and_discard_the_staged_file(self):
        source = self.source
        block_start = source.index('if ! "${VISUDO}" -c -f "${SUDOERS_TMP}"')
        block = source[block_start : source.index("install -m 440", block_start)]
        assert 'rm -f "${SUDOERS_TMP}"' in block
        assert "exit 1" in block

    def test_the_install_line_is_the_only_writer_of_the_live_file(self):
        # Anything else touching ${SUDOERS_FILE} would reintroduce the
        # half-written-file failure mode this guard exists to prevent.
        writers = [
            line.strip()
            for line in self.source.splitlines()
            if "${SUDOERS_FILE}" in line
            and not line.lstrip().startswith("#")
            and not line.lstrip().startswith("printf")
            and not line.lstrip().startswith("echo")
            and "SUDOERS_FILE=" not in line
            and "SUDOERS_TMP=" not in line
        ]
        assert writers == [
            'install -m 440 -o root -g root "${SUDOERS_TMP}" "${SUDOERS_FILE}"'
        ]
