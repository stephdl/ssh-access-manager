"""Assert that sam-pkg cannot reach root through package management.

A sudoers rule on the package manager itself is root-equivalent: every
package manager installs a local file whose scripts run as root, and most
accept a hook option that runs a command outright. Sudoers wildcards
cannot express "a package name but not a path or an option", so SAM grants
sudo on the sam-install-pkg wrapper instead and validates there.

These tests run the generated shell directly. The wrapper is exercised
with an empty PATH so it never finds a package manager: reaching the
"no supported package manager" branch is the signal that validation let
the arguments through.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ssh

NO_PKG_MANAGER = "no supported package manager"
INVALID_NAME = "invalid package name"


@pytest.fixture
def wrapper(tmp_path):
    """sam-install-pkg on disk, runnable with a PATH holding no tooling."""
    script = tmp_path / "sam-install-pkg"
    script.write_bytes(ssh.SAM_INSTALL_PKG)
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()

    def run(*args: str) -> subprocess.CompletedProcess:
        # /bin/sh by absolute path: PATH is emptied for the script, and
        # Popen would otherwise fail to resolve the interpreter itself.
        return subprocess.run(
            ["/bin/sh", str(script), *args],
            capture_output=True,
            text=True,
            env={"PATH": str(empty_path)},
        )

    return run


class TestWrapperRejectsRootEscalation:
    @pytest.mark.parametrize(
        "argument",
        [
            "./payload.deb",      # dpkg runs its maintainer scripts as root
            "payload.deb",        # apt treats a .deb suffix as a local file
            "/tmp/payload.rpm",
            "../payload.apk",
            "payload.pkg.tar.zst",
            "payload.txz",
        ],
    )
    def test_local_package_files_are_refused(self, wrapper, argument):
        result = wrapper("install", argument)
        assert result.returncode == 1
        assert INVALID_NAME in result.stderr

    @pytest.mark.parametrize(
        "argument",
        [
            "-o",                             # apt -o DPkg::Pre-Invoke = root shell
            "--allow-untrusted",
            "-U",                             # pacman -U installs a local file
            "--assume-yes",
        ],
    )
    def test_options_are_refused(self, wrapper, argument):
        result = wrapper("install", argument, "nginx")
        assert result.returncode == 1
        assert INVALID_NAME in result.stderr

    @pytest.mark.parametrize(
        "argument", ["pkg;id", "pkg$(id)", "pkg`id`", "pkg&&id", "pkg|id", "pkg name"]
    )
    def test_shell_metacharacters_are_refused(self, wrapper, argument):
        result = wrapper("install", argument)
        assert result.returncode == 1
        assert INVALID_NAME in result.stderr

    def test_one_bad_name_rejects_the_whole_invocation(self, wrapper):
        result = wrapper("install", "nginx", "./payload.deb", "curl")
        assert result.returncode == 1
        assert INVALID_NAME in result.stderr
        assert NO_PKG_MANAGER not in result.stderr

    @pytest.mark.parametrize("action", ["remove", "purge", "-S", "", "install-pkg"])
    def test_only_install_and_upgrade_are_accepted(self, wrapper, action):
        result = wrapper(action) if action else wrapper()
        assert result.returncode == 1
        assert "Usage: sam-install-pkg" in result.stderr


class TestWrapperAcceptsRealPackageNames:
    @pytest.mark.parametrize(
        "package",
        [
            "nginx",
            "python3.11",        # dots are legitimate, so they stay allowed
            "lib32z1-dev",
            "ca-certificates",
            "g++",
            "nginx=1.24.0-1",    # apt version pinning
            "kernel_5.15",
        ],
    )
    def test_package_name_passes_validation(self, wrapper, package):
        result = wrapper("install", package)
        assert NO_PKG_MANAGER in result.stderr, result.stderr

    def test_several_packages_pass_validation(self, wrapper):
        result = wrapper("install", "nginx", "curl", "python3.11")
        assert NO_PKG_MANAGER in result.stderr

    def test_upgrade_takes_no_package(self, wrapper):
        result = wrapper("upgrade")
        assert NO_PKG_MANAGER in result.stderr


class TestGeneratedSudoersRules:
    """Drive `sam-self-update --dry-run`, which stages in a temp dir."""

    @pytest.fixture(scope="class")
    def rules(self, tmp_path_factory) -> str:
        tmp_path = tmp_path_factory.mktemp("self-update")
        script = tmp_path / "sam-self-update"
        script.write_bytes(ssh.SAM_SELF_UPDATE)
        result = subprocess.run(
            ["sh", str(script), "--dry-run"], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    @pytest.mark.parametrize(
        "command",
        [
            "apt install",
            "apt upgrade",
            "dnf install",
            "yum install",
            "zypper install",
            "apk add",
            "pacman -S",
        ],
    )
    def test_no_package_manager_is_granted_directly(self, rules, command):
        assert command not in rules

    def test_package_management_goes_through_the_wrapper(self, rules):
        assert (
            "%sam-pkg ALL=(root) PASSWD: /usr/local/bin/sam-install-pkg" in rules
        )

    def test_the_wrapper_rule_carries_no_argument_list(self, rules):
        # A bare Cmnd accepts any arguments, which is what the wrapper needs;
        # a `*` variant would be redundant and suggest the args are unchecked.
        assert "/usr/local/bin/sam-install-pkg *" not in rules

    @pytest.mark.parametrize("group", ["sam-operator", "sam-pkg"])
    def test_runagent_is_not_granted(self, rules, group):
        # runagent executes arbitrary commands as root.
        for line in rules.splitlines():
            if f"%{group} " in line:
                assert "runagent" not in line
                assert "api-cli" not in line

    @pytest.mark.parametrize("group", ["sam-operator", "sam-pkg"])
    def test_every_rule_still_requires_a_password(self, rules, group):
        # sam-root is deliberately ALL=(ALL) ALL and is excluded.
        matched = [ln for ln in rules.splitlines() if ln.startswith(f"+%{group} ")]
        assert matched
        for line in matched:
            assert "PASSWD:" in line and "NOPASSWD" not in line


def test_wrapper_is_deployed_with_the_other_helpers():
    import inspect

    source = inspect.getsource(ssh.ensure_scripts)
    assert "(SAM_INSTALL_PKG, SAM_INSTALL_PKG_PATH)" in source
    assert ssh.SAM_INSTALL_PKG_PATH == "/usr/local/bin/sam-install-pkg"
