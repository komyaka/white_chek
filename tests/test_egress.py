"""
Unit tests for egress module: backend selection, iptables check, Docker
availability check, and mandatory CIDR behaviour.
"""
from __future__ import annotations

import platform
import subprocess
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from whitelistchecker.egress import (
    EgressError,
    _check_docker_available,
    _check_iptables_available,
    _docker_command,
    _select_enforced_backend,
    apply_egress_whitelist,
)


# ---------------------------------------------------------------------------
# _check_iptables_available
# ---------------------------------------------------------------------------

def test_iptables_available_when_which_returns_path():
    with patch("whitelistchecker.egress.shutil.which", return_value="/sbin/iptables"):
        assert _check_iptables_available() is True


def test_iptables_unavailable_when_which_returns_none():
    with patch("whitelistchecker.egress.shutil.which", return_value=None):
        assert _check_iptables_available() is False


# ---------------------------------------------------------------------------
# _docker_command / _check_docker_available
# ---------------------------------------------------------------------------

def test_docker_command_returns_docker_if_present():
    def _which(cmd):
        return "/usr/bin/docker" if cmd == "docker" else None

    with patch("whitelistchecker.egress.shutil.which", side_effect=_which):
        assert _docker_command() == "docker"


def test_docker_command_returns_podman_if_docker_absent():
    def _which(cmd):
        return "/usr/bin/podman" if cmd == "podman" else None

    with patch("whitelistchecker.egress.shutil.which", side_effect=_which):
        assert _docker_command() == "podman"


def test_docker_command_returns_none_if_neither_present():
    with patch("whitelistchecker.egress.shutil.which", return_value=None):
        assert _docker_command() is None


def test_docker_available_true_when_info_succeeds():
    with patch("whitelistchecker.egress.shutil.which", return_value="/usr/bin/docker"):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("whitelistchecker.egress.subprocess.run", return_value=mock_result):
            assert _check_docker_available() is True


def test_docker_available_false_when_info_fails():
    with patch("whitelistchecker.egress.shutil.which", return_value="/usr/bin/docker"):
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("whitelistchecker.egress.subprocess.run", return_value=mock_result):
            assert _check_docker_available() is False


def test_docker_available_false_when_command_not_found():
    with patch("whitelistchecker.egress.shutil.which", return_value=None):
        assert _check_docker_available() is False


# ---------------------------------------------------------------------------
# _select_enforced_backend
# ---------------------------------------------------------------------------

def test_enforced_backend_linux_native_when_iptables_available():
    with patch("whitelistchecker.egress.platform.system", return_value="Linux"):
        with patch("whitelistchecker.egress._check_iptables_available", return_value=True):
            assert _select_enforced_backend("native") == "iptables"


def test_enforced_backend_linux_fails_when_iptables_missing():
    with patch("whitelistchecker.egress.platform.system", return_value="Linux"):
        with patch("whitelistchecker.egress._check_iptables_available", return_value=False):
            with pytest.raises(EgressError, match="iptables is not available"):
                _select_enforced_backend("native")


def test_enforced_backend_windows_docker_when_available():
    with patch("whitelistchecker.egress.platform.system", return_value="Windows"):
        with patch("whitelistchecker.egress._check_docker_available", return_value=True):
            assert _select_enforced_backend("native") == "docker"


def test_enforced_backend_windows_fails_when_docker_missing():
    with patch("whitelistchecker.egress.platform.system", return_value="Windows"):
        with patch("whitelistchecker.egress._check_docker_available", return_value=False):
            with pytest.raises(EgressError, match="Docker is not available on Windows"):
                _select_enforced_backend("native")


def test_enforced_backend_explicit_docker_fails_when_unavailable():
    with patch("whitelistchecker.egress.platform.system", return_value="Linux"):
        with patch("whitelistchecker.egress._check_docker_available", return_value=False):
            with pytest.raises(EgressError, match="docker.*requested but Docker is not available"):
                _select_enforced_backend("docker")


def test_enforced_backend_explicit_docker_succeeds_when_available():
    with patch("whitelistchecker.egress.platform.system", return_value="Linux"):
        with patch("whitelistchecker.egress._check_docker_available", return_value=True):
            assert _select_enforced_backend("docker") == "docker"


def test_enforced_backend_unsupported_os_raises():
    with patch("whitelistchecker.egress.platform.system", return_value="FreeBSD"):
        with patch("whitelistchecker.egress._check_iptables_available", return_value=True):
            with pytest.raises(EgressError, match="no suitable backend"):
                _select_enforced_backend("native")


# ---------------------------------------------------------------------------
# apply_egress_whitelist – off mode
# ---------------------------------------------------------------------------

def test_off_mode_requires_allow_off_flag():
    with pytest.raises(EgressError, match="--egress-allow-off"):
        with apply_egress_whitelist([], mode="off", allow_off=False):
            pass


def test_off_mode_succeeds_with_allow_off():
    executed = []
    with apply_egress_whitelist([], mode="off", allow_off=True):
        executed.append(True)
    assert executed == [True]


# ---------------------------------------------------------------------------
# apply_egress_whitelist – unsupported mode
# ---------------------------------------------------------------------------

def test_unsupported_mode_raises():
    with pytest.raises(EgressError, match="Unsupported egress mode"):
        with apply_egress_whitelist([], mode="invalid_mode", allow_off=False):
            pass


# ---------------------------------------------------------------------------
# apply_egress_whitelist – iptables mode (mocked)
# ---------------------------------------------------------------------------

def test_iptables_mode_runs_body_and_restores(tmp_path):
    backup_file = tmp_path / "rules"
    backup_file.write_text("")

    calls = []

    def _fake_run(cmd):
        calls.append(cmd)
        if cmd[0] == "iptables-save":
            return "# rules"
        return ""

    executed = []
    with patch("whitelistchecker.egress._check_iptables_available", return_value=True):
        with patch("whitelistchecker.egress._run", side_effect=_fake_run):
            with apply_egress_whitelist(["10.0.0.0/8"], mode="iptables"):
                executed.append(True)

    assert executed == [True]
    # iptables-save must have been called
    assert any(c[0] == "iptables-save" for c in calls)
    # iptables-restore must have been called
    assert any(c[0] == "iptables-restore" for c in calls)


def test_iptables_mode_fails_when_iptables_missing():
    with patch("whitelistchecker.egress._check_iptables_available", return_value=False):
        with pytest.raises(EgressError, match="iptables is not available"):
            with apply_egress_whitelist(["10.0.0.0/8"], mode="iptables"):
                pass


# ---------------------------------------------------------------------------
# apply_egress_whitelist – enforced mode delegates correctly (mocked)
# ---------------------------------------------------------------------------

def test_enforced_mode_delegates_to_iptables_on_linux(tmp_path):
    """enforced on Linux with iptables available should use iptables backend."""

    @contextmanager
    def _fake_iptables(cidrs):
        yield

    with patch("whitelistchecker.egress.platform.system", return_value="Linux"):
        with patch("whitelistchecker.egress._check_iptables_available", return_value=True):
            with patch("whitelistchecker.egress._apply_iptables_egress", _fake_iptables) as m:
                executed = []
                with apply_egress_whitelist(["10.0.0.0/8"], mode="enforced"):
                    executed.append(True)
                assert executed == [True]


def test_enforced_mode_delegates_to_docker_on_windows():
    """enforced on Windows with Docker available should use docker backend."""

    @contextmanager
    def _fake_docker(cidrs):
        yield

    with patch("whitelistchecker.egress.platform.system", return_value="Windows"):
        with patch("whitelistchecker.egress._check_docker_available", return_value=True):
            with patch("whitelistchecker.egress._apply_docker_egress", _fake_docker):
                executed = []
                with apply_egress_whitelist(["10.0.0.0/8"], mode="enforced"):
                    executed.append(True)
                assert executed == [True]
