from __future__ import annotations
import subprocess
import tempfile
from contextlib import contextmanager
from typing import List, Optional

class EgressError(RuntimeError):
    pass


def _run(cmd: List[str]):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise EgressError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
    return res.stdout


@contextmanager
def apply_egress_whitelist(cidrs: List[str], mode: str = "iptables"):
    if mode == "off":
        yield
        return

    if mode == "iptables":
        with tempfile.NamedTemporaryFile("w+") as backup:
            # backup current rules
            backup.write(_run(["iptables-save"]))
            backup.flush()
            try:
                _run(["iptables", "-P", "OUTPUT", "DROP"])
                _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
                _run(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
                for dns in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]:
                    _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-d", dns, "-j", "ACCEPT"])
                    _run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-d", dns, "-j", "ACCEPT"])
                for cidr in cidrs:
                    _run(["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"])
                yield
            finally:
                _run(["iptables-restore", backup.name])
        return

    if mode == "linux-netns":
        # simplified: fallback to iptables in current ns for now
        with apply_egress_whitelist(cidrs, mode="iptables"):
            yield
        return

    raise EgressError(f"Unsupported egress mode: {mode}")
