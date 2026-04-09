"""
Shared test fixtures for RelayKing test suite.
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field
from typing import Optional, List, Set

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Stub out heavy third-party packages so tests run without them installed.
# This block must execute BEFORE any RelayKing imports.
# ---------------------------------------------------------------------------

def _ensure_mock_module(name):
    """Insert a MagicMock for *name* into sys.modules if it isn't importable."""
    try:
        __import__(name)
    except ImportError:
        parts = name.split(".")
        for i in range(len(parts)):
            partial = ".".join(parts[: i + 1])
            if partial not in sys.modules:
                sys.modules[partial] = MagicMock()


# impacket tree
for _mod in [
    "impacket",
    "impacket.dcerpc",
    "impacket.dcerpc.v5",
    "impacket.dcerpc.v5.transport",
    "impacket.dcerpc.v5.rpcrt",
    "impacket.dcerpc.v5.rrp",
    "impacket.dcerpc.v5.rprn",
    "impacket.ldap",
    "impacket.ldap.ldap",
    "impacket.ldap.ldapasn1",
    "impacket.smbconnection",
    "impacket.tds",
    "impacket.ntlm",
    "impacket.smb",
    "impacket.smb3",
    "impacket.uuid",
    "impacket.dcerpc.v5.samr",
    "impacket.dcerpc.v5.epm",
    "impacket.dcerpc.v5.even",
    "impacket.dcerpc.v5.ndr",
    "impacket.dcerpc.v5.dtypes",
]:
    _ensure_mock_module(_mod)

# ldap3
for _mod in ["ldap3"]:
    _ensure_mock_module(_mod)

# requests / requests_ntlm / urllib3 / dnspython
for _mod in [
    "requests",
    "requests.exceptions",
    "requests_ntlm",
    "urllib3",
    "dns",
    "dns.resolver",
    "dns.rdatatype",
    "dns.query",
    "dns.message",
]:
    _ensure_mock_module(_mod)


# ---------------------------------------------------------------------------
# Lightweight config stand-in (mirrors RelayKingConfig fields used by auth.py)
# ---------------------------------------------------------------------------

@dataclass
class FakeConfig:
    """Minimal stand-in for RelayKingConfig that covers every field auth.py touches."""
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    lmhash: str = ''
    nthash: str = ''
    aesKey: Optional[str] = None
    use_kerberos: bool = False
    krb_dc_only: bool = False
    dc_ip: Optional[str] = None
    use_ldaps: bool = False
    null_auth: bool = False
    verbose: int = 0
    _dc_hostnames: Set[str] = field(default_factory=set)

    def should_use_kerberos(self, target: str) -> bool:
        if not self.krb_dc_only:
            return self.use_kerberos
        return target.lower() in self._dc_hostnames


@pytest.fixture
def password_config():
    """Config for standard password authentication."""
    return FakeConfig(
        username='lowpriv',
        password='Password1',
        domain='corp.local',
        dc_ip='10.0.0.1',
    )


@pytest.fixture
def pth_config():
    """Config for pass-the-hash authentication."""
    return FakeConfig(
        username='lowpriv',
        domain='corp.local',
        dc_ip='10.0.0.1',
        nthash='aabbccdd11223344aabbccdd11223344',
    )


@pytest.fixture
def kerberos_config():
    """Config for Kerberos authentication."""
    return FakeConfig(
        username='lowpriv',
        password='Password1',
        domain='corp.local',
        dc_ip='10.0.0.1',
        use_kerberos=True,
    )


@pytest.fixture
def null_config():
    """Config for null/anonymous authentication."""
    return FakeConfig(
        null_auth=True,
        domain='corp.local',
        dc_ip='10.0.0.1',
    )


@pytest.fixture
def ldaps_config():
    """Config for password auth forced over LDAPS."""
    return FakeConfig(
        username='lowpriv',
        password='Password1',
        domain='corp.local',
        dc_ip='10.0.0.1',
        use_ldaps=True,
    )


@pytest.fixture
def krb_dc_only_config():
    """Config with --krb-dc-only: Kerberos for DCs, NTLM for everything else."""
    cfg = FakeConfig(
        username='lowpriv',
        password='Password1',
        domain='corp.local',
        dc_ip='10.0.0.1',
        use_kerberos=True,
        krb_dc_only=True,
        _dc_hostnames={'dc01.corp.local'},
    )
    return cfg
