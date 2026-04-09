"""
NTLMv1 Detector
Detects NTLMv1 support via GPO (domain-wide) and registry (per-host)
"""

from impacket.dcerpc.v5 import transport, rrp
from core.auth import connect_ldap, get_base_dn, is_kerberos_error, configure_rpc_auth, connect_dce


class NTLMv1Detector:
    """Detector for NTLMv1 support"""

    # LmCompatibilityLevel values
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
    LM_COMPAT_LEVELS = {
        0: "Send LM & NTLM responses",  # NTLMv1 enabled
        1: "Send LM & NTLM - use NTLMv2 session security if negotiated",  # NTLMv1 enabled
        2: "Send NTLM response only",  # NTLMv1 enabled
        3: "Send NTLMv2 response only",  # NTLMv2 only
        4: "Send NTLMv2 response only. Refuse LM",  # NTLMv2 only
        5: "Send NTLMv2 response only. Refuse LM & NTLM",  # NTLMv2 only
    }

    def __init__(self, config):
        self.config = config
        self.gpo_ntlmv1_enabled = None
        self.vulnerable_hosts = {}

    def check_gpo(self, dc_host: str) -> dict:
        """
        Check GPO for domain-wide NTLMv1 policy

        Returns dict with:
            - enabled: bool (True if NTLMv1 is allowed by GPO)
            - level: int (LmCompatibilityLevel value)
            - details: str (explanation)
        """
        result = {
            'enabled': False,
            'level': None,
            'details': None,
            'error': None
        }

        try:
            # Query LDAP for GPO settings
            # The LmCompatibilityLevel can be set via GPO at:
            # Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
            # "Network security: LAN Manager authentication level"

            try:
                ldap_conn, _, _ = connect_ldap(self.config, dc_host)
            except Exception as e:
                if is_kerberos_error(e):
                    result['error'] = f'Kerberos auth failed: {e}'
                    return result
                raise

            # Search for GPO objects with NTLMv1 settings
            # Look in Default Domain Policy and Default Domain Controllers Policy
            search_filter = "(objectClass=groupPolicyContainer)"

            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            resp = ldap_conn.search(
                searchBase=f"CN=Policies,CN=System,{self._get_base_dn()}",
                searchFilter=search_filter,
                attributes=['displayName', 'gPCFileSysPath'],
                scope=ldapasn1_impacket.Scope('wholeSubtree')
            )

            # Note: Actually reading the GPO files from SYSVOL would be complex
            # For now, we'll try to read the registry value from the DC itself
            # as a proxy for the domain policy

            if self.config.verbose >= 2:
                print(f"[*] Checking DC registry for domain NTLMv1 policy...")

            level = self._get_lm_compat_level(dc_host)

            if level is not None:
                result['level'] = level
                result['enabled'] = (level <= 2)  # Levels 0-2 allow NTLMv1
                result['details'] = self.LM_COMPAT_LEVELS.get(level, f"Unknown level: {level}")

                if result['enabled']:
                    result['note'] = (
                        "NTLMv1 is enabled domain-wide. LDAP signing/channel binding can be bypassed "
                        "using --remove-mic in ntlmrelayx. Test with: "
                        "ntlmrelayx.py -t ldaps://dc --remove-mic --escalate-user lowpriv"
                    )
            else:
                result['error'] = "Could not determine LmCompatibilityLevel"

        except Exception as e:
            result['error'] = str(e)

        return result

    def check_host_registry(self, host: str) -> dict:
        """
        Check a specific host's registry for NTLMv1 support

        Returns dict with:
            - enabled: bool (True if NTLMv1 is supported)
            - level: int (LmCompatibilityLevel value)
            - details: str (explanation)
        """
        result = {
            'enabled': False,
            'level': None,
            'details': None,
            'error': None
        }

        try:
            level = self._get_lm_compat_level(host)

            if level is not None:
                result['level'] = level
                result['enabled'] = (level <= 2)  # Levels 0-2 allow NTLMv1
                result['details'] = self.LM_COMPAT_LEVELS.get(level, f"Unknown level: {level}")
            else:
                result['error'] = "Could not read LmCompatibilityLevel from registry"

        except Exception as e:
            result['error'] = str(e)

        return result

    def _get_lm_compat_level(self, host: str) -> int:
        """
        Read LmCompatibilityLevel from remote registry

        Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel
        Default value if not set: 3 (Send NTLMv2 response only)
        """
        try:
            # Create RPC transport over SMB
            rpc = transport.DCERPCTransportFactory(f"ncacn_np:{host}[\\pipe\\winreg]")
            use_kerberos = configure_rpc_auth(self.config, rpc, host)

            # Connect and bind
            try:
                dce = connect_dce(rpc, use_kerberos, rrp.MSRPC_UUID_RRP)
            except Exception as conn_err:
                if is_kerberos_error(conn_err):
                    if self.config.verbose >= 2:
                        print(f"[!] Kerberos auth failed for registry access to {host}: {conn_err}")
                    return None
                raise

            # Read LmCompatibilityLevel from registry
            hRootKey = rrp.hOpenLocalMachine(dce)["phKey"]
            hKey = rrp.hBaseRegOpenKey(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Control\\Lsa")["phkResult"]

            try:
                level = rrp.hBaseRegQueryValue(dce, hKey, "LmCompatibilityLevel")[1]
                dce.disconnect()

                if self.config.verbose >= 2:
                    print(f"[*] LmCompatibilityLevel from {host}: {level}")

                return level
            except:
                # Key doesn't exist - return default value
                dce.disconnect()
                if self.config.verbose >= 2:
                    print(f"[*] LmCompatibilityLevel not set on {host}, using default (3)")
                return 3  # Default is 3 (NTLMv2 only)

        except Exception as e:
            if self.config.verbose >= 3:
                print(f"[!] Failed to read LmCompatibilityLevel from {host}: {e}")
            return None

    def _get_base_dn(self) -> str:
        """Convert domain to base DN"""
        return get_base_dn(self.config.domain)
