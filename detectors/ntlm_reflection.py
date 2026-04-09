"""
NTLM Reflection Detector
Identifies hosts vulnerable to CVE-2025-33073 (NTLM Reflection attack)
"""

from impacket.dcerpc.v5 import transport, rrp, rprn
from impacket.smbconnection import SessionError
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import threading
import time

from core.auth import configure_rpc_auth, connect_dce, is_kerberos_error


class NTLMReflectionDetector:
    """Detector for CVE-2025-33073 NTLM reflection vulnerability"""

    # Shared thread pool for registry checks (limit concurrent access to avoid SMB session exhaustion)
    _registry_pool = None
    _registry_pool_lock = threading.Lock()

    # Semaphore to limit concurrent DCE/RPC connections (max 2 concurrent)
    _dce_semaphore = threading.Semaphore(2)

    # Reference table from MSRC report
    # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073
    MSRC_PATCHES = {    # key = (major, minor, build), value = minimum patched UBR
        (6, 0, 6003): 23351,      # Windows Server 2008 SP2
        (6, 1, 7601): 27769,      # Windows Server 2008 R2 SP1
        (6, 2, 9200): 25522,      # Windows Server 2012
        (6, 3, 9600): 22620,      # Windows Server 2012 R2
        (10, 0, 14393): 8148,     # Windows Server 2016
        (10, 0, 17763): 7434,     # Windows Server 2019 / Win10 1809
        (10, 0, 20348): 3807,     # Windows Server 2022
        (10, 0, 19044): 5965,     # Windows 10 21H2
        (10, 0, 22621): 5472,     # Windows 11 22H2
        (10, 0, 26100): 6584,     # Windows Server 2025 / Windows 11 24H2 (CVE-2025-54918)
    }

    # Minimum patched UBR for CVE-2019-1040 (Drop the MIC)
    # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040
    # Patched by June 11, 2019 Patch Tuesday cumulative updates
    CVE_2019_1040_PATCHES = {   # key = (major, minor, build), value = minimum patched UBR
        (10, 0, 10240): 18244,   # Windows 10 1507 (KB4503291)
        (10, 0, 14393): 3025,    # Windows Server 2016 / Win10 1607 (KB4503267)
        (10, 0, 15063): 1868,    # Windows 10 1703 (KB4503279)
        (10, 0, 16299): 1217,    # Windows 10 1709 (KB4503284)
        (10, 0, 17134): 829,     # Windows 10 1803 (KB4503286)
        (10, 0, 17763): 557,     # Windows Server 2019 / Win10 1809 (KB4503327)
        (10, 0, 18362): 175,     # Windows 10 1903 (KB4503293)
        # Builds >= 18363 (Win10 1909+) shipped after June 2019 patch - not affected
    }

    def __init__(self, config):
        self.config = config

        # Initialize shared thread pool for registry checks (lazy initialization)
        # Limit to 3 workers to avoid SMB session exhaustion on target hosts
        with self._registry_pool_lock:
            if NTLMReflectionDetector._registry_pool is None:
                NTLMReflectionDetector._registry_pool = ThreadPoolExecutor(
                    max_workers=3,
                    thread_name_prefix="ntlm_reflection_registry"
                )

    def analyze(self, protocol_results: dict, target: str) -> dict:
        """
        Analyze protocol results to identify CVE-2025-33073 vulnerability

        CVE-2025-33073 (NTLM Reflection) allows relaying FROM SMB TO other protocols
        based on unpatched Windows versions.

        Args:
            protocol_results: dict of protocol -> ProtocolResult
            target: hostname/IP of the target

        Returns:
            dict with 'vulnerable' bool, 'paths' list, and optional 'details'
        """
        result = {
            'vulnerable': False,
            'paths': [],
            'details': None
        }

        # Check if SMB is available
        if 'smb' not in protocol_results:
            return result

        smb_result = protocol_results['smb']
        if not smb_result.available:
            return result

        # Check if this is a Windows host
        server_os = smb_result.additional_info.get('server_os', '').lower()
        if not ('windows' in server_os or not server_os):
            # Not Windows - not vulnerable
            return result

        # Get Windows version from SMB connection (already available)
        major = smb_result.additional_info.get('server_os_major')
        minor = smb_result.additional_info.get('server_os_minor')
        build = smb_result.additional_info.get('server_os_build')

        if major is None or build is None:
            # Can't determine version - not enough info
            if self.config.verbose >= 2:
                print(f"[!] Could not get version from SMB on {target} (major={major}, build={build})")
            return result

        # Try to get UBR from registry with retry logic (up to 2 retries)
        ubr = None
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                future = self._registry_pool.submit(self._get_ubr_from_registry, target)
                # Wait up to 10 seconds for registry read
                ubr = future.result(timeout=10.0)

                if ubr is not None:
                    break  # Success!

                # UBR was None - retry if we have attempts left
                if attempt < max_retries:
                    if self.config.verbose >= 3:
                        print(f"[!] UBR check returned None on {target}, retrying ({attempt + 1}/{max_retries})...")
                    time.sleep(0.5)  # Brief delay before retry
                    continue

            except FuturesTimeoutError:
                if attempt < max_retries:
                    if self.config.verbose >= 3:
                        print(f"[!] Registry check timed out on {target}, retrying ({attempt + 1}/{max_retries})...")
                    time.sleep(0.5)
                    continue
                else:
                    if self.config.verbose >= 2:
                        print(f"[!] Registry check timed out on {target} after {max_retries + 1} attempts")
                    return result

            except Exception as e:
                if attempt < max_retries:
                    if self.config.verbose >= 3:
                        print(f"[!] Registry check failed on {target}, retrying ({attempt + 1}/{max_retries}): {e}")
                    time.sleep(0.5)
                    continue
                else:
                    if self.config.verbose >= 3:
                        print(f"[!] Registry check failed on {target} after {max_retries + 1} attempts: {e}")
                    return result

        if ubr is None:
            if self.config.verbose >= 2:
                print(f"[!] Could not get UBR from registry on {target} after {max_retries + 1} attempts")
            return result

        # Check if vulnerable based on version
        is_vulnerable = self._is_vulnerable(major, minor or 0, build, ubr)

        if self.config.verbose >= 2:
            print(f"[*] NTLM reflection check for {target}: version=({major}, {minor or 0}, {build}), ubr={ubr}, vulnerable={is_vulnerable}")

        # CVE-2025-54918: any unpatched Server 2025 host is at least MEDIUM.
        # If it is also a DC with PrintSpooler enabled → CRITICAL.
        if major == 10 and minor == 0 and build == 26100 and ubr < 6584:
            is_dc = self.config.is_dc(target)
            printspooler_enabled = False

            if is_dc:
                if self.config.verbose >= 2:
                    print(f"[*] CVE-2025-54918: Server 2025 DC detected on {target} (build {build}.{ubr}) - checking PrintSpooler")
                printspooler_enabled = self._check_printspooler_enabled(target)
                if self.config.verbose >= 2:
                    state = "enabled" if printspooler_enabled else "not enabled/accessible"
                    print(f"[*] CVE-2025-54918: PrintSpooler on {target} is {state}")
            else:
                if self.config.verbose >= 2:
                    print(f"[*] CVE-2025-54918: Server 2025 non-DC host {target} (build {build}.{ubr}) is unpatched")

            result['cve_2025_54918'] = {
                'vulnerable': True,
                'is_dc': is_dc,
                'build': f"{major}.{minor}.{build}.{ubr}",
                'printspooler_enabled': printspooler_enabled,
            }

            if self.config.verbose >= 1:
                if is_dc and printspooler_enabled:
                    print(f"[!] {target}: CVE-2025-54918 CRITICAL - Server 2025 DC with PrintSpooler enabled (build {build}.{ubr})")
                else:
                    role = "DC" if is_dc else "host"
                    print(f"[!] {target}: CVE-2025-54918 MEDIUM - Server 2025 {role} unpatched (build {build}.{ubr})")

        # CVE-2019-1040 (Drop the MIC): check all Windows hosts against patch table
        cve_1040_vulnerable = self._is_vulnerable_cve2019_1040(major, minor or 0, build, ubr)
        if cve_1040_vulnerable:
            result['cve_2019_1040'] = {
                'vulnerable': True,
                'build': f"{major}.{minor or 0}.{build}.{ubr}",
            }
            if self.config.verbose >= 1:
                print(f"[!] {target}: CVE-2019-1040 (Drop the MIC) - Windows {major}.{minor or 0}.{build}.{ubr} is unpatched")

        if is_vulnerable:
            result['vulnerable'] = True

            # Determine what can be relayed to
            smb_signing_required = smb_result.signing_required

            # Build list of available protocols that can be relayed to
            # CVE-2025-33073 allows relaying FROM SMB TO other protocols if unpatched
            # The vulnerability is CLIENT-SIDE, so we list all available destination protocols
            available_protocols = []
            for proto_name, proto_result in protocol_results.items():
                # Skip non-protocol entries (webdav, ntlm_reflection, etc.)
                if not hasattr(proto_result, 'available'):
                    continue

                # Only list available protocols (vulnerability allows relay regardless of server protections)
                if not proto_result.available:
                    continue

                if proto_name == 'smb':
                    # SMB: Can relay to SMB if source SMB signing is not required
                    if not smb_signing_required:
                        available_protocols.append('SMB')
                elif proto_name in ['http', 'https', 'ldap', 'ldaps', 'mssql', 'smtp', 'imap', 'imaps']:
                    # All other protocols: add if available (client vuln bypasses server protections)
                    available_protocols.append(proto_name.upper())

            result['paths'] = available_protocols

            if not smb_signing_required:
                # Can relay SMB to ANY protocol
                result['details'] = (
                    f"VULNERABLE to CVE-2025-33073: Can relay SMB to any protocol. "
                    f"Windows version {major}.{minor}.{build}.{ubr} is unpatched and SMB signing is not required."
                )
            else:
                # Can relay SMB to other protocols except SMB
                result['details'] = (
                    f"VULNERABLE to CVE-2025-33073: Can relay SMB to other protocols except SMB. "
                    f"Windows version {major}.{minor}.{build}.{ubr} is unpatched (SMB signing is required)."
                )
        elif is_vulnerable is False:
            # Patched - not vulnerable
            result['vulnerable'] = False
            result['details'] = f"Not vulnerable - Windows version {major}.{minor}.{build}.{ubr} is patched"
        else:
            # Unknown version - cannot determine
            result['vulnerable'] = False
            result['details'] = f"Cannot determine - Windows version {major}.{minor}.{build}.{ubr} not in MSRC patch table"

        return result

    def _get_ubr_from_registry(self, target: str) -> int:
        """
        Get UBR (Update Build Revision) from remote registry
        Returns UBR as int or None

        Uses semaphore to limit concurrent DCE/RPC connections
        """

        # Acquire semaphore with timeout (wait max 5 seconds for slot)
        acquired = self._dce_semaphore.acquire(timeout=5.0)
        if not acquired:
            if self.config.verbose >= 3:
                print(f"[!] Could not acquire DCE/RPC semaphore for {target} (too busy)")
            return None

        try:
            try:
                # Create RPC transport over SMB named pipe
                rpc = transport.DCERPCTransportFactory(f"ncacn_np:{target}[\\pipe\\winreg]")
                use_kerberos = configure_rpc_auth(self.config, rpc, target)

                # Connect and bind to winreg
                try:
                    dce = connect_dce(rpc, use_kerberos, rrp.MSRPC_UUID_RRP)
                except Exception as conn_err:
                    if is_kerberos_error(conn_err):
                        if self.config.verbose >= 3:
                            print(f"[!] Kerberos auth failed for UBR check on {target}: {conn_err}")
                        return None
                    raise

                # Open HKLM
                hRootKey = rrp.hOpenLocalMachine(dce)["phKey"]

                # Open CurrentVersion key
                hKey = rrp.hBaseRegOpenKey(
                    dce,
                    hRootKey,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                )["phkResult"]

                # Read UBR value
                ubr = rrp.hBaseRegQueryValue(dce, hKey, "UBR")[1]

                # Close connection
                dce.disconnect()

                if self.config.verbose >= 3:
                    print(f"[*] Got UBR from {target}: {ubr}")

                return ubr

            except SessionError as e:
                error_str = str(e)
                if self.config.verbose >= 3:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" in error_str:
                        print(f"[!] UBR key not found on {target} (old Windows version)")
                    elif "STATUS_PIPE_NOT_AVAILABLE" in error_str:
                        print(f"[!] RemoteRegistry service not running on {target}")
                    else:
                        print(f"[!] Registry access error on {target}: {e}")
                return None

            except Exception as e:
                if self.config.verbose >= 3:
                    print(f"[!] Failed to read registry from {target}: {type(e).__name__}: {e}")
                return None

        finally:
            # Always release semaphore
            self._dce_semaphore.release()

    def _check_printspooler_enabled(self, target: str) -> bool:
        """
        Check if PrintSpooler service is enabled via RPC over TCP
        Returns True if PrintSpooler is enabled, False otherwise

        Uses RPC over TCP (ncacn_ip_tcp) as required for Server 2025
        """

        # Acquire semaphore with timeout (wait max 5 seconds for slot)
        acquired = self._dce_semaphore.acquire(timeout=5.0)
        if not acquired:
            if self.config.verbose >= 3:
                print(f"[!] Could not acquire DCE/RPC semaphore for PrintSpooler check on {target} (too busy)")
            return False

        try:
            try:
                # Build RPC over TCP connection string
                # First try to use port 135 for endpoint mapper
                stringbinding = f'ncacn_ip_tcp:{target}'

                if self.config.verbose >= 3:
                    print(f"[*] Checking PrintSpooler on {target} via RPC over TCP")

                # Create RPC transport and set credentials
                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                use_kerberos = configure_rpc_auth(self.config, rpctransport, target)

                # Get DCE/RPC connection
                dce = rpctransport.get_dce_rpc()

                # Set Kerberos auth if needed
                if use_kerberos:
                    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE as _GSS
                    dce.set_auth_type(_GSS)

                # Connect
                try:
                    dce.connect()
                except Exception as conn_err:
                    if is_kerberos_error(conn_err):
                        if self.config.verbose >= 3:
                            print(f"[!] Kerberos auth failed for PrintSpooler check on {target}: {conn_err}")
                        return False
                    raise

                # Bind to Print Spooler interface (MS-RPRN)
                try:
                    dce.bind(rprn.MSRPC_UUID_RPRN)

                    if self.config.verbose >= 3:
                        print(f"[+] PrintSpooler is enabled on {target}")

                    # Disconnect and return success
                    dce.disconnect()
                    return True

                except Exception as bind_err:
                    error_str = str(bind_err).upper()
                    if 'ACCESS_DENIED' in error_str:
                        if self.config.verbose >= 3:
                            print(f"[!] PrintSpooler check on {target}: Access denied")
                        dce.disconnect()
                        return False
                    elif 'RPC_S_SERVER_UNAVAILABLE' in error_str:
                        if self.config.verbose >= 3:
                            print(f"[!] PrintSpooler service not available on {target}")
                        dce.disconnect()
                        return False
                    else:
                        # Unknown error during bind
                        if self.config.verbose >= 3:
                            print(f"[!] PrintSpooler bind error on {target}: {bind_err}")
                        dce.disconnect()
                        return False

            except Exception as e:
                if self.config.verbose >= 3:
                    print(f"[!] Failed to check PrintSpooler on {target}: {type(e).__name__}: {e}")
                return False

        finally:
            # Always release semaphore
            self._dce_semaphore.release()

    def _is_vulnerable(self, major: int, minor: int, build: int, ubr: int) -> bool:
        """
        Check if Windows version is vulnerable to CVE-2025-33073

        Returns:
            True if vulnerable, False if patched, None if unknown
        """
        key = (major, minor, build)
        min_patched_ubr = self.MSRC_PATCHES.get(key)

        if min_patched_ubr is None:
            return None  # Unknown product

        if ubr is None:
            return None

        return ubr < min_patched_ubr

    def _is_vulnerable_cve2019_1040(self, major: int, minor: int, build: int, ubr: int) -> bool:
        """
        Check if Windows version is vulnerable to CVE-2019-1040 (Drop the MIC).

        Returns:
            True if vulnerable, False if patched or unknown build
        """
        if ubr is None:
            return False
        key = (major, minor, build)
        min_patched_ubr = self.CVE_2019_1040_PATCHES.get(key)
        if min_patched_ubr is None:
            return False  # Unknown or not in affected range
        return ubr < min_patched_ubr
