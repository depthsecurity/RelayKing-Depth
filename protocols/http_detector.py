"""
HTTP/HTTPS Protocol Detector
Detects EPA (Extended Protection for Authentication) and NTLM-enabled paths
Based on RelayInformer EPA detection logic for accurate HTTPS EPA testing
"""

import requests
import os
import socket
import ssl
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base_detector import BaseDetector, ProtocolResult

# Try to import requests-ntlm for EPA testing
try:
    from requests_ntlm import HttpNtlmAuth
    REQUESTS_NTLM_AVAILABLE = True
except ImportError:
    REQUESTS_NTLM_AVAILABLE = False


class CustomAvHttpNtlmAuth(HttpNtlmAuth):
    """
    HttpNtlmAuth subclass that allows overriding the server certificate hash
    for EPA (Extended Protection for Authentication) testing.
    Based on RelayInformer's implementation.
    """

    def __init__(
        self,
        username: str,
        password: str,
        send_cbt: bool = True,
        custom_cert_hash: bytes = None,
    ):
        """Create an authentication handler with optional custom certificate hash.

        :param str username: Username in 'domain\\username' format
        :param str password: Password
        :param bool send_cbt: Will send the channel bindings over a HTTPS channel (Default: True)
        :param bytes custom_cert_hash: Custom certificate hash to use instead of the server's actual certificate
        """
        super().__init__(username, password, send_cbt=send_cbt)
        self.custom_cert_hash = custom_cert_hash

    def _get_server_cert(self, response):
        """
        Override to return custom certificate hash if provided, otherwise use parent implementation.
        """
        if self.custom_cert_hash is not None:
            return self.custom_cert_hash
        return super()._get_server_cert(response)


class HTTPDetector(BaseDetector):
    """Detector for HTTP/HTTPS protocols with comprehensive path enumeration"""

    # SCCM-specific paths to check
    SCCM_PATHS = [
        '/ccm_system_windowsauth/request',
        '/sms_mp/.sms_aut',
    ]

    def detect(self, host: str, port: int = 80, use_ssl: bool = False) -> ProtocolResult:
        """
        Detect HTTP/HTTPS configuration

        If HTTP/HTTPS is explicitly requested (--protocols includes http/https),
        performs comprehensive path enumeration using web_ntlm_paths.dict
        Otherwise, only checks root path and SCCM paths (for high-value targets)

        For HTTPS with credentials: Tests actual EPA enforcement via NTLM auth
        For HTTP: Always marks as relayable (no channel binding possible)
        """
        protocol = 'https' if use_ssl else 'http'
        result = self._create_result(protocol, host, port)

        # Disable SSL warnings for self-signed certs
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            # First, check if a web server is actually listening before doing any enumeration
            if not self._check_connectivity(host, port, use_ssl):
                # No web server listening - skip all checks
                return result

            # Determine if this is comprehensive scanning (explicit --protocols http/https)
            # or targeted scanning (auto-detected high-value target)
            comprehensive_scan = self._is_comprehensive_scan()

            if comprehensive_scan:
                # Full path enumeration with wordlist
                ntlm_paths = self._enumerate_ntlm_paths(host, port, use_ssl)
            else:
                # Minimal check: root + SCCM paths only
                ntlm_paths = self._check_basic_paths(host, port, use_ssl)

            if ntlm_paths:
                result.available = True
                result.additional_info['ntlm_enabled'] = True
                result.additional_info['ntlm_paths'] = ntlm_paths

                # Check for ADCS. Validate against catchall NTLM web apps that
                # 401 every URL (which would otherwise match /certsrv/ too).
                if any('/certsrv' in path.lower() for path in ntlm_paths):
                    scheme = 'https' if use_ssl else 'http'
                    if self._is_catchall_ntlm(host, port, scheme) is False:
                        result.additional_info['is_adcs'] = True
                        result.additional_info['adcs_method'] = 'certsrv endpoint (validated)'
                    else:
                        result.additional_info['adcs_unconfirmed'] = True

                # Check for SCCM
                if any('ccm_system_windowsauth' in path.lower() or 'sms_mp' in path.lower() for path in ntlm_paths):
                    result.additional_info['is_sccm'] = True
                    result.additional_info['sccm_method'] = 'SCCM auth endpoint'

                # EPA detection
                if use_ssl:
                    # Get TLS version
                    tls_version = self._get_tls_version(host, port)
                    if tls_version:
                        result.version = tls_version
                        result.channel_binding = (tls_version in ['TLSv1.2', 'TLSv1.3'])

                    # For HTTPS, we need to test EPA with credentials
                    if self.config.null_auth:
                        # Cannot test EPA without credentials
                        result.epa_enforced = None  # Unknown
                        result.additional_info['epa_note'] = 'EPA cannot be tested without credentials (--null-auth mode)'
                    elif not REQUESTS_NTLM_AVAILABLE:
                        # requests-ntlm not available
                        result.epa_enforced = None  # Unknown
                        result.additional_info['epa_note'] = 'requests-ntlm not installed - cannot test EPA'
                    else:
                        # Test EPA using RelayInformer-style detection
                        # Use the first NTLM-enabled path for testing
                        test_path = ntlm_paths[0]
                        epa_result = self._test_https_epa(host, port, test_path)

                        if epa_result == 'NOT_ENFORCED':
                            result.epa_enforced = False
                            result.additional_info['epa_note'] = 'EPA not enforced - RELAYABLE'
                        elif epa_result == 'ENFORCED':
                            result.epa_enforced = True
                            result.additional_info['epa_note'] = 'EPA enforced - channel binding required'
                        elif epa_result == 'WHEN_SUPPORTED':
                            # EPA set to "when supported" - relayable by attackers who don't send CBT
                            result.epa_enforced = False
                            result.additional_info['epa_note'] = 'EPA set to "when supported" - RELAYABLE (attackers can omit CBT)'
                        else:
                            # Couldn't determine
                            result.epa_enforced = None
                            result.additional_info['epa_note'] = f'EPA status unknown: {epa_result}'
                else:
                    # HTTP (plain text) - EPA is impossible (no TLS channel)
                    # HTTP with NTLM is ALWAYS relayable
                    result.epa_enforced = False
                    result.channel_binding = False
                    result.additional_info['epa_note'] = 'Plain HTTP - no EPA possible, always relayable'

            else:
                # No NTLM-enabled paths found
                result.available = False
                result.error = 'No NTLM-enabled paths found'

        except Exception as e:
            result.error = str(e)

        return result

    def _test_https_epa(self, host: str, port: int, path: str) -> str:
        """
        Test HTTPS EPA enforcement using RelayInformer-style detection.

        Logic (based on RelayInformer):
        1. Try with correct/real CBT - should succeed if creds are valid
        2. Try with bogus CBT - if this fails with 401 but #1 succeeded, EPA is enforced
        3. Try with missing CBT - if this succeeds, EPA is "never" or "when supported"

        Returns:
            'NOT_ENFORCED' - EPA not enforced, relayable
            'ENFORCED' - EPA enforced, not relayable
            'WHEN_SUPPORTED' - EPA set to "when supported", relayable
            'AUTH_FAILED' - Authentication failed (bad creds)
            'ERROR' - Could not determine
        """
        url = f"https://{host}:{port}{path}"

        username = f"{self.config.domain}\\{self.config.username}" if self.config.domain else self.config.username
        password = self.config.password

        # Handle hash authentication
        if not password and self.config.nthash:
            # Pass-the-hash: format as LM:NT for requests-ntlm/pyspnego
            lmhash = self.config.lmhash or 'aad3b435b51404eeaad3b435b51404ee'
            password = f"{lmhash}:{self.config.nthash}"

        try:
            session = requests.Session()

            # Test 1: Try with real/correct CBT (send_cbt=True, no custom hash)
            auth_handler = CustomAvHttpNtlmAuth(username, password, send_cbt=True, custom_cert_hash=None)
            session.auth = auth_handler

            response = session.get(url, verify=False, timeout=self._get_timeout())

            if response.status_code == 401:
                # Auth failed even with correct CBT - bad credentials
                return 'AUTH_FAILED'
            elif response.status_code != 200:
                # Unexpected response, but not a failure
                pass

            # Test 2: Try with bogus CBT
            session2 = requests.Session()
            bogus_cbt = b'\x00' * 73  # Bogus channel binding token (wrong hash)
            auth_handler2 = CustomAvHttpNtlmAuth(username, password, send_cbt=True, custom_cert_hash=bogus_cbt)
            session2.auth = auth_handler2

            response2 = session2.get(url, verify=False, timeout=self._get_timeout())

            if response2.status_code == 401:
                # Bogus CBT was rejected - EPA is enforced
                return 'ENFORCED'

            # Test 3: Try with no CBT (send_cbt=False)
            session3 = requests.Session()
            auth_handler3 = CustomAvHttpNtlmAuth(username, password, send_cbt=False, custom_cert_hash=None)
            session3.auth = auth_handler3

            response3 = session3.get(url, verify=False, timeout=self._get_timeout())

            if response3.status_code == 200:
                # Success without CBT - EPA is set to "never" or "when supported"
                # Since bogus CBT worked, it's likely "never"
                return 'NOT_ENFORCED'
            elif response3.status_code == 401:
                # No CBT was rejected but bogus CBT worked - "when supported" mode
                return 'WHEN_SUPPORTED'

            # Couldn't determine clearly
            return 'NOT_ENFORCED'  # Default to not enforced if we couldn't confirm

        except requests.exceptions.SSLError as e:
            return f'TLS_ERROR: {str(e)}'
        except requests.exceptions.Timeout:
            return 'TIMEOUT'
        except requests.exceptions.RequestException as e:
            return f'REQUEST_ERROR: {str(e)}'
        except Exception as e:
            return f'ERROR: {str(e)}'

    def _check_connectivity(self, host: str, port: int, use_ssl: bool) -> bool:
        """
        Quick connectivity check to see if a web server is listening
        Returns True if server responds, False otherwise
        """
        try:
            # Use socket for quick connectivity test (faster than HTTP request)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # 2 second timeout for connection test

            if use_ssl:
                # For HTTPS, wrap socket with SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.close()
            return True

        except (socket.timeout, socket.error, ssl.SSLError, ConnectionRefusedError, OSError):
            # Connection failed - no web server listening
            return False

    def _is_comprehensive_scan(self) -> bool:
        """Check if user explicitly requested HTTP/HTTPS scanning"""
        # If protocols were explicitly specified, do comprehensive scanning
        return self.config.protocols is not None and (
            'http' in self.config.protocols or 'https' in self.config.protocols
        )

    def _check_basic_paths(self, host: str, port: int, use_ssl: bool) -> list:
        """Check root path and SCCM-specific paths only"""
        scheme = 'https' if use_ssl else 'http'
        paths_to_check = ['/'] + self.SCCM_PATHS

        ntlm_paths = []
        for path in paths_to_check:
            if self._check_path_for_ntlm(host, port, scheme, path):
                ntlm_paths.append(path)

        return ntlm_paths

    def _enumerate_ntlm_paths(self, host: str, port: int, use_ssl: bool) -> list:
        """
        Enumerate all paths from web_ntlm_paths.dict for NTLM authentication
        Uses threading for performance
        """
        scheme = 'https' if use_ssl else 'http'

        # Load wordlist
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'web_ntlm_paths.dict')

        if not os.path.exists(wordlist_path):
            if self._is_verbose(1):
                print(f"[!] Wordlist not found: {wordlist_path}")
            return self._check_basic_paths(host, port, use_ssl)

        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if self._is_verbose(2):
            print(f"[*] Enumerating {len(paths)} paths on {scheme}://{host}:{port}")

        ntlm_paths = []

        # Use thread pool for concurrent path checking (20 threads for speed)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_path = {
                executor.submit(self._check_path_for_ntlm, host, port, scheme, path): path
                for path in paths
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    if future.result():
                        ntlm_paths.append(path)
                        if self._is_verbose(2):
                            print(f"[+] NTLM enabled: {scheme}://{host}:{port}{path}")
                except Exception as e:
                    if self._is_verbose(3):
                        print(f"[!] Error checking {path}: {e}")

        return ntlm_paths

    def _is_catchall_ntlm(self, host: str, port: int, scheme: str):
        """Returns True if random bogus paths also 401-NTLM (catchall site,
        meaning /certsrv/ is not proof of ADCS), False otherwise, None on error."""
        bogus = ['/relayking-validation-xyzzy/', '/relayking-not-real-9f3c/']
        try:
            return all(self._check_path_for_ntlm(host, port, scheme, p) for p in bogus)
        except Exception:
            return None

    def _check_path_for_ntlm(self, host: str, port: int, scheme: str, path: str) -> bool:
        """Check if a specific path requires NTLM authentication"""
        try:
            url = f"{scheme}://{host}:{port}{path}"

            response = requests.get(
                url,
                timeout=self._get_timeout(),
                verify=False,
                allow_redirects=False
            )

            # Check for NTLM/Negotiate authentication in WWW-Authenticate header
            if response.status_code == 401 and 'WWW-Authenticate' in response.headers:
                auth_header = response.headers['WWW-Authenticate']
                if 'NTLM' in auth_header or 'Negotiate' in auth_header:
                    return True

            return False

        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            return False
        except Exception:
            return False

    def _get_tls_version(self, host: str, port: int) -> str:
        """Get TLS version"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self._get_timeout()) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.version()

        except:
            return None


class HTTPSDetector(HTTPDetector):
    """Detector specifically for HTTPS"""

    def detect(self, host: str, port: int = 443) -> ProtocolResult:
        """Detect HTTPS configuration"""
        return super().detect(host, port, use_ssl=True)
