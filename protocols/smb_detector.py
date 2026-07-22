"""
SMB Protocol Detector
Detects SMB signing, channel binding, NTLMv1 support
"""

from impacket.smbconnection import SMBConnection, SMB_DIALECT
from impacket import smb, smb3
from .base_detector import BaseDetector, ProtocolResult
import socket


class SMBDetector(BaseDetector):
    """Detector for SMB/SMB2/SMB3 protocols"""

    @staticmethod
    def _get_signing_required(conn) -> bool:
        """
        Determine whether the server *requires* SMB signing.

        We cannot trust impacket's ``RequireSigning`` flag (nor
        ``isSigningRequired()``, which returns the same value): impacket forces
        it to True whenever the negotiated dialect is SMB 3.1.1, regardless of
        the server's actual security mode (see smb3.py negotiateSession, the
        "Always Sign" branch). Since Windows 10 / Server 2016+ negotiate 3.1.1
        by default, that reports "signing required" on hosts where signing is
        only *enabled* but not required - which is a valid relay target.

        The authoritative signal is the SMB2_NEGOTIATE_SIGNING_REQUIRED bit in
        the server's negotiate-response SecurityMode. impacket stores that raw
        value in ServerSecurityMode, but only for dialect >= 3.0. For 2.0/2.1
        (and SMB1) the RequireSigning flag is accurate because the 3.1.1
        override does not apply there.
        """
        smb_conn = conn._SMBConnection

        # SMB1 path: isSigningRequired() reflects the real state
        if isinstance(smb_conn, smb.SMB):
            return conn.isSigningRequired()

        connection = smb_conn._Connection
        dialect = connection.get("Dialect", 0)

        if dialect >= smb3.SMB2_DIALECT_30:
            # ServerSecurityMode is the raw server SecurityMode; test the
            # REQUIRED bit directly to bypass impacket's 3.1.1 override.
            server_security_mode = connection.get("ServerSecurityMode", 0)
            return bool(server_security_mode & smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED)

        # SMB 2.0 / 2.1: RequireSigning accurately reflects the REQUIRED bit
        return connection.get("RequireSigning", False)

    def detect(self, host: str, port: int = 445) -> ProtocolResult:
        """Detect SMB configuration"""

        result = self._create_result('smb', host, port)

        try:
            # Create SMB connection
            if self.config.null_auth:
                username = ''
                password = ''
                domain = ''
                lmhash = ''
                nthash = ''
                use_kerberos = False
                aesKey = None
                dc_ip = None
            else:
                username = self.config.username
                password = self.config.password
                domain = self.config.domain or ''
                lmhash = self.config.lmhash
                nthash = self.config.nthash
                use_kerberos = self.config.should_use_kerberos(host)
                aesKey = self.config.aesKey
                dc_ip = self.config.dc_ip

            # Try to connect
            conn = SMBConnection(host, host, sess_port=port, timeout=self._get_timeout())

            try:
                # Login - use Kerberos if specified
                if use_kerberos:
                    # Use uppercase domain for Kerberos realm matching, useCache for ccache
                    krb_domain = domain.upper() if domain else ''
                    try:
                        conn.kerberosLogin(username, password, krb_domain, lmhash, nthash, aesKey, dc_ip, useCache=True)
                        result.additional_info['auth_method'] = 'kerberos'
                    except Exception as krb_err:
                        # Handle Kerberos-specific errors - do NOT fallback to NTLM
                        # This prevents account lockouts from repeated auth failures
                        krb_error = str(krb_err).lower()
                        if 'kdc' in krb_error or 'kerberos' in krb_error or 'krb' in krb_error:
                            # Kerberos error - skip this host for auth, just check signing
                            result.available = True
                            result.error = f'Kerberos auth failed: {krb_err}'
                            result.additional_info['auth_method'] = 'kerberos_failed'

                            # Still get signing info from negotiation (doesn't require auth)
                            try:
                                result.signing_required = self._get_signing_required(conn)
                            except:
                                pass

                            try:
                                conn.close()
                            except:
                                pass
                            return result
                        else:
                            # Non-Kerberos error, re-raise
                            raise
                elif nthash:
                    conn.login(username, '', domain, lmhash, nthash)
                    result.additional_info['auth_method'] = 'ntlm_hash'
                else:
                    conn.login(username, password, domain)
                    result.additional_info['auth_method'] = 'ntlm_password'

                result.available = True

                # Get SMB dialect/version
                dialect = conn.getDialect()

                if dialect == SMB_DIALECT:
                    result.version = 'SMB1'
                elif dialect == smb3.SMB2_DIALECT_002:
                    result.version = 'SMB2.0'
                elif dialect == smb3.SMB2_DIALECT_21:
                    result.version = 'SMB2.1'
                elif dialect == smb3.SMB2_DIALECT_30:
                    result.version = 'SMB3.0'
                elif dialect == smb3.SMB2_DIALECT_302:
                    result.version = 'SMB3.0.2'
                elif dialect == smb3.SMB2_DIALECT_311:
                    result.version = 'SMB3.1.1'
                else:
                    result.version = f'Unknown ({hex(dialect)})'

                # Check signing requirement from the server's negotiate-response
                # SecurityMode (see _get_signing_required for why we can't use
                # impacket's RequireSigning flag directly).
                try:
                    result.signing_required = self._get_signing_required(conn)
                except Exception as e:
                    # Fallback to isSigningRequired() if we can't access internal state
                    result.signing_required = conn.isSigningRequired()

                # Check channel binding (SMB 3.1.1+)
                if dialect == smb3.SMB2_DIALECT_311:
                    result.channel_binding = True
                    result.additional_info['supports_encryption'] = True

                # Note: NTLMv1 checking is disabled during scan when --ntlmv1 or --ntlmv1-all
                # is specified, as the dedicated registry-based check is more accurate
                # and avoids connection exhaustion during parallel scans

                # Check if anonymous/guest login worked
                if self.config.null_auth or (not username and not password):
                    result.anonymous_allowed = True

                # Additional info
                result.additional_info['server_name'] = conn.getServerName()
                result.additional_info['server_os'] = conn.getServerOS()
                result.additional_info['server_domain'] = conn.getServerDomain()

                # Get OS version numbers for CVE checks
                try:
                    result.additional_info['server_os_major'] = conn.getServerOSMajor()
                    result.additional_info['server_os_minor'] = conn.getServerOSMinor()
                    result.additional_info['server_os_build'] = conn.getServerOSBuild()
                except Exception as e:
                    if self.config.verbose >= 2:
                        print(f"[!] Could not get OS version from SMB connection to {host}: {e}")
                    pass

                conn.close()

            except Exception as e:
                # Connection succeeded but login failed
                if 'STATUS_LOGON_FAILURE' in str(e):
                    result.available = True
                    result.error = 'Authentication failed'

                    # Still try to get signing info from the negotiation
                    try:
                        result.signing_required = self._get_signing_required(conn)
                    except:
                        pass

                elif 'STATUS_ACCESS_DENIED' in str(e):
                    result.available = True
                    result.error = 'Access denied'

                    # Try to get signing info even with access denied
                    try:
                        result.signing_required = self._get_signing_required(conn)
                    except:
                        pass
                else:
                    result.error = str(e)

        except socket.timeout:
            result.error = 'Connection timeout'
        except socket.error as e:
            result.error = f'Socket error: {e}'
        except Exception as e:
            result.error = str(e)

        return result

    def _check_ntlmv1(self, host: str, port: int) -> bool:
        """
        Check if NTLMv1 is supported
        This requires attempting an NTLMv1 authentication
        """
        try:
            # Create a new connection specifically for NTLMv1 test
            conn = SMBConnection(host, host, sess_port=port, timeout=self._get_timeout())

            # Attempt to force NTLMv1
            # This is a simplified check - full implementation would modify
            # the NTLM negotiation to request NTLMv1
            # For now, we assume NTLMv1 is supported if SMB1 is available

            dialect = conn.getDialect()
            if dialect == SMB_DIALECT:
                # SMB1 typically supports NTLMv1
                return True

            conn.close()
            return False

        except:
            return False
