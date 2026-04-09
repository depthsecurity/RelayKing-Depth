"""
Credential Checker
Check if given credential is valid to avoid unexpected account lockout
"""

from core.auth import connect_ldap, is_kerberos_error


class CredentialChecker:
    """Checker of given credentials"""

    def __init__(self, config):
        self.config = config
        self.vulnerable_hosts = {}

    def check_creds(self) -> str:
        """
        Check given credentials

        Returns string with:
            - status: "success"
            - error: Error message
        """
        result = {
            'status': None,
            'error': None
        }

        dc_host = self.config.dc_ip if self.config.dc_ip is not None else self.config.domain
        print(f"[*] Checking given credentials against domain controller [{dc_host}] ... ")

        try:
            connect_ldap(self.config, dc_host)
            result['status'] = "success"
            result['error'] = "None"
            return result
        except Exception as e:
            if is_kerberos_error(e):
                result['error'] = f'Kerberos auth failed: {e}'
            else:
                result['error'] = str(e)
            return result


