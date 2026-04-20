"""
Credential Checker
Check if given credential is valid to avoid unexpected account lockout
"""

from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket


class CredentialChecker:
    """Checker of given credentials"""

    def __init__(self, config):
        self.config = config
        self.vulnerable_hosts = {}

    def check_creds(self) -> str:
        """
        Check given credentials

        Returns string with:
            - status: "Success"
            - error: Error message
        """
        result = {
            'status': None,
            'error': None
        }

        dc_host = self.config.dc_ip if self.config.dc_ip is not None else self.config.domain
        print(f"[*] Checking given credentials against domain controller [{dc_host}] ... ")

        last_error = None
        for proto in ('ldap', 'ldaps'):
            try:
                ldap_url = f"{proto}://{dc_host}"
                ldap_conn = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.config.domain, dstIp=dc_host, signing=proto == 'ldap')

                if self.config.should_use_kerberos(dc_host):
                    krb_domain = (self.config.domain or '').upper()
                    try:
                        ldap_conn.kerberosLogin(
                            user=self.config.username,
                            password=self.config.password or '',
                            domain=krb_domain,
                            lmhash=self.config.lmhash or '',
                            nthash=self.config.nthash or '',
                            aesKey=self.config.aesKey,
                            kdcHost=self.config.dc_ip,
                            useCache=True
                        )
                    except Exception as krb_err:
                        krb_error = str(krb_err).lower()
                        if 'kdc' in krb_error or 'kerberos' in krb_error or 'krb' in krb_error:
                            result['error'] = f'Kerberos auth failed: {krb_err}'
                            return result
                        raise
                else:
                    ldap_conn.login(
                        user=self.config.username,
                        password=self.config.password,
                        domain=self.config.domain or '',
                        lmhash=self.config.lmhash or '',
                        nthash=self.config.nthash or '',
                        authenticationChoice='sasl'
                    )

                result['status'] = "Success"
                result['error'] = "None"
                return result

            except Exception as e:
                err_str = str(e)
                last_error = err_str
                # 80090346 = SEC_E_BAD_BINDINGS: channel binding required.
                # Retry with LDAPS so impacket can negotiate CBT over TLS.
                if '80090346' in err_str and proto == 'ldap':
                    continue
                result['error'] = err_str
                return result

        result['error'] = last_error
        return result


    def _get_base_dn(self) -> str:
        """Convert domain to base DN"""
        if not self.config.domain:
            return ""

        parts = self.config.domain.split('.')
        return ','.join([f"DC={part}" for part in parts])
