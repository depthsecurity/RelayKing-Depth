"""
RelayKing Shared Authentication Module
Consolidates LDAP and RPC authentication logic used across the codebase.
"""

from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.ldap import ldap as ldap_impacket


def get_base_dn(domain):
    """Convert domain name to LDAP base DN (e.g. 'corp.local' -> 'DC=corp,DC=local')."""
    if not domain:
        return ""
    return ','.join(f"DC={part}" for part in domain.split('.'))


def is_kerberos_error(error):
    """Check if an exception is Kerberos-specific (should not be retried)."""
    err_str = str(error).lower()
    return any(kw in err_str for kw in ('kdc', 'kerberos', 'krb'))


def connect_ldap(config, dc_ip=None):
    """
    Establish an authenticated LDAP connection using impacket.

    Handles Kerberos, pass-the-hash, password auth, and null/anonymous bind.
    Automatically falls back from ldap:// to ldaps:// on channel binding
    enforcement (80090346).

    Args:
        config: RelayKingConfig instance
        dc_ip: DC IP address (defaults to config.dc_ip, then resolved from config.domain)

    Returns:
        Tuple of (connection, use_impacket: bool, search_base: str)
        use_impacket is False only for null/anonymous bind (ldap3 connection).

    Raises:
        Exception on connection or auth failure
    """
    import socket as _socket

    if not dc_ip:
        dc_ip = config.dc_ip
        if not dc_ip and config.domain:
            dc_ip = _socket.gethostbyname(config.domain)

    search_base = get_base_dn(config.domain) if config.domain else ''

    # Null/anonymous bind uses ldap3 (impacket requires credentials)
    if config.null_auth:
        import ssl
        from ldap3 import Server, Connection, ALL, Tls
        port = 636 if config.use_ldaps else 389
        tls_config = Tls(validate=ssl.CERT_NONE) if config.use_ldaps else None
        server = Server(dc_ip, port=port, use_ssl=config.use_ldaps, tls=tls_config, get_info=ALL)
        conn = Connection(server, auto_bind=True, auto_referrals=False)
        return conn, False, search_base

    # All credentialed auth uses impacket
    protos = ['ldaps'] if config.use_ldaps else ['ldap', 'ldaps']

    for proto in protos:
        try:
            conn = ldap_impacket.LDAPConnection(
                url=f"{proto}://{dc_ip}",
                baseDN=config.domain,
                dstIp=dc_ip,
                signing=proto == 'ldap',
            )

            if config.use_kerberos:
                krb_domain = (config.domain or '').upper()
                conn.kerberosLogin(
                    user=config.username,
                    password=config.password or '',
                    domain=krb_domain,
                    lmhash=config.lmhash or '',
                    nthash=config.nthash or '',
                    aesKey=config.aesKey,
                    kdcHost=config.dc_ip,
                    useCache=True,
                )
            elif config.nthash:
                conn.login(
                    user=config.username,
                    password='',
                    domain=config.domain or '',
                    lmhash=config.lmhash or '',
                    nthash=config.nthash,
                    authenticationChoice='sasl',
                )
            else:
                conn.login(
                    user=config.username,
                    password=config.password,
                    domain=config.domain or '',
                    lmhash='',
                    nthash='',
                    authenticationChoice='sasl',
                )

            return conn, True, search_base

        except Exception as e:
            if '80090346' in str(e) and proto == 'ldap':
                continue
            raise


def configure_rpc_auth(config, rpc_transport, target):
    """
    Set credentials and Kerberos options on an RPC transport.

    Args:
        config: RelayKingConfig instance
        rpc_transport: DCERPCTransport from transport factory
        target: Target hostname or IP (used for per-host Kerberos decision)

    Returns:
        bool: True if Kerberos auth is configured
    """
    use_kerberos = config.should_use_kerberos(target)

    if config.username:
        if use_kerberos:
            rpc_transport.set_credentials(
                config.username,
                config.password or '',
                config.domain or '',
                config.lmhash or '',
                config.nthash or '',
                config.aesKey,
            )
            rpc_transport.set_kerberos(True, config.dc_ip)
        else:
            rpc_transport.set_credentials(
                config.username,
                config.password,
                config.domain or '',
                config.lmhash or '',
                config.nthash or '',
            )

    return use_kerberos


def connect_dce(rpc_transport, use_kerberos, uuid):
    """
    Create, connect, and bind a DCE/RPC handle from a configured transport.

    Args:
        rpc_transport: Configured DCERPCTransport (credentials already set)
        use_kerberos: Whether to set Kerberos auth type
        uuid: Service UUID to bind to (e.g. rrp.MSRPC_UUID_RRP)

    Returns:
        Connected and bound DCE/RPC handle

    Raises:
        Exception on connection or bind failure
    """
    dce = rpc_transport.get_dce_rpc()
    if use_kerberos:
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    dce.connect()
    dce.bind(uuid)
    return dce
