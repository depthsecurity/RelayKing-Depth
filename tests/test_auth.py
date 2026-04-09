"""
Comprehensive tests for core.auth — the shared authentication module.

Every function is tested across all auth modes (password, pass-the-hash,
Kerberos, null/anonymous) and edge cases (fallback, errors, missing fields).
"""

import pytest
from unittest.mock import MagicMock, patch, call

from core.auth import (
    get_base_dn,
    is_kerberos_error,
    connect_ldap,
    configure_rpc_auth,
    connect_dce,
)


# ═══════════════════════════════════════════════════════════════════
# get_base_dn
# ═══════════════════════════════════════════════════════════════════

class TestGetBaseDn:
    def test_simple_domain(self):
        assert get_base_dn('corp.local') == 'DC=corp,DC=local'

    def test_three_part_domain(self):
        assert get_base_dn('sub.corp.local') == 'DC=sub,DC=corp,DC=local'

    def test_single_label(self):
        assert get_base_dn('WORKGROUP') == 'DC=WORKGROUP'

    def test_empty_string(self):
        assert get_base_dn('') == ''

    def test_none(self):
        assert get_base_dn(None) == ''


# ═══════════════════════════════════════════════════════════════════
# is_kerberos_error
# ═══════════════════════════════════════════════════════════════════

class TestIsKerberosError:
    @pytest.mark.parametrize('msg', [
        'KDC_ERR_CLIENT_REVOKED',
        'Kerberos SessionError: KRB_AP_ERR_SKEW',
        'kdc unreachable',
        'krb5 library error',
        'KERBEROS authentication failed',
    ])
    def test_detects_kerberos_errors(self, msg):
        assert is_kerberos_error(Exception(msg)) is True

    @pytest.mark.parametrize('msg', [
        'Connection refused',
        'STATUS_LOGON_FAILURE',
        '80090346',  # channel binding — NOT kerberos
        'timeout',
        '',
    ])
    def test_rejects_non_kerberos_errors(self, msg):
        assert is_kerberos_error(Exception(msg)) is False

    def test_accepts_plain_string(self):
        """is_kerberos_error should work with str(exception) internally."""
        assert is_kerberos_error(Exception('KDC timeout')) is True

    def test_case_insensitive(self):
        assert is_kerberos_error(Exception('kErBeRoS')) is True


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — password auth
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapPassword:
    """Standard username + password auth via impacket."""

    @patch('core.auth.ldap_impacket')
    def test_password_auth_returns_connection(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        conn, use_impacket, search_base = connect_ldap(password_config)

        assert conn is mock_conn
        assert use_impacket is True
        assert search_base == 'DC=corp,DC=local'

    @patch('core.auth.ldap_impacket')
    def test_password_calls_login_with_sasl(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(password_config)

        mock_conn.login.assert_called_once_with(
            user='lowpriv',
            password='Password1',
            domain='corp.local',
            lmhash='',
            nthash='',
            authenticationChoice='sasl',
        )

    @patch('core.auth.ldap_impacket')
    def test_password_tries_ldap_first(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(password_config)

        # First call should be ldap:// with signing=True
        mock_ldap.LDAPConnection.assert_called_once_with(
            url='ldap://10.0.0.1',
            baseDN='corp.local',
            dstIp='10.0.0.1',
            signing=True,
        )

    @patch('core.auth.ldap_impacket')
    def test_password_ldaps_forced(self, mock_ldap, ldaps_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(ldaps_config)

        mock_ldap.LDAPConnection.assert_called_once_with(
            url='ldaps://10.0.0.1',
            baseDN='corp.local',
            dstIp='10.0.0.1',
            signing=False,
        )

    @patch('core.auth.ldap_impacket')
    def test_explicit_dc_ip_overrides_config(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(password_config, dc_ip='10.99.99.99')

        mock_ldap.LDAPConnection.assert_called_once_with(
            url='ldap://10.99.99.99',
            baseDN='corp.local',
            dstIp='10.99.99.99',
            signing=True,
        )


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — channel binding fallback (80090346)
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapChannelBindingFallback:
    """When ldap:// fails with 80090346 the function should retry with ldaps://."""

    @patch('core.auth.ldap_impacket')
    def test_fallback_to_ldaps_on_channel_binding(self, mock_ldap, password_config):
        mock_conn_ldap = MagicMock()
        mock_conn_ldaps = MagicMock()

        # First call (ldap://) raises channel binding error, second (ldaps://) succeeds
        mock_ldap.LDAPConnection.side_effect = [mock_conn_ldap, mock_conn_ldaps]
        mock_conn_ldap.login.side_effect = Exception('80090346 SEC_E_BAD_BINDINGS')
        mock_conn_ldaps.login.return_value = None

        conn, use_impacket, _ = connect_ldap(password_config)

        assert conn is mock_conn_ldaps
        assert use_impacket is True
        assert mock_ldap.LDAPConnection.call_count == 2

        # Verify second call was ldaps with signing=False
        second_call = mock_ldap.LDAPConnection.call_args_list[1]
        assert second_call == call(
            url='ldaps://10.0.0.1',
            baseDN='corp.local',
            dstIp='10.0.0.1',
            signing=False,
        )

    @patch('core.auth.ldap_impacket')
    def test_non_channel_binding_error_raises_immediately(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn
        mock_conn.login.side_effect = Exception('STATUS_LOGON_FAILURE')

        with pytest.raises(Exception, match='STATUS_LOGON_FAILURE'):
            connect_ldap(password_config)

        # Should NOT retry with ldaps
        assert mock_ldap.LDAPConnection.call_count == 1

    @patch('core.auth.ldap_impacket')
    def test_ldaps_forced_no_fallback_needed(self, mock_ldap, ldaps_config):
        """When use_ldaps=True, only ldaps:// is tried — no fallback loop."""
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn
        mock_conn.login.side_effect = Exception('80090346 bad bindings')

        with pytest.raises(Exception, match='80090346'):
            connect_ldap(ldaps_config)

        # Only one attempt (ldaps)
        assert mock_ldap.LDAPConnection.call_count == 1


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — pass-the-hash
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapPassTheHash:

    @patch('core.auth.ldap_impacket')
    def test_pth_sends_empty_password_and_nthash(self, mock_ldap, pth_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(pth_config)

        mock_conn.login.assert_called_once_with(
            user='lowpriv',
            password='',
            domain='corp.local',
            lmhash='',
            nthash='aabbccdd11223344aabbccdd11223344',
            authenticationChoice='sasl',
        )

    @patch('core.auth.ldap_impacket')
    def test_pth_returns_impacket_connection(self, mock_ldap, pth_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        conn, use_impacket, _ = connect_ldap(pth_config)
        assert use_impacket is True

    @patch('core.auth.ldap_impacket')
    def test_pth_falls_back_on_channel_binding(self, mock_ldap, pth_config):
        mock_conn_ldap = MagicMock()
        mock_conn_ldaps = MagicMock()
        mock_ldap.LDAPConnection.side_effect = [mock_conn_ldap, mock_conn_ldaps]
        mock_conn_ldap.login.side_effect = Exception('80090346')

        conn, _, _ = connect_ldap(pth_config)
        assert conn is mock_conn_ldaps


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — Kerberos
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapKerberos:

    @patch('core.auth.ldap_impacket')
    def test_kerberos_calls_kerberosLogin(self, mock_ldap, kerberos_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(kerberos_config)

        mock_conn.kerberosLogin.assert_called_once_with(
            user='lowpriv',
            password='Password1',
            domain='CORP.LOCAL',
            lmhash='',
            nthash='',
            aesKey=None,
            kdcHost='10.0.0.1',
            useCache=True,
        )
        mock_conn.login.assert_not_called()

    @patch('core.auth.ldap_impacket')
    def test_kerberos_uppercases_domain(self, mock_ldap, kerberos_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(kerberos_config)

        kw = mock_conn.kerberosLogin.call_args
        assert kw[1]['domain'] == 'CORP.LOCAL'

    @patch('core.auth.ldap_impacket')
    def test_kerberos_with_aeskey(self, mock_ldap, kerberos_config):
        kerberos_config.aesKey = 'deadbeef' * 8
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(kerberos_config)

        kw = mock_conn.kerberosLogin.call_args
        assert kw[1]['aesKey'] == 'deadbeef' * 8


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — null/anonymous auth
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapNull:

    @patch('core.auth.ldap_impacket')
    def test_null_returns_ldap3_connection(self, mock_ldap, null_config):
        """Null auth must use ldap3 (not impacket) because impacket needs creds."""
        import ldap3
        ldap3.Server = MagicMock()
        ldap3.Connection = MagicMock(return_value=MagicMock())
        ldap3.ALL = 'ALL'
        ldap3.Tls = MagicMock()

        conn, use_impacket, search_base = connect_ldap(null_config)

        assert use_impacket is False
        assert search_base == 'DC=corp,DC=local'
        # impacket should NOT be called
        mock_ldap.LDAPConnection.assert_not_called()

    @patch('core.auth.ldap_impacket')
    def test_null_ldaps(self, mock_ldap, null_config):
        null_config.use_ldaps = True
        import ldap3
        ldap3.Server = MagicMock()
        ldap3.Connection = MagicMock(return_value=MagicMock())
        ldap3.ALL = 'ALL'
        ldap3.Tls = MagicMock()

        connect_ldap(null_config)

        # Server should be created with use_ssl=True and port 636
        server_call = ldap3.Server.call_args
        assert server_call[0][0] == '10.0.0.1'
        assert server_call[1].get('port') == 636 or server_call[0][1] == 636
        assert server_call[1].get('use_ssl') is True


# ═══════════════════════════════════════════════════════════════════
# connect_ldap — dc_ip resolution
# ═══════════════════════════════════════════════════════════════════

class TestConnectLdapDcResolution:

    @patch('core.auth.ldap_impacket')
    def test_falls_back_to_config_dc_ip(self, mock_ldap, password_config):
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(password_config)  # dc_ip not passed; uses config.dc_ip

        mock_ldap.LDAPConnection.assert_called_once_with(
            url='ldap://10.0.0.1',
            baseDN='corp.local',
            dstIp='10.0.0.1',
            signing=True,
        )

    @patch('socket.gethostbyname', return_value='10.0.0.42')
    @patch('core.auth.ldap_impacket')
    def test_resolves_domain_when_no_dc_ip(self, mock_ldap, mock_dns, password_config):
        password_config.dc_ip = None
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        connect_ldap(password_config)

        mock_dns.assert_called_once_with('corp.local')
        mock_ldap.LDAPConnection.assert_called_once_with(
            url='ldap://10.0.0.42',
            baseDN='corp.local',
            dstIp='10.0.0.42',
            signing=True,
        )

    @patch('core.auth.ldap_impacket')
    def test_no_domain_gives_empty_search_base(self, mock_ldap, password_config):
        password_config.domain = None
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        _, _, search_base = connect_ldap(password_config)
        assert search_base == ''


# ═══════════════════════════════════════════════════════════════════
# configure_rpc_auth
# ═══════════════════════════════════════════════════════════════════

class TestConfigureRpcAuth:

    def test_ntlm_sets_credentials(self, password_config):
        transport = MagicMock()

        use_krb = configure_rpc_auth(password_config, transport, 'target.corp.local')

        assert use_krb is False
        transport.set_credentials.assert_called_once_with(
            'lowpriv', 'Password1', 'corp.local', '', '', 
        )
        transport.set_kerberos.assert_not_called()

    def test_kerberos_sets_credentials_and_kerberos(self, kerberos_config):
        transport = MagicMock()

        use_krb = configure_rpc_auth(kerberos_config, transport, 'dc01.corp.local')

        assert use_krb is True
        transport.set_credentials.assert_called_once_with(
            'lowpriv', 'Password1', 'corp.local', '', '', None,
        )
        transport.set_kerberos.assert_called_once_with(True, '10.0.0.1')

    def test_pth_sets_nthash(self, pth_config):
        transport = MagicMock()

        configure_rpc_auth(pth_config, transport, 'target.corp.local')

        transport.set_credentials.assert_called_once_with(
            'lowpriv', None, 'corp.local', '', 'aabbccdd11223344aabbccdd11223344', 
        )

    def test_no_username_skips_credentials(self, null_config):
        transport = MagicMock()

        configure_rpc_auth(null_config, transport, 'target.corp.local')

        transport.set_credentials.assert_not_called()
        transport.set_kerberos.assert_not_called()

    def test_krb_dc_only_uses_kerberos_for_dc(self, krb_dc_only_config):
        transport = MagicMock()

        use_krb = configure_rpc_auth(krb_dc_only_config, transport, 'dc01.corp.local')

        assert use_krb is True
        transport.set_kerberos.assert_called_once()

    def test_krb_dc_only_uses_ntlm_for_member(self, krb_dc_only_config):
        transport = MagicMock()

        use_krb = configure_rpc_auth(krb_dc_only_config, transport, 'workstation1.corp.local')

        assert use_krb is False
        transport.set_kerberos.assert_not_called()

    def test_kerberos_includes_aeskey(self, kerberos_config):
        kerberos_config.aesKey = 'aes256key'
        transport = MagicMock()

        configure_rpc_auth(kerberos_config, transport, 'dc.corp.local')

        cred_args = transport.set_credentials.call_args[0]
        assert cred_args[5] == 'aes256key'


# ═══════════════════════════════════════════════════════════════════
# connect_dce
# ═══════════════════════════════════════════════════════════════════

class TestConnectDce:

    def test_creates_connects_binds_dce(self):
        transport = MagicMock()
        mock_dce = MagicMock()
        transport.get_dce_rpc.return_value = mock_dce
        fake_uuid = b'\x01\x02\x03'

        result = connect_dce(transport, use_kerberos=False, uuid=fake_uuid)

        assert result is mock_dce
        mock_dce.connect.assert_called_once()
        mock_dce.bind.assert_called_once_with(fake_uuid)
        mock_dce.set_auth_type.assert_not_called()

    def test_sets_kerberos_auth_type(self):
        from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

        transport = MagicMock()
        mock_dce = MagicMock()
        transport.get_dce_rpc.return_value = mock_dce

        connect_dce(transport, use_kerberos=True, uuid=b'\x01')

        mock_dce.set_auth_type.assert_called_once_with(RPC_C_AUTHN_GSS_NEGOTIATE)

    def test_connect_failure_propagates(self):
        transport = MagicMock()
        mock_dce = MagicMock()
        transport.get_dce_rpc.return_value = mock_dce
        mock_dce.connect.side_effect = OSError('Connection refused')

        with pytest.raises(OSError, match='Connection refused'):
            connect_dce(transport, use_kerberos=False, uuid=b'\x01')

    def test_bind_failure_propagates(self):
        transport = MagicMock()
        mock_dce = MagicMock()
        transport.get_dce_rpc.return_value = mock_dce
        mock_dce.bind.side_effect = Exception('RPC_S_SERVER_UNAVAILABLE')

        with pytest.raises(Exception, match='RPC_S_SERVER_UNAVAILABLE'):
            connect_dce(transport, use_kerberos=False, uuid=b'\x01')


# ═══════════════════════════════════════════════════════════════════
# Integration-style: end-to-end auth flow scenarios
# ═══════════════════════════════════════════════════════════════════

class TestAuthIntegrationScenarios:
    """Test realistic multi-step auth flows matching how callers use the module."""

    @patch('core.auth.ldap_impacket')
    def test_creds_checker_flow(self, mock_ldap, password_config):
        """Simulates CredentialChecker.check_creds() calling connect_ldap."""
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        # CredentialChecker calls connect_ldap(config, dc_host)
        conn, use_impacket, _ = connect_ldap(password_config, dc_ip='10.0.0.1')

        assert conn is mock_conn
        assert use_impacket is True
        mock_conn.login.assert_called_once()

    @patch('core.auth.ldap_impacket')
    def test_ghost_spn_flow_kerberos(self, mock_ldap, kerberos_config):
        """Simulates GhostSPNDetector._connect_ldap() flow with Kerberos."""
        mock_conn = MagicMock()
        mock_ldap.LDAPConnection.return_value = mock_conn

        conn, use_impacket, search_base = connect_ldap(kerberos_config, dc_ip='10.0.0.1')

        assert use_impacket is True
        assert search_base == 'DC=corp,DC=local'
        mock_conn.kerberosLogin.assert_called_once()

    def test_ntlmv1_registry_check_flow(self, password_config):
        """Simulates NTLMv1Detector._get_lm_compat_level() RPC flow."""
        from impacket.dcerpc.v5 import rrp

        rpc_transport = MagicMock()
        mock_dce = MagicMock()
        rpc_transport.get_dce_rpc.return_value = mock_dce

        # Step 1: configure auth
        use_krb = configure_rpc_auth(password_config, rpc_transport, 'target.corp.local')
        assert use_krb is False

        # Step 2: connect + bind
        dce = connect_dce(rpc_transport, use_krb, rrp.MSRPC_UUID_RRP)
        assert dce is mock_dce
        mock_dce.connect.assert_called_once()
        mock_dce.bind.assert_called_once_with(rrp.MSRPC_UUID_RRP)

    @patch('core.auth.ldap_impacket')
    def test_channel_binding_then_kerberos_error(self, mock_ldap, kerberos_config):
        """Channel binding fallback should still propagate Kerberos errors."""
        mock_conn_ldap = MagicMock()
        mock_conn_ldaps = MagicMock()
        mock_ldap.LDAPConnection.side_effect = [mock_conn_ldap, mock_conn_ldaps]

        # ldap:// fails with channel binding
        mock_conn_ldap.kerberosLogin.side_effect = Exception('80090346')
        # ldaps:// fails with Kerberos error
        mock_conn_ldaps.kerberosLogin.side_effect = Exception('KDC_ERR_C_PRINCIPAL_UNKNOWN')

        with pytest.raises(Exception, match='KDC_ERR_C_PRINCIPAL_UNKNOWN'):
            connect_ldap(kerberos_config)
