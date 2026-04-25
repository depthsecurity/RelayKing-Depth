"""
Ghost SPN Detector
Identifies Service Principal Names pointing to hostnames with no DNS record,
enabling NTLM relay attacks via DNS registration.
"""

import re
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional


class GhostSPNDetector:
    """
    Detect Ghost SPNs in Active Directory.

    A Ghost SPN is a Service Principal Name whose hostname no longer exists in DNS.
    An attacker can register that DNS name and receive NTLM authentication
    intended for the service principal, enabling relay attacks.

    Findings are classified as:
      - vulnerable:          SPN hostname has no DNS record at all
      - probably_vulnerable: SPN hostname resolves only via wildcard DNS
    """

    # SPN format: serviceclass/hostname[:port][/instancename]
    SPN_REGEX = re.compile(r'^[^/]+/([^:/]+)(?::\d+)?(?:/.*)?$', re.IGNORECASE)

    # GUID hostnames (DSA GUIDs) resolve via _msdcs CNAMEs, not a relay vector.
    # GUID service classes (e.g. DRSUAPI) are Kerberos-only.
    GUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                            re.IGNORECASE)

    # SPNs whose service class is always self-referential - skip them
    SKIP_SERVICE_CLASSES = {'host', 'rpcss', 'wsman', 'exchangeinternalipaddress'}

    def __init__(self, config):
        self.config = config

    def detect(self) -> Dict:
        """
        Run Ghost SPN detection against Active Directory.

        Returns:
            dict with keys:
              'vulnerable'          - list of {account, spn, hostname}
              'probably_vulnerable' - list of {account, spn, hostname}
              'checked'             - number of unique hostnames checked
              'error'               - error string or None
        """
        result = {
            'vulnerable': [],
            'probably_vulnerable': [],
            'checked': 0,
            'error': None,
        }

        if self.config.null_auth or not self.config.username:
            result['error'] = "Credentials required for Ghost SPN check"
            return result

        if not self.config.dc_ip and not self.config.domain:
            result['error'] = "DC IP or domain required for Ghost SPN check"
            return result

        dc_ip = self.config.dc_ip
        if not dc_ip and self.config.domain:
            try:
                dc_ip = socket.gethostbyname(self.config.domain)
            except socket.gaierror:
                result['error'] = f"Could not resolve domain: {self.config.domain}"
                return result

        try:
            conn, use_impacket, search_base = self._connect_ldap(dc_ip)
        except Exception as e:
            result['error'] = f"LDAP connection failed: {e}"
            return result

        try:
            has_wildcard_dns = self._check_wildcard_dns(conn, search_base, use_impacket)
            spn_objects = self._get_spn_objects(conn, search_base, use_impacket)
        except Exception as e:
            result['error'] = f"LDAP query failed: {e}"
            return result
        finally:
            if not use_impacket:
                try:
                    conn.unbind()
                except Exception:
                    pass

        # Build map: hostname -> [(account, spn), ...]
        hostname_map: Dict[str, List[Tuple[str, str]]] = {}
        obj_domain = self.config.domain.lower() if self.config.domain else ''

        for obj in spn_objects:
            account = obj.get('sAMAccountName', '')
            spns = obj.get('servicePrincipalName', [])
            dn = obj.get('distinguishedName', '')

            # Derive domain from DN as fallback
            if not obj_domain and dn:
                parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
                obj_domain = '.'.join(parts).lower() if parts else ''

            for spn in spns:
                m = self.SPN_REGEX.match(spn)
                if not m:
                    continue

                service_class = spn.split('/')[0].lower()
                if service_class in self.SKIP_SERVICE_CLASSES:
                    continue
                if self.GUID_REGEX.match(service_class):
                    continue

                raw_host = m.group(1).lower()
                if self.GUID_REGEX.match(raw_host.split('.')[0]):
                    continue

                # Promote short hostname to FQDN
                if '.' not in raw_host and obj_domain:
                    fqdn = f"{raw_host}.{obj_domain}"
                else:
                    fqdn = raw_host

                # Skip trivially self-referential entries (host == domain)
                if fqdn == obj_domain or raw_host == obj_domain:
                    continue

                hostname_map.setdefault(fqdn, []).append((account, spn))

        # DNS-resolve all unique hostnames in parallel
        hostnames = list(hostname_map.keys())
        result['checked'] = len(hostnames)
        resolution_map = self._resolve_all(hostnames)

        # A wildcard *existing* doesn't mean a given name resolved via it —
        # real A records win. Probe to find the wildcard's IPs so we can
        # tell catches apart from legit records.
        wildcard_ips_by_domain: Dict[str, Set[str]] = {}
        if has_wildcard_dns:
            parents = {fqdn.split('.', 1)[1] for fqdn in hostnames if '.' in fqdn}
            wildcard_ips_by_domain = self._probe_wildcard_targets(parents)

        # Classify findings
        for fqdn, entries in hostname_map.items():
            ips = resolution_map.get(fqdn)

            if ips is None:
                # No DNS record - ghost SPN
                for account, spn in entries:
                    result['vulnerable'].append({
                        'account': account,
                        'spn': spn,
                        'hostname': fqdn,
                    })
            elif has_wildcard_dns:
                parent = fqdn.split('.', 1)[1] if '.' in fqdn else ''
                wc_ips = wildcard_ips_by_domain.get(parent, set())
                if wc_ips and set(ips).issubset(wc_ips):
                    for account, spn in entries:
                        result['probably_vulnerable'].append({
                            'account': account,
                            'spn': spn,
                            'hostname': fqdn,
                            'resolved_to': list(ips),
                        })

        return result

    # ──────────────────────────────────────────────────────────────
    # LDAP helpers
    # ──────────────────────────────────────────────────────────────

    def _connect_ldap(self, dc_ip: str) -> Tuple:
        """Establish LDAP connection. Returns (conn, use_impacket, search_base).

        Uses impacket for all auth types:
          - signing=True on ldap:// satisfies LDAP signing enforcement (00002028)
          - authenticationChoice='sasl' on ldaps:// computes CBT from the TLS cert,
            satisfying channel binding enforcement (80090346)
          - Falls back ldap -> ldaps automatically on 80090346
        """
        from impacket.ldap import ldap as ldap_impacket

        search_base = ''
        if self.config.domain:
            search_base = ','.join(f"DC={part}" for part in self.config.domain.split('.'))

        use_ldaps = self.config.use_ldaps
        protos = ['ldaps'] if use_ldaps else ['ldap', 'ldaps']

        for proto in protos:
            try:
                conn = ldap_impacket.LDAPConnection(
                    url=f"{proto}://{dc_ip}", baseDN=self.config.domain, dstIp=dc_ip,
                    signing=proto == 'ldap'
                )

                if self.config.use_kerberos:
                    krb_domain = self.config.domain.upper() if self.config.domain else ''
                    conn.kerberosLogin(
                        user=self.config.username,
                        password=self.config.password or '',
                        domain=krb_domain,
                        lmhash=self.config.lmhash or '',
                        nthash=self.config.nthash or '',
                        aesKey=self.config.aesKey,
                        kdcHost=self.config.dc_ip,
                        useCache=True,
                    )
                elif self.config.nthash:
                    conn.login(
                        user=self.config.username,
                        password='',
                        domain=self.config.domain,
                        lmhash=self.config.lmhash or '',
                        nthash=self.config.nthash,
                        authenticationChoice='sasl'
                    )
                else:
                    conn.login(
                        user=self.config.username,
                        password=self.config.password,
                        domain=self.config.domain or '',
                        lmhash='',
                        nthash='',
                        authenticationChoice='sasl'
                    )

                return conn, True, search_base

            except Exception as e:
                if '80090346' in str(e) and proto == 'ldap':
                    continue
                raise

    def _check_wildcard_dns(self, conn, search_base: str, use_impacket: bool) -> bool:
        """Return True if any wildcard DNS entry exists in DomainDnsZones."""
        dns_base = f"CN=MicrosoftDNS,DC=DomainDnsZones,{search_base}"
        wc_filter = '(&(objectClass=dnsNode)(dc=\\2A))'

        try:
            if use_impacket:
                from impacket.ldap import ldapasn1 as ldapasn1_imp
                resp = conn.search(
                    searchBase=dns_base,
                    searchFilter=wc_filter,
                    attributes=['dc'],
                    scope=ldapasn1_imp.Scope('wholeSubtree'),
                )
                for item in resp:
                    if isinstance(item, ldapasn1_imp.SearchResultEntry):
                        return True
            else:
                from ldap3 import SUBTREE
                conn.search(
                    search_base=dns_base,
                    search_filter=wc_filter,
                    search_scope=SUBTREE,
                    attributes=['dc'],
                )
                if conn.entries:
                    return True
        except Exception:
            pass  # DomainDnsZones may not be accessible to this account

        return False

    def _get_spn_objects(self, conn, search_base: str, use_impacket: bool) -> List[Dict]:
        """Return list of dicts with sAMAccountName, servicePrincipalName, distinguishedName."""
        objects = []
        search_filter = '(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        attributes = ['sAMAccountName', 'servicePrincipalName', 'distinguishedName']

        if use_impacket:
            from impacket.ldap import ldapasn1 as ldapasn1_imp

            def _on_spn(item):
                if not isinstance(item, ldapasn1_imp.SearchResultEntry):
                    return
                obj = {'sAMAccountName': '', 'servicePrincipalName': [], 'distinguishedName': ''}
                for attr in item['attributes']:
                    attr_type = str(attr['type'])
                    if attr_type == 'sAMAccountName':
                        obj['sAMAccountName'] = str(attr['vals'][0])
                    elif attr_type == 'distinguishedName':
                        obj['distinguishedName'] = str(attr['vals'][0])
                    elif attr_type == 'servicePrincipalName':
                        obj['servicePrincipalName'] = [str(v) for v in attr['vals']]
                objects.append(obj)

            try:
                conn.search(
                    searchBase=search_base,
                    searchFilter=search_filter,
                    attributes=attributes,
                    scope=ldapasn1_imp.Scope('wholeSubtree'),
                    perRecordCallback=_on_spn,
                )
            except Exception as e:
                if 'sizeLimitExceeded' not in str(e):
                    raise
        else:
            from ldap3 import SUBTREE
            page_size = self.config.ad_page_size
            cookie = None
            while True:
                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
                for entry in conn.entries:
                    spns = []
                    if entry.servicePrincipalName:
                        if hasattr(entry.servicePrincipalName, 'values'):
                            spns = [str(v) for v in entry.servicePrincipalName.values]
                        else:
                            spns = [str(entry.servicePrincipalName)]
                    objects.append({
                        'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                        'servicePrincipalName': spns,
                        'distinguishedName': str(entry.entry_dn) if entry.entry_dn else '',
                    })
                cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                if not cookie:
                    break

        return objects

    # ──────────────────────────────────────────────────────────────
    # DNS helpers
    # ──────────────────────────────────────────────────────────────

    def _probe_wildcard_targets(self, domains: Set[str]) -> Dict[str, Set[str]]:
        """Resolve a bogus name in each domain to discover the wildcard's
        target IPs. Hostnames with real A records resolve to different IPs."""
        probes = {d: f"relayking-wc-{uuid.uuid4().hex[:12]}.{d}" for d in domains}
        resolved = self._resolve_all(list(probes.values()))
        return {d: set(resolved[name]) for d, name in probes.items() if resolved.get(name)}

    def _resolve_all(self, hostnames: List[str]) -> Dict[str, Optional[List[str]]]:
        """
        Resolve all hostnames in parallel.
        Returns dict: hostname -> list of IPs, or None if unresolvable.
        """
        results: Dict[str, Optional[List[str]]] = {}

        def resolve_one(hostname: str) -> Tuple[str, Optional[List[str]]]:
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3)
                try:
                    infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
                    ips = list({r[4][0] for r in infos})
                    return hostname, ips if ips else None
                except (socket.gaierror, socket.timeout):
                    return hostname, None
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception:
                return hostname, None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(resolve_one, h): h for h in hostnames}
            for future in as_completed(futures):
                try:
                    hostname, ips = future.result(timeout=5)
                    results[hostname] = ips
                except Exception:
                    results[futures[future]] = None

        return results
