"""
RelayKing Target Parser
Parse targets from various formats: CIDR, ranges, files, AD enumeration
"""

import ipaddress
import os
import re
import subprocess
import platform
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

from core.auth import connect_ldap


def _is_valid_unicast_ip(ip: str) -> bool:
    """
    Check if an IP address is a valid unicast address for host resolution.

    Filters out:
    - Loopback (127.0.0.0/8)
    - Multicast (224.0.0.0/4) - THIS WAS CAUSING THE 224.0.0.x BUG
    - Link-local (169.254.0.0/16)
    - Broadcast (255.255.255.255)
    - Reserved/Invalid (0.0.0.0)

    Args:
        ip: IP address string

    Returns:
        True if valid unicast IP, False otherwise
    """
    try:
        addr = ipaddress.ip_address(ip)

        # Filter out invalid address types
        if addr.is_loopback:       # 127.0.0.0/8
            return False
        if addr.is_multicast:      # 224.0.0.0/4 - THE BUG!
            return False
        if addr.is_link_local:     # 169.254.0.0/16
            return False
        if addr.is_reserved:       # Various reserved ranges
            return False
        if addr.is_unspecified:    # 0.0.0.0
            return False

        # IPv4 broadcast
        if ip == '255.255.255.255':
            return False

        return True
    except ValueError:
        return False


class TargetParser:
    """Parse and expand targets from various input formats"""

    def __init__(self, config):
        self.config = config
        self.targets: Set[str] = set()
        self.tier0_assets: Set[str] = set()  # Store tier-0 asset hostnames

    def parse_targets(self) -> List[str]:
        """Parse all target sources and return unique list"""

        # Parse command-line targets
        for target in self.config.targets:
            self._parse_target(target)

        # Parse target file
        if self.config.target_file:
            self._parse_file(self.config.target_file)

        # Enumerate from AD (in audit mode or coerce-all mode)
        if self.config.audit_mode or self.config.coerce_all:
            self._enumerate_ad()

        return sorted(list(self.targets))

    def _parse_target(self, target: str):
        """Parse a single target specification"""

        # Check for CIDR notation
        if '/' in target:
            self._parse_cidr(target)

        # Check for IP range (e.g., 192.168.1.1-254)
        # Guard: only attempt range parsing if the part before the last dash
        # is a valid IPv4 address - this prevents hyphenated hostnames like
        # CTC-PS-CTX-FAS1.gmt.internal from being misidentified as ranges.
        elif '-' in target and '.' in target:
            start_part = target.rsplit('-', 1)[0]
            try:
                ipaddress.ip_address(start_part)
                self._parse_range(target)
            except ValueError:
                self.targets.add(target)  # Hyphenated hostname, not an IP range

        # Single host (IP or hostname)
        else:
            self.targets.add(target)

    def _parse_cidr(self, cidr: str):
        """Parse CIDR notation and expand to individual IPs"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]

            if self.config.no_ping:
                # Skip ping sweep - add all IPs directly
                print(f"[*] Skipping ping sweep (--no-ping), adding all {len(all_ips)} IPs from {cidr}...")
                for ip in all_ips:
                    self.targets.add(ip)
            else:
                # Ping sweep to find live hosts
                print(f"[*] Performing ping sweep on {cidr}...")
                live_hosts = self._ping_sweep(all_ips)
                print(f"[+] Found {len(live_hosts)} live hosts in {cidr}")

                for ip in live_hosts:
                    self.targets.add(ip)
        except ValueError as e:
            print(f"[!] Invalid CIDR notation '{cidr}': {e}")

    def _parse_range(self, range_spec: str):
        """Parse IP range (e.g., 192.168.1.1-254)"""
        try:
            # Split by last dash to handle IPv4
            parts = range_spec.rsplit('-', 1)
            if len(parts) != 2:
                self.targets.add(range_spec)
                return

            start_ip = parts[0].strip()
            end_octet = int(parts[1].strip())

            # Validate start IP
            start = ipaddress.ip_address(start_ip)

            # Get the base network (first 3 octets for IPv4)
            octets = str(start).split('.')
            if len(octets) != 4:
                self.targets.add(range_spec)
                return

            start_octet = int(octets[3])
            base = '.'.join(octets[:3])

            # Generate range
            for i in range(start_octet, end_octet + 1):
                self.targets.add(f"{base}.{i}")

        except (ValueError, IndexError) as e:
            print(f"[!] Invalid IP range '{range_spec}': {e}")
            # Add as-is, might be a hostname
            self.targets.add(range_spec)

    def _parse_file(self, filename: str):
        """Parse targets from file"""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        self._parse_target(line)
        except FileNotFoundError:
            print(f"[!] Target file not found: {filename}")
        except Exception as e:
            print(f"[!] Error reading target file: {e}")

    def _enumerate_ad(self):
        """Enumerate computer accounts from Active Directory via LDAP"""
        print("[*] Enumerating computers from Active Directory...")

        try:
            # Determine DC IP
            dc_ip = self.config.dc_ip
            if not dc_ip:
                # Try to resolve domain to get DC
                try:
                    dc_ip = socket.gethostbyname(self.config.domain)
                except socket.gaierror:
                    print(f"[!] Could not resolve domain: {self.config.domain}")
                    return

            try:
                # Print auth method info
                if self.config.use_kerberos:
                    ccache_file = os.environ.get('KRB5CCNAME', '')
                    if ccache_file:
                        print(f"[*] Using Kerberos authentication with ccache: {ccache_file}")
                    else:
                        print("[*] Using Kerberos authentication for AD enumeration...")
                elif self.config.nthash:
                    print("[*] Using NTLM pass-the-hash authentication for AD enumeration...")

                conn, use_impacket, search_base = connect_ldap(self.config, dc_ip)

                # Detect tier-0 assets (SCCM, ADCS, Exchange) if not using null auth
                # Note: Tier0Detector requires ldap3 connection, skip for Kerberos/impacket
                if not self.config.null_auth and not use_impacket:
                    try:
                        from detectors.tier0_detector import Tier0Detector
                        print("[*] Detecting tier-0 assets (SCCM, ADCS, Exchange)...")
                        tier0_detector = Tier0Detector(conn, self.config.domain)
                        self.tier0_assets = tier0_detector.detect_all()
                        if self.tier0_assets:
                            print(f"[+] Identified {len(self.tier0_assets)} tier-0 asset(s):")
                            for asset in sorted(self.tier0_assets):
                                print(f"    - {asset}")
                    except Exception as e:
                        print(f"[!] Error detecting tier-0 assets: {e}")
                        if self.config.verbose >= 2:
                            import traceback
                            traceback.print_exc()
                elif use_impacket and not self.config.null_auth:
                    auth_type = "Kerberos" if self.config.use_kerberos else "pass-the-hash"
                    print(f"[*] Tier-0 asset detection not yet supported with {auth_type} auth")

                # Search for enabled computer objects only
                # userAccountControl flag 0x0002 = ACCOUNTDISABLE
                # We want computers where this bit is NOT set
                hostnames_to_resolve = []
                hostnames_seen = set()  # Track seen hostnames for deduplication

                if use_impacket:
                    from impacket.ldap import ldapasn1 as ldapasn1_impacket

                    auth_method = "Kerberos" if self.config.use_kerberos else "NTLM"
                    print(f"[*] Retrieving computers via {auth_method} LDAP...")
                    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'

                    def _on_computer(item):
                        if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                            return
                        hostname = None
                        name = None
                        for attr in item['attributes']:
                            attr_type = str(attr['type'])
                            if attr_type == 'dNSHostName':
                                hostname = str(attr['vals'][0])
                            elif attr_type == 'name':
                                name = str(attr['vals'][0])
                        final_hostname = hostname or name
                        if final_hostname and final_hostname not in hostnames_seen:
                            hostnames_seen.add(final_hostname)
                            hostnames_to_resolve.append(final_hostname)

                    try:
#page_size now reads from self.config.ad_page_size so the --ad-page-size flag actually takes effect on this code path
# add SimplePagedResultsControl to get full results.
                        page_size = getattr(self.config, 'ad_page_size', 1000) 
                        paged_control = ldapasn1_impacket.SimplePagedResultsControl(size=page_size)
                        conn.search(
                            searchBase=search_base,
                            searchFilter=search_filter,
                            attributes=['dNSHostName', 'name'],
                            scope=ldapasn1_impacket.Scope('wholeSubtree'),
                            perRecordCallback=_on_computer,
                            searchControls=[paged_control],
                        )
                    except Exception as e:
                        if 'sizeLimitExceeded' in str(e):
                            print(f"[!] AD size limit hit — retrieved {len(hostnames_to_resolve)} computers (partial). Lower --ad-page-size or use paged auth.")
                        else:
                            print(f"[!] Error retrieving computers from AD: {e}")
                            if self.config.verbose >= 2:
                                import traceback
                                traceback.print_exc()

                    print(f"[+] Retrieved {len(hostnames_to_resolve)} computers")
                else:
                    # Use ldap3's paged search for null/anonymous auth
                    from ldap3 import SUBTREE
                    page_size = self.config.ad_page_size
                    cookie = None
                    total_retrieved = 0

                    print(f"[*] Retrieving computers in pages of {page_size}...")

                    while True:
                        conn.search(
                            search_base=search_base,
                            search_filter='(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                            search_scope=SUBTREE,
                            attributes=['dNSHostName', 'name'],
                            paged_size=page_size,
                            paged_cookie=cookie
                        )

                        # Process entries from this page
                        page_count = 0
                        for entry in conn.entries:
                            # Prefer dNSHostName, fall back to name
                            hostname = None
                            if entry.dNSHostName:
                                hostname = str(entry.dNSHostName)
                            elif entry.name:
                                hostname = str(entry.name)

                            # Deduplicate hostnames
                            if hostname and hostname not in hostnames_seen:
                                hostnames_seen.add(hostname)
                                hostnames_to_resolve.append(hostname)
                                page_count += 1

                        total_retrieved += page_count
                        print(f"[*] Retrieved {page_count} computers in this page (total: {total_retrieved})")

                        # Get the cookie for the next page
                        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']

                        # If cookie is empty, we've retrieved all results
                        if not cookie:
                            break

                count = len(hostnames_to_resolve)

                print(f"[+] Enumerated {count} computers from Active Directory")

                # Always query Domain Controllers (needed for --krb-dc-only and CVE-2025-54918 detection)
                dc_hostnames = self._get_domain_controllers(conn, search_base, use_impacket)
                if dc_hostnames:
                    self.config.set_dc_hostnames(dc_hostnames)
                    if self.config.krb_dc_only:
                        print(f"[+] Found {len(dc_hostnames)} Domain Controller(s) for --krb-dc-only:")
                        for dc in sorted(dc_hostnames):
                            print(f"    - {dc}")
                    elif self.config.verbose >= 2:
                        print(f"[+] Found {len(dc_hostnames)} Domain Controller(s)")
                else:
                    if self.config.krb_dc_only:
                        print("[!] Warning: Could not enumerate Domain Controllers, --krb-dc-only may not work correctly")
                    elif self.config.verbose >= 2:
                        print("[!] Warning: Could not enumerate Domain Controllers")

                # Filter to only hosts that resolve in DNS
                print(f"[*] Checking DNS resolution for {len(hostnames_to_resolve)} hosts...")
                resolved_hosts = self._check_dns_resolution(hostnames_to_resolve)
                print(f"[+] {len(resolved_hosts)} hosts resolved in DNS")

                for host in resolved_hosts:
                    self.targets.add(host)

                if not use_impacket:
                    conn.unbind()

            except ImportError:
                print("[!] ldap3 library not found, trying alternative method")
                # Fallback: could implement with impacket's LDAP
                self._enumerate_ad_impacket(dc_ip)

        except Exception as e:
            print(f"[!] Error enumerating AD: {e}")
            if self.config.verbose >= 2:
                import traceback
                traceback.print_exc()

    def _get_domain_controllers(self, conn, search_base: str, use_impacket: bool) -> Set[str]:
        """
        Query AD for Domain Controllers (members of 'Domain Controllers' group)

        Returns set of DC hostnames
        """
        dc_hostnames = set()

        try:
            if use_impacket:
                # Use impacket's search method
                from impacket.ldap import ldapasn1 as ldapasn1_impacket

                # Search for computers with userAccountControl containing SERVER_TRUST_ACCOUNT (0x2000)
                # This flag indicates a Domain Controller
                search_filter = '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

                resp = conn.search(
                    searchBase=search_base,
                    searchFilter=search_filter,
                    attributes=['dNSHostName', 'name'],
                    scope=ldapasn1_impacket.Scope('wholeSubtree')
                )

                for item in resp:
                    if isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        hostname = None
                        name = None
                        for attr in item['attributes']:
                            attr_type = str(attr['type'])
                            if attr_type == 'dNSHostName':
                                hostname = str(attr['vals'][0])
                            elif attr_type == 'name':
                                name = str(attr['vals'][0])

                        final_hostname = hostname or name
                        if final_hostname:
                            dc_hostnames.add(final_hostname.lower())
            else:
                # Use ldap3
                from ldap3 import SUBTREE

                # Search for Domain Controllers (SERVER_TRUST_ACCOUNT = 0x2000 = 8192)
                conn.search(
                    search_base=search_base,
                    search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                    search_scope=SUBTREE,
                    attributes=['dNSHostName', 'name']
                )

                for entry in conn.entries:
                    hostname = None
                    if entry.dNSHostName:
                        hostname = str(entry.dNSHostName)
                    elif entry.name:
                        hostname = str(entry.name)

                    if hostname:
                        dc_hostnames.add(hostname.lower())

        except Exception as e:
            if self.config.verbose >= 2:
                print(f"[!] Error querying Domain Controllers: {e}")

        return dc_hostnames

    def _enumerate_ad_impacket(self, dc_ip: str):
        """Alternative AD enumeration using impacket"""
        # This is a placeholder for impacket-based LDAP enumeration
        # The ldap3 method above is preferred
        print("[!] Impacket-based LDAP enumeration not yet implemented")
        print("[!] Please install ldap3: pip install ldap3")

    def _ping_sweep(self, ip_list: List[str]) -> List[str]:
        """Ping sweep to find live hosts"""
        live_hosts = []

        # Determine ping command based on OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'

        def ping_host(ip):
            """Ping a single host"""
            try:
                # Use subprocess with timeout
                result = subprocess.run(
                    ['ping', param, '1', '-W' if platform.system().lower() != 'windows' else '-w', '1', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                return ip if result.returncode == 0 else None
            except:
                return None

        # Multi-threaded ping sweep
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)

        return live_hosts

    def _check_dns_resolution(self, hostnames: List[str]) -> List[str]:
        """Check which hostnames resolve in DNS"""
        from concurrent.futures import wait, ALL_COMPLETED
        import time

        resolved = []
        custom_ns = self.config.nameserver
        use_tcp = self.config.dns_tcp

        if custom_ns:
            print(f"[*] Using custom DNS server: {custom_ns}")
        if use_tcp:
            print(f"[*] Using TCP for DNS resolution")

        def resolve_host(hostname):
            """Try to resolve a single hostname with timeout"""
            try:
                if custom_ns or use_tcp:
                    # Use dnspython for custom DNS server or TCP mode
                    try:
                        import dns.resolver
                        import dns.rdatatype
                        resolver = dns.resolver.Resolver()
                        if custom_ns:
                            # Resolve the nameserver hostname to IP if needed
                            try:
                                import socket as sock
                                ns_ip = sock.gethostbyname(custom_ns)
                                resolver.nameservers = [ns_ip]
                            except Exception:
                                resolver.nameservers = [custom_ns]
                        resolver.timeout = 3
                        resolver.lifetime = 3

                        if use_tcp:
                            # Use TCP instead of UDP
                            import dns.query
                            import dns.message
                            query = dns.message.make_query(hostname, dns.rdatatype.A)
                            ns_to_use = resolver.nameservers[0] if resolver.nameservers else '8.8.8.8'
                            response = dns.query.tcp(query, ns_to_use, timeout=3)
                            if response.answer:
                                for rrset in response.answer:
                                    for rdata in rrset:
                                        ip = str(rdata)
                                        if _is_valid_unicast_ip(ip):
                                            return hostname
                            return None
                        else:
                            # Standard UDP resolution
                            answers = resolver.resolve(hostname, 'A')
                            ip = str(answers[0])
                            if _is_valid_unicast_ip(ip):
                                return hostname
                            return None
                    except ImportError:
                        # dnspython not installed - only warn once (handled outside)
                        raise ImportError("dnspython required for custom DNS or --dns-tcp")
                    except Exception:
                        return None

                # Use system DNS resolver
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3)  # 3 second DNS timeout per host
                try:
                    ip = socket.gethostbyname(hostname)
                    # Filter out invalid IPs (multicast, loopback, etc.)
                    if _is_valid_unicast_ip(ip):
                        return hostname
                    return None
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except (socket.gaierror, socket.timeout):
                return None
            except ImportError:
                raise  # Re-raise to handle at caller level
            except Exception:
                return None

        # Multi-threaded DNS resolution - complete all lookups
        print(f"[*] Starting DNS resolution check...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(resolve_host, host): host for host in hostnames}

            # Process results as they complete, with progress updates
            completed_count = 0
            last_update = 0

            for future in as_completed(futures):
                completed_count += 1

                # Collect result
                try:
                    result = future.result(timeout=0.1)
                    if result:
                        resolved.append(result)
                except Exception:
                    pass

                # Progress update every 100 hosts or every 10 seconds
                elapsed = time.time() - start_time
                if completed_count % 100 == 0 or elapsed - last_update > 10:
                    print(f"[*] DNS check progress: {completed_count}/{len(hostnames)} ({elapsed:.1f}s elapsed)")
                    last_update = elapsed

        elapsed = time.time() - start_time
        print(f"[*] DNS check completed in {elapsed:.1f}s")

        return resolved
