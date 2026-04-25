"""
Relay Attack Path Analyzer
Identifies and prioritizes viable relay attack paths
"""

from dataclasses import dataclass
from typing import List, Dict
from enum import Enum


class RelayImpact(Enum):
    """Impact levels for relay attacks"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class RelayPath:
    """Represents a relay attack path"""
    source_host: str
    source_protocol: str
    dest_host: str
    dest_protocol: str
    impact: RelayImpact
    description: str
    ntlmv1_required: bool = False
    source_ips: List[str] = None  # Resolved IP addresses for source host
    dest_ips: List[str] = None  # Resolved IP addresses for dest host

    def __post_init__(self):
        """Initialize empty lists for IPs if not provided"""
        if self.source_ips is None:
            self.source_ips = []
        if self.dest_ips is None:
            self.dest_ips = []


class RelayAnalyzer:
    """Analyzes scan results to identify relay opportunities"""

    # High-value service indicators (hostname-based heuristics)
    SCCM_INDICATORS = ['sccm', 'mecm', 'configmgr']
    # Note: 'ca' is intentionally excluded - it matches too many hostnames (Exchange CAS, etc.)
    # ADCS detection relies on LDAP pKIEnrollmentService queries or HTTP /certsrv/ detection
    ADCS_INDICATORS = ['certsrv', 'pki']

    def __init__(self, config, tier0_assets: set = None):
        self.config = config
        # LDAP-detected tier-0 assets (more accurate than hostname heuristics)
        self.tier0_assets = tier0_assets or set()

    def skeleton(self, all_results: Dict[str, Dict] = {}, ntlmv1_analysis: Dict = None) -> Dict:
        analysis = {
            'relay_paths': [],
            'high_value_targets': {
                'sccm': [],
                'adcs': [],
            },
            'statistics': {
                'total_hosts': len(all_results),
                'relayable_hosts': 0,
                'critical_paths': 0,
                'high_paths': 0,
                'medium_paths': 0,
                'low_paths': 0,
            },
            'ntlmv1_analysis': ntlmv1_analysis
        }
        return analysis

    def analyze(self, all_results: Dict[str, Dict], ntlmv1_analysis: Dict = None) -> Dict:
        """
        Analyze all scan results and identify relay paths

        Args:
            all_results: dict of {host: {protocol: ProtocolResult, ...}}
            ntlmv1_analysis: optional NTLMv1 analysis results from scanner

        Returns:
            dict with relay paths, high-value targets, statistics
        """
        analysis = self.skeleton(all_results, ntlmv1_analysis)
        """
        analysis = {
            'relay_paths': [],
            'high_value_targets': {
                'sccm': [],
                'adcs': [],
            },
            'statistics': {
                'total_hosts': len(all_results),
                'relayable_hosts': 0,
                'critical_paths': 0,
                'high_paths': 0,
                'medium_paths': 0,
                'low_paths': 0,
            },
            'ntlmv1_analysis': ntlmv1_analysis
        }
        """

        # Identify relay paths for each host
        for host, protocol_results in all_results.items():
            # Check for high-value targets
            self._identify_high_value_targets(host, protocol_results, analysis)

            # Find relay paths
            paths = self._find_relay_paths(host, protocol_results, all_results, ntlmv1_analysis)

            for path in paths:
                analysis['relay_paths'].append(path)

                # Update statistics
                if path.impact == RelayImpact.CRITICAL:
                    analysis['statistics']['critical_paths'] += 1
                elif path.impact == RelayImpact.HIGH:
                    analysis['statistics']['high_paths'] += 1
                elif path.impact == RelayImpact.MEDIUM:
                    analysis['statistics']['medium_paths'] += 1
                else:
                    analysis['statistics']['low_paths'] += 1

            # Check if any protocol is relayable
            if any(pr.is_relayable() for pr in protocol_results.values() if hasattr(pr, 'is_relayable')):
                analysis['statistics']['relayable_hosts'] += 1

        # Sort paths by impact, then by destination protocol, then by source protocol, then by host
        impact_order = {
            RelayImpact.CRITICAL: 0,
            RelayImpact.HIGH: 1,
            RelayImpact.MEDIUM: 2,
            RelayImpact.LOW: 3
        }

        # Protocol priority for better grouping (specific protocols before 'any'/'multiple')
        def protocol_sort_key(protocol):
            if protocol == 'any':
                return 'zzz_any'
            elif protocol == 'multiple':
                return 'zzz_multiple'
            else:
                return protocol

        analysis['relay_paths'].sort(key=lambda p: (
            impact_order[p.impact],
            protocol_sort_key(p.dest_protocol),
            protocol_sort_key(p.source_protocol),
            p.source_host
        ))

        return analysis

    def _identify_high_value_targets(self, host: str, protocol_results: Dict, analysis: Dict):
        """Identify SCCM and ADCS servers"""

        host_lower = host.lower()

        # Check for SCCM
        if any(indicator in host_lower for indicator in self.SCCM_INDICATORS):
            analysis['high_value_targets']['sccm'].append(host)

        # Only check for ADCS via actual /certsrv/ detection, not hostname heuristics
        # Hostname heuristics are unreliable (e.g., 'ca' matches Exchange CAS servers)
        for proto in ['http', 'https']:
            if proto in protocol_results:
                result = protocol_results[proto]
                if result.available and result.additional_info.get('is_adcs'):
                    if host not in analysis['high_value_targets']['adcs']:
                        analysis['high_value_targets']['adcs'].append(host)

    def _find_relay_paths(self, host: str, protocol_results: Dict, all_results: Dict, ntlmv1_analysis: Dict = None) -> List[RelayPath]:
        """Find relay paths for a specific host"""

        paths = []

        # Extract resolved IPs from protocol results metadata
        host_ips = protocol_results.get('_target_ips', [])

        # Skip non-Windows hosts (Linux, Unix, etc.) - NTLM relay only relevant for Windows
        if 'smb' in protocol_results:
            smb_result = protocol_results['smb']
            server_os = smb_result.additional_info.get('server_os', '').lower()
            if server_os and 'windows' not in server_os:
                # Non-Windows host - skip relay path analysis
                return paths

        # Check each protocol to see if it's relayable (as a destination)
        for dest_protocol, dest_result in protocol_results.items():
            if not hasattr(dest_result, 'is_relayable'):
                continue

            if dest_result.is_relayable():
                # This protocol is a valid relay destination
                impact = self._calculate_impact(dest_protocol, host, dest_result)
                description = self._generate_description(dest_protocol, host, dest_result)

                # Create a path (for simplicity, source is also the host)
                # In real scenarios, you'd relay from one host to another
                path = RelayPath(
                    source_host=host,
                    source_protocol='any',  # Any source that can coerce auth
                    dest_host=host,
                    dest_protocol=dest_protocol,
                    impact=impact,
                    description=description,
                    source_ips=host_ips,
                    dest_ips=host_ips
                )

                paths.append(path)

        # Check for cross-protocol relay opportunities (REQUIRES NTLMv1)
        # NTLMv2 includes a MIC (Message Integrity Code) that prevents cross-protocol relay.
        # NTLMv1 doesn't support MIC computation, so cross-protocol relay is only possible
        # when NTLMv1 is enabled (LmCompatibilityLevel <= 2).
        # This path is now generated in _find_ntlmv1_paths() when NTLMv1 is detected.

        # Check for NTLMv1 relay paths
        if ntlmv1_analysis:
            ntlmv1_paths = self._find_ntlmv1_paths(host, protocol_results, ntlmv1_analysis, host_ips)
            paths.extend(ntlmv1_paths)

        # Check for NTLM reflection vulnerability
        if 'ntlm_reflection' in protocol_results:
            reflection_result = protocol_results['ntlm_reflection']
            if reflection_result.get('vulnerable'):
                protocols_list = '/'.join(reflection_result.get('paths', []))
                path = RelayPath(
                    source_host=host,
                    source_protocol='smb',
                    dest_host=host,
                    dest_protocol='multiple',
                    impact=RelayImpact.HIGH,
                    description=f"CVE-2025-33073: Relay credentials from SMB to {protocols_list} on {host}",
                    source_ips=host_ips,
                    dest_ips=host_ips
                )
                paths.append(path)

            # Check for CVE-2025-54918 (unpatched Server 2025)
            # CRITICAL: DC with PrintSpooler enabled (RPC coercion -> LDAPS reflection)
            # MEDIUM:   any other unpatched Server 2025 host
            cve_54918 = reflection_result.get('cve_2025_54918')
            if cve_54918 and cve_54918.get('vulnerable'):
                is_dc = cve_54918.get('is_dc', False)
                spooler = cve_54918.get('printspooler_enabled', False)
                build_str = cve_54918.get('build', '')

                if is_dc and spooler:
                    path = RelayPath(
                        source_host=host,
                        source_protocol='rpc',
                        dest_host=host,
                        dest_protocol='ldaps',
                        impact=RelayImpact.CRITICAL,
                        description=(
                            f"CVE-2025-54918: Server 2025 DC with PrintSpooler enabled on {host} - "
                            f"Coerce via RPC, reflect to LDAPS (bypasses channel binding). "
                            f"Build {build_str} is unpatched."
                        ),
                        source_ips=host_ips,
                        dest_ips=host_ips,
                    )
                else:
                    role = "DC (PrintSpooler not confirmed)" if is_dc else "non-DC host"
                    path = RelayPath(
                        source_host=host,
                        source_protocol='any',
                        dest_host=host,
                        dest_protocol='any',
                        impact=RelayImpact.MEDIUM,
                        description=(
                            f"CVE-2025-54918: Server 2025 {role} on {host} is unpatched "
                            f"(build {build_str}) - vulnerable to NTLM reflection."
                        ),
                        source_ips=host_ips,
                        dest_ips=host_ips,
                    )
                paths.append(path)

            # Check for CVE-2019-1040 (Drop the MIC) - HIGH severity relay risk
            cve_1040 = reflection_result.get('cve_2019_1040')
            if cve_1040 and cve_1040.get('vulnerable'):
                build_str = cve_1040.get('build', '')
                path = RelayPath(
                    source_host=host,
                    source_protocol='smb',
                    dest_host=host,
                    dest_protocol='ldap',
                    impact=RelayImpact.HIGH,
                    description=(
                        f"CVE-2019-1040 (Drop the MIC): {host} running Windows {build_str} is unpatched - "
                        f"MIC can be stripped from NTLM messages enabling cross-protocol relay "
                        f"(SMB -> LDAP/LDAPS). Use ntlmrelayx with --remove-mic."
                    ),
                    source_ips=host_ips,
                    dest_ips=host_ips,
                )
                paths.append(path)

        # Check for WebDAV/WebClient service
        if 'webdav' in protocol_results:
            webdav_result = protocol_results['webdav']
            if webdav_result.get('enabled'):
                path = RelayPath(
                    source_host=host,
                    source_protocol='webdav',
                    dest_host='any',
                    dest_protocol='any',
                    impact=RelayImpact.HIGH,
                    description=f"WebClient service enabled on {host} - can be coerced to authenticate to attacker-controlled WebDAV share",
                    source_ips=host_ips,
                    dest_ips=[]  # Destination is 'any', so no specific IPs
                )
                paths.append(path)

        return paths

    def _find_ntlmv1_paths(self, host: str, protocol_results: Dict, ntlmv1_analysis: Dict, host_ips: List[str] = None) -> List[RelayPath]:
        """
        Find NTLMv1-specific relay paths based on analysis results.

        NTLMv1 enables cross-protocol relay attacks because NTLMv1 doesn't support
        computing a MIC (Message Integrity Code). With NTLMv2, the MIC binds the
        authentication to the specific protocol, preventing cross-protocol relay.
        When NTLMv1 is enabled (LmCompatibilityLevel <= 2), we can use --remove-mic
        in ntlmrelayx to perform cross-protocol relay (e.g., SMB -> LDAP).
        """

        paths = []
        if host_ips is None:
            host_ips = []

        if not ntlmv1_analysis:
            return paths

        # Check if SMB and LDAP are available on this host (for cross-protocol relay)
        smb_available = 'smb' in protocol_results and protocol_results['smb'].available
        ldap_available = 'ldap' in protocol_results and protocol_results['ldap'].available
        ldaps_available = 'ldaps' in protocol_results and protocol_results['ldaps'].available

        # Helper to check if LDAP signing/channel binding would normally protect
        ldap_relayable = 'ldap' in protocol_results and protocol_results['ldap'].is_relayable()
        ldaps_relayable = 'ldaps' in protocol_results and protocol_results['ldaps'].is_relayable()

        # Check domain-wide NTLMv1 policy
        domain_policy = ntlmv1_analysis.get('domain_policy')
        ntlmv1_domain_enabled = domain_policy and domain_policy.get('enabled')

        # Check per-host NTLMv1 support
        vulnerable_hosts = ntlmv1_analysis.get('vulnerable_hosts', {})
        ntlmv1_host_enabled = host in vulnerable_hosts
        host_level = vulnerable_hosts.get(host, {}).get('level', 'unknown') if ntlmv1_host_enabled else None

        # Generate paths if NTLMv1 is enabled (domain-wide or per-host)
        if ntlmv1_domain_enabled or ntlmv1_host_enabled:
            # Determine the NTLMv1 source description
            if ntlmv1_domain_enabled:
                ntlmv1_source = "Domain-wide NTLMv1 enabled"
            else:
                ntlmv1_source = f"LmCompatibilityLevel={host_level}"

            # Cross-protocol relay: SMB -> LDAP (only possible with NTLMv1)
            # This is the key attack path - coerce SMB auth and relay to LDAP
            if smb_available and ldap_available:
                path = RelayPath(
                    source_host=host,
                    source_protocol='smb',
                    dest_host=host,
                    dest_protocol='ldap',
                    impact=RelayImpact.CRITICAL,
                    description=f"Cross-protocol relay: SMB -> LDAP on {host} - {ntlmv1_source} (can create computer accounts, modify ACLs with --remove-mic)",
                    ntlmv1_required=True,
                    source_ips=host_ips,
                    dest_ips=host_ips
                )
                paths.append(path)

            # Cross-protocol relay: SMB -> LDAPS
            if smb_available and ldaps_available:
                path = RelayPath(
                    source_host=host,
                    source_protocol='smb',
                    dest_host=host,
                    dest_protocol='ldaps',
                    impact=RelayImpact.CRITICAL,
                    description=f"Cross-protocol relay: SMB -> LDAPS on {host} - {ntlmv1_source} (can create computer accounts, modify ACLs with --remove-mic)",
                    ntlmv1_required=True,
                    source_ips=host_ips,
                    dest_ips=host_ips
                )
                paths.append(path)

            # Also note if LDAP signing/channel binding can be bypassed even for same-protocol
            # This is relevant when LDAP signing IS enforced but NTLMv1 allows bypass
            if ldap_available and not ldap_relayable:
                # LDAP signing is enforced, but NTLMv1 allows bypass with --remove-mic
                path = RelayPath(
                    source_host=host,
                    source_protocol='any',
                    dest_host=host,
                    dest_protocol='ldap',
                    impact=RelayImpact.CRITICAL,
                    description=f"NTLMv1 relay to LDAP on {host} - {ntlmv1_source} (bypasses LDAP signing with --remove-mic)",
                    ntlmv1_required=True,
                    source_ips=host_ips,
                    dest_ips=host_ips
                )
                paths.append(path)

            if ldaps_available and not ldaps_relayable:
                # LDAPS channel binding is enforced, but NTLMv1 allows bypass with --remove-mic
                path = RelayPath(
                    source_host=host,
                    source_protocol='any',
                    dest_host=host,
                    dest_protocol='ldaps',
                    impact=RelayImpact.CRITICAL,
                    description=f"NTLMv1 relay to LDAPS on {host} - {ntlmv1_source} (bypasses channel binding with --remove-mic)",
                    ntlmv1_required=True,
                    source_ips=host_ips,
                    dest_ips=host_ips
                )
                paths.append(path)

        return paths

    def _calculate_impact(self, protocol: str, host: str, result=None) -> RelayImpact:
        """Calculate impact level for relay to this protocol"""

        # LDAP/LDAPS = CRITICAL (can create computer accounts, modify ACLs)
        if protocol in ['ldap', 'ldaps']:
            return RelayImpact.CRITICAL

        # SMB/MSSQL = HIGH (file access, potential code execution)
        if protocol in ['smb', 'mssql']:
            return RelayImpact.HIGH

        # HTTP/HTTPS - CRITICAL for ADCS or tier-0/high-value targets, otherwise MEDIUM
        if protocol in ['http', 'https']:
            # Check if this is an ADCS server (detected via /certsrv/ endpoint)
            if result and hasattr(result, 'additional_info') and result.additional_info.get('is_adcs'):
                return RelayImpact.CRITICAL
            if self._is_high_value_target(host):
                return RelayImpact.CRITICAL
            return RelayImpact.MEDIUM

        # Other protocols = LOW
        return RelayImpact.LOW

    def _is_high_value_target(self, host: str) -> bool:
        """
        Check if a host is a high-value/tier-0 target.

        Uses LDAP-detected tier-0 assets first (more accurate),
        falls back to hostname-based heuristics.
        """
        host_lower = host.lower()

        # Check LDAP-detected tier-0 assets first (exact match and short hostname match)
        if self.tier0_assets:
            if host_lower in self.tier0_assets:
                return True
            # Also check short hostname match (handle FQDN vs hostname mismatch)
            host_short = host_lower.split('.')[0]
            for asset in self.tier0_assets:
                asset_lower = asset.lower()
                asset_short = asset_lower.split('.')[0]
                if host_short == asset_short or host_lower == asset_lower or asset_lower == host_short:
                    return True

        # Fall back to hostname-based heuristics (SCCM/ADCS indicators)
        if any(ind in host_lower for ind in self.SCCM_INDICATORS + self.ADCS_INDICATORS):
            return True

        return False

    def _generate_description(self, protocol: str, host: str, result=None) -> str:
        """Generate description for relay path"""

        # Check for ADCS-specific description
        if protocol in ['http', 'https']:
            if result and hasattr(result, 'additional_info'):
                info = result.additional_info
                if info.get('is_adcs'):
                    return (f"ADCS relay to {protocol.upper()} on {host} - "
                            f"Certificate enrollment abuse (ESC8), potential domain compromise")
                if info.get('adcs_unconfirmed'):
                    return (f"Relay to {protocol.upper()} on {host} - "
                            f"/certsrv/ matched but ADCS unconfirmed (catchall NTLM site)")

        descriptions = {
            'ldap': f"Relay to LDAP on {host} - Can create computer accounts, modify ACLs (RBCD, DACL abuse)",
            'ldaps': f"Relay to LDAPS on {host} - Can create computer accounts, modify ACLs (RBCD, DACL abuse)",
            'smb': f"Relay to SMB on {host} - File system access, potential code execution via services",
            'mssql': f"Relay to MSSQL on {host} - Database access, potential code execution via xp_cmdshell",
            'http': f"Relay to HTTP on {host} - Application access (no EPA possible on plaintext)",
            'https': f"Relay to HTTPS on {host} - Application access (EPA not enforced)",
        }

        return descriptions.get(protocol, f"Relay to {protocol} on {host}")

    def add_ghost_spn_paths(self, analysis: Dict, ghost_spn_results: Dict, max_paths: int = 5):
        """
        Inject up to max_paths Ghost SPN relay paths into analysis['relay_paths'].

        All findings are capped at max_paths entries in the report to avoid clutter.
        The caller is responsible for writing the full list to a separate file.
        ghost_spn_results is mutated to record truncation metadata.
        """
        impact_order = {
            RelayImpact.CRITICAL: 0,
            RelayImpact.HIGH: 1,
            RelayImpact.MEDIUM: 2,
            RelayImpact.LOW: 3,
        }

        # Combine all findings, prioritising definite (no DNS) over probable (wildcard)
        all_findings = []
        for finding in ghost_spn_results.get('vulnerable', []):
            all_findings.append(('vulnerable', finding))
        for finding in ghost_spn_results.get('probably_vulnerable', []):
            all_findings.append(('probably_vulnerable', finding))

        total = len(all_findings)
        shown = all_findings[:max_paths]
        truncated = total > max_paths

        # Record truncation metadata so formatters can reference the output file
        ghost_spn_results['_total_findings'] = total
        ghost_spn_results['_truncated'] = truncated

        for kind, finding in shown:
            if kind == 'vulnerable':
                description = (
                    f"Ghost SPN: '{finding.get('spn')}' is registered to '{finding.get('account')}' "
                    f"but '{finding.get('hostname')}' has no DNS record - "
                    f"Register this DNS name to receive NTLM authentication and relay it."
                )
            else:
                resolved = ', '.join(finding.get('resolved_to', []))
                description = (
                    f"Ghost SPN (wildcard DNS): '{finding.get('spn')}' registered to "
                    f"'{finding.get('account')}' - '{finding.get('hostname')}' resolves to "
                    f"{resolved or 'wildcard'} via wildcard DNS. May be exploitable for NTLM relay."
                )

            path = RelayPath(
                source_host=finding.get('account', 'unknown'),
                source_protocol='ghost_spn',
                dest_host=finding.get('hostname', 'unknown'),
                dest_protocol='any',
                impact=RelayImpact.MEDIUM,
                description=description,
                source_ips=[],
                dest_ips=[],
            )
            analysis['relay_paths'].append(path)
            analysis['statistics']['medium_paths'] += 1

        # Re-sort so Ghost SPN paths sit alongside other MEDIUM findings
        analysis['relay_paths'].sort(key=lambda p: impact_order[p.impact])
