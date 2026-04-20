"""
RelayKing Scanner
Main scanning orchestration and coordination
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
import os
import sys
import socket
import string
import datetime

try:
    import dns.resolver
    import dns.query
    import dns.message
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from .target_parser import TargetParser, _is_valid_unicast_ip
from .relay_analyzer import RelayAnalyzer
from .port_scanner import FastPortScanner
from .creds_checker import CredentialChecker ## added
from protocols.smb_detector import SMBDetector
from protocols.http_detector import HTTPDetector, HTTPSDetector
from protocols.ldap_detector import LDAPDetector, LDAPSDetector
from protocols.mssql_detector import MSSQLDetector
from protocols.rpc_detector import RPCDetector
from protocols.additional_detectors import (
    SMTPDetector, IMAPDetector, IMAPSDetector,
    WINRMDetector, WINRMSDetector
)
from detectors.webdav_detector import WebDAVDetector
from detectors.ntlm_reflection import NTLMReflectionDetector
from detectors.ntlmv1_detector import NTLMv1Detector
from detectors.coercion import CoercionDetector
from detectors.ghost_spn import GhostSPNDetector


class RelayKingScanner:
    """Main scanner class"""

    # Default protocols to scan (HTTP/HTTPS only scanned on high-value targets)
    DEFAULT_PROTOCOLS = ['smb', 'ldap', 'ldaps', 'mssql']

    # High-value target indicators (SCCM/ADCS)
    # Note: 'ca' is intentionally excluded - it matches too many hostnames (Exchange CAS, etc.)
    # ADCS detection relies on LDAP pKIEnrollmentService queries or HTTP /certsrv/ detection
    HIGH_VALUE_INDICATORS = ['sccm', 'mecm', 'configmgr', 'certsrv', 'pki']

    # Protocol to detector mapping
    PROTOCOL_DETECTORS = {
        'smb': (SMBDetector, 445),
        'http': (HTTPDetector, 80),
        'https': (HTTPSDetector, 443),
        'ldap': (LDAPDetector, 389),
        'ldaps': (LDAPSDetector, 636),
        'mssql': (MSSQLDetector, 1433),
        'rpc': (RPCDetector, 135),
        'smtp': (SMTPDetector, 25),
        'imap': (IMAPDetector, 143),
        'imaps': (IMAPSDetector, 993),
        'winrm': (WINRMDetector, 5985),
        'winrms': (WINRMSDetector, 5986),
    }

    def __init__(self, config, session=None):
        self.config = config
        self.target_parser = TargetParser(config)
        # RelayAnalyzer is initialized later after target parsing to get tier-0 assets
        self.relay_analyzer = None
        self.cred_checker = CredentialChecker(config)
        self.all_targets = []
        self.session = session  # SessionManager instance (or None)
        # Ghost SPN results cached here so the AD query only fires once across multi-group scans
        self._ghost_spn_results = None

    def prepare(self) -> Dict:
        """
        Prepare for scan
            - check credential
            - prepare target list (or load from session)

        Returns:
            dict with status, details and number_of_target
        """

        # Check if given credential is valid
        creds_status = self.cred_checker.check_creds()
        if creds_status['status'] != "Success":
            print(f"[*] Given credential looks invalid: {creds_status['error']}\nExitting ...")
            return {
                'status': "Invalid_credential",
                'details': creds_status['error'],
                'number_of_target': 0
            }
        else:
            print("[*] Given credential looks valid. Good to move forward")

        # If resuming from session, load targets instead of re-enumerating
        if self.session and self.config.session_resume:
            phase = self.session.get_phase()
            print(f"[*] Resuming from session file (phase: {phase})")

            # Load targets from session
            self.all_targets = self.session.get_targets()

            # Restore tier-0 assets and DC hostnames
            self.target_parser.tier0_assets = self.session.get_tier0_assets()
            dc_hostnames = self.session.get_dc_hostnames()
            if dc_hostnames:
                self.config.set_dc_hostnames(dc_hostnames)

            if self.target_parser.tier0_assets:
                print(f"[+] Restored {len(self.target_parser.tier0_assets)} tier-0 asset(s) from session")
            if dc_hostnames:
                print(f"[+] Restored {len(dc_hostnames)} DC hostname(s) from session")

            completed = self.session.get_completed_hosts()
            print(f"[+] Restored {len(self.all_targets)} target(s) from session ({len(completed)} already scanned)")

            if not self.all_targets:
                print("[!] No targets in session file")
                return {
                    'status': "No target to scan",
                    'details': "",
                    'number_of_target': 0
                }

            return {
                'status': "Success",
                'details': "",
                'number_of_target': len(self.all_targets)
            }

        # Normal flow: parse targets from scratch
        print("[*] Parsing targets...")
        self.all_targets = self.target_parser.parse_targets()
        
        # Write target to file - for better observability
        base_path = os.path.dirname(os.path.abspath(self.config.output_file))
        timestamp = format(datetime.datetime.now(), '%Y%m%d_%H%M%S')
        target_file = os.path.join(base_path, f"target_{timestamp}.txt")
        try:
            with open(target_file, 'w') as f:
                f.write('\n'.join(self.all_targets) + '\n')
            print(f"\n[+] Scan target list written to: {target_file}")
            print(f"    Contains {len(self.all_targets)} scan target(s)")
        except Exception as e:
            print(f"\n[!] Error writing target list to {target_file}: {e}")

        if not self.all_targets:
            print("[!] No targets to scan")
            return {
                'status': "No target to scan",
                'details': "",
                'number_of_target': 0
            }

        # Save to session if active (--audit creates session automatically)
        if self.session:
            self.session.set_targets(self.all_targets)
            self.session.set_tier0_assets(self.target_parser.tier0_assets)
            self.session.set_dc_hostnames(self.config._dc_hostnames)
            self.session.set_phase('targets_ready')

        print(f"[+] Found {len(self.all_targets)} target(s)")
        return {
            'status': "Success",
            'details': "",
            'number_of_target': len(self.all_targets)
        }

    def scan(self, start_idx, end_idx) -> Dict:
        """
        Run the scan

        Returns:
            dict with all results, analysis, and statistics
        """


        # Special mode: --coerce-all (only coerce, no protocol scanning)
        if self.config.coerce_all:
            return self._coerce_all_mode(start_idx, end_idx)

        # Initialize RelayAnalyzer with tier-0 assets from target parsing
        self.relay_analyzer = RelayAnalyzer(self.config, self.target_parser.tier0_assets)

        targets = self.all_targets[start_idx:end_idx]
        analysis = self.relay_analyzer.skeleton()
        all_results = {}

        # If resuming, load previously completed host results for this group
        completed_hosts_in_session = set()
        if self.session and self.config.session_resume:
            completed_hosts_in_session = self.session.get_completed_hosts()
            restored = self.session.get_completed_host_results()
            # Only restore results for hosts in this group's target range
            for target in targets:
                if target in restored:
                    all_results[target] = restored[target]

            remaining = [t for t in targets if t not in completed_hosts_in_session]
            if remaining:
                print(f"[*] Resuming: {len(targets) - len(remaining)} hosts restored from session, {len(remaining)} remaining")
            else:
                print(f"[*] All {len(targets)} hosts in this group already scanned (from session)")
        else:
            remaining = list(targets)

        try:

            # Determine which protocols to scan
            protocols = self.config.protocols if self.config.protocols else self.DEFAULT_PROTOCOLS

            # Ensure SMB is always scanned when not in null-auth mode (required for NTLM reflection detection)
            if not self.config.null_auth and 'smb' not in protocols:
                protocols = protocols.copy()  # Don't modify the original
                protocols.insert(0, 'smb')  # Add SMB at the beginning

            print(f"[*] Scanning protocols: {', '.join(protocols)}")
            if self.config.protocols is None and not self.config.null_auth:
                print(f"[*] Note: HTTP/HTTPS will be scanned on tier-0 assets only")
            elif self.config.protocols is not None:
                # User explicitly specified protocols - check if HTTP/HTTPS included
                if 'http' in protocols or 'https' in protocols:
                    print(f"[!] WARNING: HTTP/HTTPS path enumeration enabled - scan will take significantly longer")
                    print(f"[*] Each HTTP/HTTPS host will be scanned against ~50 NTLM-enabled paths")
            print(f"[*] Using {self.config.threads} threads")
            print()

            # Fast port scan if --proto-portscan enabled
            port_scan_results = {}
            if self.config.proto_portscan:
                # If resuming and we have port scan results from session, use those
                if self.session and self.config.session_resume:
                    session_port_results = self.session.get_port_scan_results()
                    if session_port_results:
                        # Use session results for already-scanned hosts, scan the rest
                        hosts_needing_portscan = [t for t in remaining if t not in session_port_results]
                        # Restore session results for all known hosts in this group
                        for target in targets:
                            if target in session_port_results:
                                port_scan_results[target] = session_port_results[target]

                        if hosts_needing_portscan:
                            print(f"[*] Running fast port scan on {len(hosts_needing_portscan)} new hosts ({len(targets) - len(hosts_needing_portscan)} restored from session)...")
                            port_scanner = FastPortScanner(timeout=0.1)
                            protocols_for_portscan = protocols.copy()
                            if self.target_parser.tier0_assets:
                                if 'http' not in protocols_for_portscan:
                                    protocols_for_portscan.append('http')
                                if 'https' not in protocols_for_portscan:
                                    protocols_for_portscan.append('https')
                            new_port_results = port_scanner.scan_hosts(hosts_needing_portscan, protocols_for_portscan, threads=50)
                            port_scan_results.update(new_port_results)

                            # Save new port scan results to session
                            if self.session:
                                self.session.set_port_scan_results(port_scan_results)
                                self.session.save()
                        else:
                            print(f"[+] Port scan results restored from session for all hosts")
                    else:
                        # No port scan results in session - scan from scratch
                        port_scan_results = self._run_port_scan(remaining, protocols)
                        if self.session:
                            self.session.set_port_scan_results(port_scan_results)
                            self.session.save()
                else:
                    port_scan_results = self._run_port_scan(targets, protocols)
                    # Save port scan results to session
                    if self.session:
                        self.session.set_port_scan_results(port_scan_results)
                        self.session.set_phase('port_scan_complete')

                # Count open ports
                total_open = sum(len(ports) for ports in port_scan_results.values())
                hosts_with_open = sum(1 for ports in port_scan_results.values() if ports)
                print(f"[+] Port scan complete: {total_open} open ports across {hosts_with_open} hosts")
                print()

            # Scan remaining targets (skip already-completed hosts)
            if remaining:
                if self.session:
                    self.session.set_phase('scanning')

                with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                    # Submit all scan tasks
                    future_to_target = {}

                    for target in remaining:
                        future = executor.submit(self._scan_target, target, protocols, port_scan_results)
                        future_to_target[future] = target

                    # Process results as they complete
                    completed = 0
                    total_to_scan = len(remaining)
                    for future in as_completed(future_to_target):
                        target = future_to_target[future]
                        completed += 1

                        try:
                            result = future.result()

                            # Resolve target IP and add to results
                            resolved_ips = self._resolve_target_ip(target)
                            result['_target_ips'] = resolved_ips  # Store IPs with underscore prefix to mark as metadata

                            all_results[target] = result

                            # Save to session (periodic flush handles disk writes)
                            if self.session:
                                self.session.mark_host_complete(target, result)
                                self.session.save_if_needed()

                            # Print progress
                            if self.config.verbose >= 1:
                                # Check if any protocol was actually available
                                has_available = any(
                                    hasattr(pr, 'available') and pr.available
                                    for pr in result.values()
                                    if not isinstance(pr, dict)
                                )

                                if has_available:
                                    # Show per-host status whenever we could connect
                                    relayable = any(
                                        pr.is_relayable() for pr in result.values()
                                        if hasattr(pr, 'is_relayable')
                                    )
                                    status = "RELAYABLE" if relayable else "PROTECTED"
                                    print(f"[{completed}/{total_to_scan}] {target}: {status}")
                                elif self.config.verbose >= 3:
                                    # -vvv: show every host, even offline/unreachable ones
                                    print(f"[{completed}/{total_to_scan}] {target}: OFFLINE")
                                else:
                                    # -v / -vv: keep a rolling counter so the scan looks alive
                                    sys.stdout.write(f"\r[*] Progress: {completed}/{total_to_scan}")
                                    sys.stdout.flush()
                            else:
                                sys.stdout.write(f"\r[*] Progress: {completed}/{total_to_scan}")
                                sys.stdout.flush()

                        except Exception as e:
                            if self.config.verbose >= 1:
                                print(f"[!] Error scanning {target}: {e}")

                # Newline after the rolling counter (used at verbose=0, and at verbose=1/2
                # for non-responding hosts; not needed at verbose>=3 which uses print())
                if self.config.verbose < 3:
                    print()

                # Final session flush after scanning completes
                if self.session:
                    self.session.save()

            # Check for NTLMv1 support first (before analysis)
            ntlmv1_analysis = None
            if self.config.check_ntlmv1 or self.config.check_ntlmv1_all:
                print("\n[*] Checking for NTLMv1 support...")
                ntlmv1_analysis = self._check_ntlmv1(targets, all_results)

            # Run analysis
            print("[*] Analyzing results...")
            analysis = self.relay_analyzer.analyze(all_results, ntlmv1_analysis)

            if self.config.check_coercion:
                print("[*] Checking for coercion vulnerabilities...")
                analysis['coercion'] = self._check_coercion(targets)

            # Ghost SPN check: --audit mode only, with credentials, and unless --no-ghosts suppresses it.
            # Results are cached on the scanner instance so the AD query only fires once even when
            # the scan is divided into multiple groups (--max-scangroup / --split-into).
            if (self.config.audit_mode and not self.config.no_ghosts
                    and not self.config.null_auth
                    and (self.config.dc_ip or self.config.domain)):
                if self._ghost_spn_results is None:
                    # First group: run the AD query and write the findings file
                    print("[*] Checking for Ghost SPN relay vulnerabilities...")
                    self._ghost_spn_results = self._check_ghost_spn()
                    if self._ghost_spn_results.get('error'):
                        if self.config.verbose >= 2:
                            print(f"[!] Ghost SPN check failed: {self._ghost_spn_results['error']}")
                    else:
                        vuln = len(self._ghost_spn_results.get('vulnerable', []))
                        prob = len(self._ghost_spn_results.get('probably_vulnerable', []))
                        checked = self._ghost_spn_results.get('checked', 0)
                        print(f"[+] Ghost SPN: {checked} SPN hostname(s) checked, {vuln} vulnerable, {prob} probably vulnerable")
                        if vuln or prob:
                            # Place the findings file alongside --output-file if specified,
                            # otherwise fall back to the working directory
                            if self.config.output_file:
                                output_dir = os.path.dirname(os.path.abspath(self.config.output_file))
                                ghost_spn_file = os.path.join(output_dir, 'possible-ghost-spns.txt')
                            else:
                                ghost_spn_file = 'possible-ghost-spns.txt'
                            self._write_ghost_spn_file(self._ghost_spn_results, ghost_spn_file)
                            self._ghost_spn_results['output_file'] = ghost_spn_file

                # Every group gets the cached results injected so Ghost SPN paths and the
                # file reference appear in each group's output (they are domain-wide findings)
                if not self._ghost_spn_results.get('error'):
                    if self._ghost_spn_results.get('vulnerable') or self._ghost_spn_results.get('probably_vulnerable'):
                        self.relay_analyzer.add_ghost_spn_paths(analysis, self._ghost_spn_results)
                analysis['ghost_spn'] = self._ghost_spn_results

        except KeyboardInterrupt:
            # Flush session before exiting so progress is saved
            if self.session:
                print("\n[*] Saving session progress...")
                self.session.save()
            print("\n[!] Scan interrupted by user")

        # Compile final results
        final_results = {
            'targets': targets,
            'results': all_results,
            'analysis': analysis,
            'config': self._get_config_summary()
        }

        return final_results

    def _check_ghost_spn(self) -> dict:
        """Check for Ghost SPN relay vulnerabilities in Active Directory."""
        try:
            detector = GhostSPNDetector(self.config)
            return detector.detect()
        except Exception as e:
            if self.config.verbose >= 2:
                print(f"[!] Ghost SPN check error: {e}")
            return {'error': str(e), 'vulnerable': [], 'probably_vulnerable': [], 'checked': 0}

    def _write_ghost_spn_file(self, ghost_spn_results: dict, filename: str):
        """Write all Ghost SPN findings to a plaintext file."""
        vulnerable = ghost_spn_results.get('vulnerable', [])
        probably_vulnerable = ghost_spn_results.get('probably_vulnerable', [])

        lines = []
        lines.append("=" * 80)
        lines.append("RelayKing - Ghost SPN Findings")
        lines.append("=" * 80)
        lines.append(f"Total SPN hostnames checked : {ghost_spn_results.get('checked', 0)}")
        lines.append(f"Vulnerable (no DNS record)  : {len(vulnerable)}")
        lines.append(f"Probably vulnerable (wildcard DNS): {len(probably_vulnerable)}")
        lines.append("")

        if vulnerable:
            lines.append("VULNERABLE - No DNS record (hostname is unregistered)")
            lines.append("-" * 80)
            for f in vulnerable:
                lines.append(f"  Account  : {f.get('account', '')}")
                lines.append(f"  SPN      : {f.get('spn', '')}")
                lines.append(f"  Hostname : {f.get('hostname', '')}")
                lines.append(f"  Action   : Register DNS '{f.get('hostname', '')}' to intercept auth")
                lines.append("")

        if probably_vulnerable:
            lines.append("PROBABLY VULNERABLE - Resolves via wildcard DNS")
            lines.append("-" * 80)
            for f in probably_vulnerable:
                resolved = ', '.join(f.get('resolved_to', []))
                lines.append(f"  Account    : {f.get('account', '')}")
                lines.append(f"  SPN        : {f.get('spn', '')}")
                lines.append(f"  Hostname   : {f.get('hostname', '')}")
                lines.append(f"  Resolves to: {resolved}")
                lines.append("")

        try:
            with open(filename, 'w') as fh:
                fh.write('\n'.join(lines))
            print(f"[+] Ghost SPN findings written to: {filename}")
        except Exception as e:
            print(f"[!] Could not write Ghost SPN file '{filename}': {e}")

    def _run_port_scan(self, targets, protocols):
        """Run fast port scan on targets and return results."""
        print(f"[*] Running fast port scan...")
        port_scanner = FastPortScanner(timeout=0.1)  # 100ms timeout

        # Determine which protocols to port scan
        protocols_for_portscan = protocols.copy()
        if self.target_parser.tier0_assets:
            if 'http' not in protocols_for_portscan:
                protocols_for_portscan.append('http')
            if 'https' not in protocols_for_portscan:
                protocols_for_portscan.append('https')

        return port_scanner.scan_hosts(targets, protocols_for_portscan, threads=50)

    def _coerce_all_mode(self, start_idx, end_idx) -> Dict:
        """
        Special mode: --coerce-all
        Enumerate AD computers and coerce them all to authenticate to listener
        """
        print("[*] Coerce-All Mode: Enumerating computers from Active Directory...")

        # Use target parser to enumerate AD (it already has this logic)
        #targets = self.target_parser.parse_targets()
        targets = self.all_targets[start_idx:end_idx]

        result = {
                'targets': [],
                'coercion_count': 0,
                'listener': self.config.coerce_target,
                'config': self._get_config_summary()
        }
        if not targets:
            print("[!] No targets found in Active Directory")
            return result

        print(f"[+] Found {len(targets)} target(s)")
        print(f"[*] Initiating coercion attacks to {self.config.coerce_target}...")

        try:
            # Import coercion detector
            from detectors.coercion import CoercionDetector
            coercion_detector = CoercionDetector(self.config)

            # Run coercion on all targets
            completed = 0
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_to_target = {}

                for target in targets:
                    future = executor.submit(coercion_detector.detect, target)
                    future_to_target[future] = target

                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    completed += 1

                    try:
                        result = future.result()

                        # Show progress
                        if self.config.verbose >= 1:
                            print(f"[{completed}/{len(targets)}] Coerced: {target}")
                        else:
                            sys.stdout.write(f"\r[*] Coercion progress: {completed}/{len(targets)}")
                            sys.stdout.flush()

                    except Exception as e:
                        if self.config.verbose >= 2:
                            print(f"[!] Error coercing {target}: {e}")

                if self.config.verbose == 0:
                    print()  # Newline after progress

            # Final summary
            print(f"\n[+] Coercion complete. All {len(targets)} targets should have initiated computer account connections to {self.config.coerce_target}")

            return {
                'targets': targets,
                'coercion_count': len(targets),
                'listener': self.config.coerce_target,
                'config': self._get_config_summary()
            }
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return result


    def _scan_target(self, target: str, protocols: List[str], port_scan_results: Dict = None) -> Dict:
        """Scan a single target for all specified protocols"""

        results = {}

        # Check if this is a tier-0 asset
        # In audit mode with credentials, use LDAP-detected tier-0 assets
        # Otherwise fall back to hostname-based detection
        target_lower = target.lower()
        if self.config.audit_mode and not self.config.null_auth and self.target_parser.tier0_assets:
            # Use LDAP-detected tier-0 assets
            # Check both exact match and short hostname match (in case of FQDN vs hostname mismatch)
            is_high_value = target_lower in self.target_parser.tier0_assets
            if not is_high_value:
                # Also check if any tier0 asset's FQDN matches (handle FQDN vs short hostname)
                target_short = target_lower.split('.')[0]
                for asset in self.target_parser.tier0_assets:
                    asset_short = asset.split('.')[0]
                    if target_short == asset_short or target_lower == asset or asset == target_short:
                        is_high_value = True
                        break
        else:
            # Fall back to hostname-based detection
            is_high_value = any(indicator in target_lower for indicator in self.HIGH_VALUE_INDICATORS)

        # Determine protocols to scan for this target
        protocols_to_scan = protocols.copy()

        # Always scan HTTP/HTTPS on high-value/tier-0 targets, even if not in protocol list
        # This ensures we detect ADCS/SCCM relay paths on critical infrastructure
        if is_high_value:
            if 'http' not in protocols_to_scan:
                protocols_to_scan.append('http')
            if 'https' not in protocols_to_scan:
                protocols_to_scan.append('https')

        # Filter protocols based on port scan results if --proto-portscan enabled
        if port_scan_results is not None and target in port_scan_results:
            open_ports = port_scan_results[target]
            protocols_to_scan = [
                proto for proto in protocols_to_scan
                if proto in self.PROTOCOL_DETECTORS and self.PROTOCOL_DETECTORS[proto][1] in open_ports
            ]

        # Scan each protocol
        for protocol in protocols_to_scan:
            if protocol not in self.PROTOCOL_DETECTORS:
                continue

            detector_class, default_port = self.PROTOCOL_DETECTORS[protocol]

            try:
                detector = detector_class(self.config)
                result = detector.detect(target)
                results[protocol] = result

            except Exception as e:
                if self.config.verbose >= 2:
                    print(f"[!] Error detecting {protocol} on {target}: {e}")

        # Additional detections on this target (skip in null auth mode)
        if not self.config.null_auth:
            # WebDAV detection (requires SMB and credentials to access IPC$ pipe)
            if 'smb' in results and results['smb'].available:
                try:
                    webdav_detector = WebDAVDetector(self.config)
                    webdav_result = webdav_detector.detect(target)
                    results['webdav'] = webdav_result
                except Exception as e:
                    if self.config.verbose >= 2:
                        print(f"[!] Error detecting WebDAV on {target}: {e}")

            # NTLM reflection analysis (requires credentials to read registry)
            try:
                reflection_detector = NTLMReflectionDetector(self.config)
                reflection_result = reflection_detector.analyze(results, target)
                results['ntlm_reflection'] = reflection_result
            except Exception as e:
                if self.config.verbose >= 2:
                    print(f"[!] Error analyzing NTLM reflection on {target}: {e}")

        return results

    def _check_coercion(self, targets: List[str]) -> Dict:
        """Check coercion vulnerabilities across all targets"""

        coercion_results = {}
        coercion_detector = CoercionDetector(self.config)

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_target = {}

            for target in targets:
                future = executor.submit(coercion_detector.detect, target)
                future_to_target[future] = target

            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1

                try:
                    result = future.result()
                    coercion_results[target] = result

                    # Show progress if verbose
                    if self.config.verbose >= 1:
                        print(f"[{completed}/{len(targets)}] Coercion check: {target}")
                    else:
                        sys.stdout.write(f"\r[*] Coercion progress: {completed}/{len(targets)}")
                        sys.stdout.flush()

                except Exception as e:
                    if self.config.verbose >= 2:
                        print(f"[!] Error checking coercion on {target}: {e}")

            if self.config.verbose == 0:
                print()  # Newline after progress

        return coercion_results

    def _check_ntlmv1(self, targets: List[str], all_results: Dict) -> Dict:
        """Check NTLMv1 support via GPO and/or registry"""

        ntlmv1_results = {
            'domain_policy': None,
            'vulnerable_hosts': {}
        }

        detector = NTLMv1Detector(self.config)

        # Check domain-wide GPO if --ntlmv1
        if self.config.check_ntlmv1:
            # Find a DC from the results (look for hosts with LDAP available)
            dc_host = self._find_dc(all_results)
            if dc_host:
                if self.config.verbose >= 2:
                    print(f"[*] Checking domain GPO for NTLMv1 policy on {dc_host}...")
                ntlmv1_results['domain_policy'] = detector.check_gpo(dc_host)
            else:
                if self.config.verbose >= 1:
                    print("[!] Could not find DC to check GPO for NTLMv1 policy")

        # Check per-host registry if --ntlmv1-all
        if self.config.check_ntlmv1_all:
            if self.config.verbose >= 2:
                print(f"[*] Checking {len(targets)} hosts for NTLMv1 support via registry...")

            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_to_target = {
                    executor.submit(detector.check_host_registry, target): target
                    for target in targets
                }

                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        if result.get('enabled'):
                            ntlmv1_results['vulnerable_hosts'][target] = result
                    except Exception as e:
                        if self.config.verbose >= 2:
                            print(f"[!] Error checking NTLMv1 on {target}: {e}")

        return ntlmv1_results

    def _find_dc(self, all_results: Dict) -> str:
        """Find a DC from scan results (look for hosts with LDAP available)"""
        # Prefer hosts with both LDAP and SMB available
        for target, results in all_results.items():
            if 'ldap' in results and results['ldap'].available:
                return target
            if 'ldaps' in results and results['ldaps'].available:
                return target

        # Fallback: use dc_ip if specified
        if self.config.dc_ip:
            return self.config.dc_ip

        return None

    def _resolve_target_ip(self, target: str) -> List[str]:
        """
        Resolve target hostname to IP address(es)

        Uses custom DNS server (-ns) and TCP (--dns-tcp) if specified,
        otherwise falls back to system DNS.

        Returns:
            List of IP addresses (empty list if resolution fails)
        """
        # First check if target is already an IP
        try:
            socket.inet_aton(target)
            return [target]  # Target is already an IP
        except socket.error:
            pass  # Not an IP, continue to resolve

        # Use custom DNS if available and specified
        if DNS_AVAILABLE and self.config.nameserver:
            try:
                nameserver = self.config.nameserver

                # Resolve nameserver hostname to IP if needed
                try:
                    socket.inet_aton(nameserver)
                except socket.error:
                    # Nameserver is a hostname, resolve it first
                    ns_info = socket.getaddrinfo(nameserver, None, socket.AF_INET)
                    if ns_info:
                        nameserver = ns_info[0][4][0]

                # Create DNS query
                query = dns.message.make_query(target, dns.rdatatype.A)

                # Send query via TCP or UDP based on config
                if self.config.dns_tcp:
                    response = dns.query.tcp(query, nameserver, timeout=self.config.timeout)
                else:
                    response = dns.query.udp(query, nameserver, timeout=self.config.timeout)

                # Extract IPs from response (filter out invalid addresses)
                ips = []
                for rrset in response.answer:
                    for rdata in rrset:
                        if hasattr(rdata, 'address'):
                            ip = rdata.address
                            if _is_valid_unicast_ip(ip):
                                ips.append(ip)

                if ips:
                    return list(set(ips))

            except Exception as e:
                if self.config.verbose >= 3:
                    print(f"[!] Custom DNS resolution failed for {target}: {e}")
                # Fall through to system DNS

        # Fallback to system DNS
        try:
            addr_info = socket.getaddrinfo(target, None, socket.AF_INET)
            # Filter out invalid IPs (multicast, loopback, etc.)
            ips = [addr[4][0] for addr in addr_info if _is_valid_unicast_ip(addr[4][0])]
            return list(set(ips))
        except (socket.gaierror, socket.timeout):
            return []
        except Exception:
            return []

    def _get_config_summary(self) -> Dict:
        """Get summary of scan configuration"""
        return {
            'username': self.config.username,
            'domain': self.config.domain,
            'null_auth': self.config.null_auth,
            'protocols': self.config.protocols,
            'check_ntlmv1': self.config.check_ntlmv1,
            'check_coercion': self.config.check_coercion,
            'threads': self.config.threads,
            'timeout': self.config.timeout,
        }
