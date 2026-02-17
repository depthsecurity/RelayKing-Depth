# RelayKing v1.0

### Dominate the domain. Relay to royalty.
![](RelayKing-Banner.png)

**RelayKing** is a comprehensive relay detection and enumeration tool designed to identify relay attack opportunities in Active Directory environments. Actual reporting options. Comprehensive attack coverage. Find the hidden relay vectors and report in your favorite output format. Feed Impacket's ntlmrelayx.py a curated target list of detected, relay-able hosts. Never miss a critical, exploitable NTLM relay path in the domain again.

## Blog/Recommended Reading:
See the associated blog released on the Depth Security website for more details: https://www.depthsecurity.com/blog/introducing-relayking-relay-to-royalty/

## Table of Contents
- [Blog/Recommended Reading](#blogrecommended-reading)
- [Read Before Using](#read-before-using)
  - [OPSEC Considerations](#opsec-considerations)
- [Features](#features)
  - [Protocol Detection](#protocol-detection)
  - [Advanced Detection](#advanced-detection)
  - [Relay Path Analysis](#relay-path-analysis)
  - [Targeting Options](#targeting-options)
  - [Output Formats](#output-formats)
  - [Misc Features](#misc-features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Examples](#examples)
- [Functionality Notes](#functionality-notes)
  - [Performance](#performance)
  - [Feature Behavior Notes](#feature-behavior-notes)
- [To-Do](#to-do)
- [Current Known Bugs/Limitations](#current-known-bugslimitations)
- [Submitting Issues/Pull Requests](#submitting-issuespull-requests)
  - [Issues](#issues)
  - [Pull Requests](#pull-requests)
- [Credits](#credits)
- [Disclaimer](#disclaimer)
- [License](#license)

## READ BEFORE USING:
### OPSEC CONSIDERATIONS:
**RelayKing is NOT AN OPSEC-FRIENDLY TOOL IN CERTAIN MODES, PARTICULARLY IN `--audit` MODE. It is mostly for COMPREHENSIVE AUDITING+CATALOGING of NTLM relaying vectors in Active Directory environments, and then facilitating reporting on said issues.  It uses Impacket and several other well-fingerprinted Python libraries under the hood.** 

**Audit mode (`--audit`) will generate potentially THOUSANDS of logons and, potentially, equally large numbers of remote access events via services such as RemoteRegistry in modes like `--ntlmv1-all`. BE PREPARED TO GENERATE ALERTS FROM SIEM/EDR/XDR/$SECURITY_SOLUTION IF YOU AUDIT ENTIRE DOMAINS WITH CREDENTIALS. Don't use with creds you don't want to potentially burn. Consider this also before punting off domain-wide checks with obnoxious flags like `--coerce-all` or `--ntlmv1-all` enabled because EDR may complicate and/or block certain remote checks, OR, worst-case, isolate hosts it perceives as compromised if configured to do so. Nearly all defensive security software vendors are well aware of Impacket and how to fingerprint usage of it. You've been warned!** 

**RelayKing is provided AS-IS WITH NO GUARANTEES. See bottom of readme.**

## Features
#### Key:
- **"WIP" = "Work In Progress" Feature. Unfinished/partially implemented.**

- **"EPA" = "Extended Protection for Authentication."** *Also, EPA == Channel Binding, functionally speaking.*

- **"CB/CBT" = "Channel Binding/Channel Binding Token"**

### Protocol Detection
- **SMB/SMB2/SMB3**: Signing requirements, channel binding, version detection *(no auth required)*
- **HTTP/HTTPS**: EPA/CBT enforcement *(Auth required for reliable HTTPS checks)*
- **LDAP/LDAPS**: Signing requirements, channel binding *(Auth required for reliable CBT check on LDAPS)*
- **MSSQL**: EPA enforcement *(Auth required for reliable check)*
- **RPC**: MS-RPC endpoint enumeration, authentication requirements *(Auth required for reliable check)*
- **WINRM/WINRMS**: WS-Management, EPA enforcement, channel binding *(Authed check)* (**WIP**)
- **SMTP**: NTLM authentication detection, STARTTLS support (**WIP**)
- **IMAP/IMAPS**: NTLM authentication, encrypted mail access (**WIP**)

### Advanced Detection
- **NTLM Reflection**: Identifies hosts vulnerable to NTLM reflection attacks (CVE-2025-33073)
- **WebDAV/WebClient**: Detects hosts with the WebDAV WebClient service running
- **NTLMv1 Support**: Checks for NTLMv1 authentication support (individually or at GPO level)
- **Coercion Vulnerabilities**: Detects unauthenticated (if specified) PetitPotam, PrinterBug, DFSCoerce

### Relay Path Analysis
- Automatically identifies viable relay attack paths (Functioning, needs more work)
- Prioritizes paths by impact (critical, high, medium, low)
- Cross-protocol relay detection (requires `--ntlmv1`or `--ntlmv1-all` - cross-protocol detection only when confirmed Net-NTLMv1 usage discovered)
- NTLM reflection paths (including partial MIC removal paths/cross-protocol relay)
- Severity rating logic is WIP, submit PRs for upgrades/improvements! Not 100% of situations/scenarios are accounted for currently - the goal is to cover all possible primitives. 

###  Targeting Options
- **Active Directory Audit `(--audit)`**: Enumerate all computers from AD via LDAP. Requires low-priv AD credentials and *functional DNS* within environment. Force with `--dc-ip` or edit `/etc/resolv.conf`. 
- **File Input**: Load targets from text file
- **CIDR Notation**: Scan entire subnets (e.g., `10.0.0.0/24`)
- **IP Ranges**: Scan IP ranges (e.g., `10.0.0.1-254`)
- **Individual Hosts**: Target specific hosts or FQDNs (`python3 relayking.py -u blah -p pass -d domain.local <your_target_ip_or_hostname>`)

### Output Formats
- **Plaintext**: Human-readable output with detailed findings
- **JSON**: Structured data for programmatic analysis
- **XML**: Hierarchical data format
- **CSV**: Spreadsheet-compatible format
- **Grep-able**: One-line-per-result format for easy parsing
- **Markdown**: Documentation-ready format

### Misc Features
- **Mass Coercion**: `--coerce-all` combined with `--audit` and low-priv creds to coerce EVERY domain machine for mass computer account relaying. Highly useful in environments with Net-NTLMv1 enabled.
- **Net-NTLMv1 Discovery**: `--ntlmv1` or `--ntlmv1-all` to detect LanMan GPOs at domain level. `--ntlmv1-all` checks ALL hosts from AD and their registry values using RemoteRegistry. **(requires local admin)**.
- **Relay List Generation**: `--gen-relay-list <file>` to produce a readily-importable target file for ntlmrelayx.py's `-tf` switch.
- **Flexible Kerberos Auth Features**: Kerberos auth via -k (and a FQDN for `--dc-ip`) should work pretty nicely. If the environment has domain controllers that have NTLM disabled entirely but tolerate it everywhere else, you can use `--krb-dc-only` so it doesn't mess with any checks. Also, --dns-tcp and -ns are available for work conducted over SOCKS/other proxy pivots. Even kerb works in this scenario pretty easily.

## Installation

```bash
# Use a venv. Save yourself the hassle.

# Clone repo:
git clone https://github.com/depthsecurity/RelayKing-Depth.git
#Navigate to cloned dir:
cd RelayKing/
# Configure Python venv:
virtualenv --python=python3 .
source bin/activate
# Install deps:
pip3 install -r requirements.txt
# Validate RelayKing installation was successful:
python3 relayking.py -h
```

## Usage

### Command-Line Options
#### Print command line args/usage with `-h`, as expected:
```
python3 relayking.py -h
```

###  Examples

#### Recommended Usage Flags for Full-Network Coverage + Output Scan Report to Plaintext & JSON:
```bash
python3 relayking.py -u ‘lowpriv’ -p ‘lowpriv-password’ -d client.domain.local --dc-ip 10.0.0.1 -vv --audit --protocols smb,ldap,ldaps,mssql,http,https --threads 10 -o plaintext,json --output-file relayking-scan --proto-portscan --ntlmv1 --gen-relay-list relaytargets.txt
```
#### Lighter Authenticated Scan w/ No HTTP(S) Checks + Output Scan Report to Plaintext & JSON:
```bash
python3 relayking.py -u ‘lowpriv’ -p ‘lowpriv-password’ -d client.domain.local --dc-ip 10.0.0.1 -vv --audit --protocols smb,ldap,ldaps,mssql -o plaintext,json --output-file relayking-scan --proto-portscan --gen-relay-list relaytargets.txt
```
#### Single-Target Auth'd Scan (single-target = positional, final arg) + Report ONLY to stdout in plaintext:
```bash
python3 relayking.py -u ‘lowpriv’ -p ‘lowpriv-password’ -d client.domain.local -vv --protocols smb,ldap,ldaps,mssql,http,https -o plaintext SERVER1-EXAMPLE.LAB.LOCAL
```
#### Unauth Sweep with CIDR Range As Target + No Report File/stdout as plaintext only:
```bash
python3 relayking.py --null-auth -vv --protocols smb,ldap,http -o plaintext 10.0.0.0/24
```
#### Full Audit, Check ALL Hosts for Net-NTLMv1 via RemoteRegistry (HEAVY):
```bash
python3 relayking.py -u ‘lowpriv’ -p ‘lowpriv-password’ -d client.domain.local --dc-ip 10.0.0.1 -vv --audit --protocols smb,ldap,ldaps,mssql,http,https --threads 10 -o plaintext,json --output-file relayking-scan --proto-portscan --ntlmv1-all --gen-relay-list relaytargets.txt
```
## Functionality notes:
### Performance
* There’s 10 main scanner threads/jobs by default, specified with `--threads`. Each main thread gets worker threads for certain tasks under it. HTTP, for example, uses 20 threads per main thread. This results in ~200 HTTP threads open to scan for HTTP NTLM auth. Most of the time, this is tolerated substantially well but if it causes lag/network issues, reduce the threads. The default of 10 threads is exceptionally quick anyways.
* You probably pretty much always want to use `--proto-portscan` with all your scans. It significantly improves performance and prevents the scanner from waiting for timeouts on ports that aren't actually there. If it causes issues, you can remove at the expensive of scan performance (but it shouldn't!)
### Feature Behavior Notes:
* `--ntlmv1` or -`-ntlmv1-all`: Adding `--ntlmv1` will pull every LanMan GPO for the domain and nothing else. Requires low-priv AD creds. `--ntlmv1-all` requires admin credentials and will check **every individual host in the domain** with SMB open for the LMCompatibilityLevel registry key. Running at least `--ntlmv1` **is required to show/detect cross-protocol SMB relay paths**. 
	* Remote registry being disabled can cause jank with `--ntlmv1-all`. Also very heavy and not OPSEC safe, but thorough. Probably not recommended unless you're YOLO'ing or desperate.
* **Output in various formats**. Supplying formats in comma-separated notation (`-o json,plaintext`) and `--output-file relayking-scan` produces relayking-scan.json + relayking-scan.txt so there’s no need to run it twice for multiple formats. Available: `plaintext, json, xml, csv, grep, markdown` (**default: plaintext)**
* `--coerce-all`functionality will use PetitPotam, DFSCoerce, and PrinterBug on ALL HOSTS TARGETED. It also mass-coerces every machine in the domain without running the full protocol audit. Supplying `--audit` + `--coerce` at the **same time** will perform a domain audit **AND** mass-coercion. (**HEAVY**)

## To-Do

* Lot more testing (YOU CAN HELP)
* Shell file coercion dropper + cleanup. (Needs specific features - reach out directly if you want to add this)
* Create usage wiki
* Kerberos relaying + paths. Create logic surrounding all krb relay techniques including reflection.
* Potential `--opsec-safe` mode that avoids Impacket/other fingerprinted Python library usage. Not trivial to implement.

## Current Known Bugs/Limitations:

* Unauthenticated checks for EPA/CB on MSSQL, HTTPS, WinRMS, and LDAPS(?) are not reliable. Avoid.
* Could miss computers if they're placed in a custom/non-standard OU for computers. May consider adding a flag for use with `--audit` to specify the OU to search for computers in aside from the default (like `--custom-computer-ou <DN_of_target_OU>`).
* Funky RPC behavior on Windows 11 hosts. Likely impacket nonsense. RPC in general could use  more improvement but RPC is typically very low impact relay protocol so not highest priority.
* Possibly buggy tier-0 detection/relay severity. Manually review relay path output for juicy stuff RelayKing may not have noticed/under-rated severity wise.
* Again, not an OPSEC-safe tool. Very, very noisy. Potential issues with Impacket protocol handlers getting blocked by EDR. In the future, **possible** implementation of alternative network libraries for signing/cbt/epa with `--no-impacket` or `--opsec` to switch from Impacket to OPSEC safe libraries. Not trivial and not massive priority currently. If widespread issues are encountered (which they haven't at the time of writing in January 2026), this could be expedited potentially.

## Submitting Issues/Pull Requests
### Issues
* Issues opened containing errors/tool failures without any details ("this doesn't work"/"why no work") will be closed.
* Generally speaking, run the tool with `-vv` or `-vvv` if you're experiencing errors. Logging isn't perfect in v1.0 - will improve in the future/as able.
* When submitting issues, as much detail as possible is highly desirable so debugging/troubleshooting is possible. Please redact any sensitive info from debugging output such as client/target domains, machine names, any other sensitive info. You don't want to leak your client's relay skeletons to the world.
* Usage args that produced issues/errors/broken behavior are also necessary.
* Issues that arise from user-error or broken, misconfigured environments will be reviewed, and likely closed. **Exceptions** to this are situations where the tool **SHOULD** gracefully handle an environment-specific quirk and it fails to run/throws exceptions+stack traces when encountered. These situations should be fairly obvious. Examples of user error/busted network setup below:
	* For example, you run `--audit` and RelayKing fails to resolve any hosts in DNS because their DNS server(s) just refuse to resolve their computer FQDNs in the target DNS zone. Not a RelayKing issue. 
	* Or, for example, failing to ensure DNS is configured properly on your testing host (by validating /etc/resolv.conf) and then stuff fails to resolve properly - not a RelayKing issue.
    * Anything else PEBKAC.
### Pull Requests:
* PRs always welcome. New features, improvements, and refactors that improve performance/overall logic are desirable. 
* Feature requests can be submitted via PRs. Description of the feature, specific behavior, and potential usage flags/args are generally be the minimum needed to consider implementation.
* PRs should be thoroughly tested, ideally in multiple environments before being submitted. We'll test PRs before merging them, but the more testing in unique environments (especially after major changes/refactoring) = the better. I want to keep RelayKing reliable, robust, and high-performance - which mandates extensive testing.
## Credits

- **My Team - Depth Security (https://www.depthsecurity.com/)**: Support, assistance, guidance, and testing. This tool would be useless without the team of teal.
- **Nick Powers (SpecterOps) (https://github.com/zyn3rgy) - RelayInformer**: Inspiration and detection logic reference
- **Numerous devs / Alex Neff (https://github.com/NeffIsBack) - NetExec**: Various detection logic implementations.
- **Fortra/SecureAuthCorp/Numerous devs - Impacket**: Protocol implementations. Various other stuff.
- **Dirk-jan Mollema (https://github.com/dirkjanm) krbrelayx**: Kerberos relay techniques, DNS stuff.
- **Garrett Foster (SpecterOps) (https://github.com/garrettfoster13) SCCMHunter**: SCCM detection logic. Lab-usage for testing (MANY THANKS!)
- **Oliver Lyak (https://github.com/ly4k) Certipy-AD**: ADCS detection logic
- **Andrea Pierini (https://github.com/decoder-it)**: Numerous relay techniques and tactics.
- Possibly more I'm missing - this tool wouldn't be possible without the greater infosec community and their contributions.
## Disclaimer

**As-is. Many bugs certainly exist. See above. Not designed or intended for illegal/unauthorized activity, obviously.**

**Consider the behavior & nature of ALL tools you run for a client engagement and on their network(s). This is accomplished by reading tool source and understanding the inner-workings prior to execution, not by blindly executing code you found on GitHub. While I can assure you that there's no deliberately malicious/destructive code inside of RelayKing, validating all novel/unused tools prior to running them is generally speaking, good practice. Trust, but always verify.**

**Be careful using on red team exercises, especially with authenticated checks and `--audit`. You WILL get detected and it will be your fault! You should have read the warning at the top of the README if you somehow are reading this sentence and didn't know this already.**

**While extremely unlikely/improbable, if RelayKing somehow breaks something, you're on your own, and neither the Author or Depth Security are liable for any outcomes/issues/problems/upside-down-geospatial-bit-flipping-nuclear-explosions that could possibly arise (however unlikely) from execution of RelayKing. Your mileage may vary. RelayKing is, once again, provided with NO GUARANTEES OR WARRANTY OF ANY SPECIFIC OUTCOMES, FEATURES, UTILITY, OR BEHAVIOR - EXPLICITLY MENTIONED HERE (AND/OR NOT MENTIONED) OR OTHERWISE IMPLIED.**

**The only legitimate GitHub repository by the Author (logansdiomedi) is present at https://github.com/depthsecurity/RelayKing-Depth - all others are forks/copies/whatever else, the Author has likely not read, validated, tested, analyzed, or inspected for functionality/behavior/legitimacy. Use your head.**

## License

MIT License - see LICENSE file for details
