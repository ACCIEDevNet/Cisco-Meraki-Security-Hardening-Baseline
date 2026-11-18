# Cisco Meraki Security Hardening Baseline

A practical, testable security baseline for Cisco Meraki cloud-managed estates: Dashboard administration, MX security appliances, MR wireless and MS switching.

> **Disclaimer.** This is an independent community guide. It is not affiliated with or endorsed by Cisco or Meraki. Dashboard menus and options change between releases, so confirm the current labels and test changes in a lab or pilot network before production. Nothing here is a compliance certification.

**Last reviewed:** 2026-11-18

---

## Contents

1. [Why this matters](#why-this-matters)
2. [How to use this baseline](#how-to-use-this-baseline)
3. [Top ten quick wins](#top-ten-quick-wins)
4. [Dashboard administrator access and identity](#1-dashboard-administrator-access-and-identity)
5. [Organization settings, API and integrations](#2-organization-settings-api-and-integrations)
6. [Logging, monitoring and alerting](#3-logging-monitoring-and-alerting)
7. [Network-wide and device management](#4-network-wide-and-device-management)
8. [MX security appliance](#5-mx-security-appliance)
9. [MR wireless](#6-mr-wireless)
10. [MS switching](#7-ms-switching)
11. [Operations: change control, review cadence, exceptions](#8-operations)
12. [Automated audit script](#automated-audit-script)
13. [Framework mapping](#framework-mapping)
14. [Sources](#sources)

---

## Why this matters

The Meraki Dashboard is a single cloud control plane that can reconfigure every firewall, access point and switch in an organization. Compromise of one administrator account, API key or support-access grant can therefore change the whole estate at once. Most of the controls below protect that management plane first, then the devices and the traffic they carry.

## How to use this baseline

Each control has an ID, a required setting, the reason it exists and a priority.

| Priority | Meaning | Suggested timeline |
| --- | --- | --- |
| **P1** | Mandatory. A gap is an exploitable weakness in the management plane or perimeter | Before go-live; fix existing estates within 30 days |
| **P2** | Required. Reduces blast radius or improves detection | Within 90 days |
| **P3** | Recommended. Defence in depth or maturity uplift | Roadmap |

Menu paths are given as they appear in the Dashboard at the time of writing (for example **Organization > Configure > Settings**).

> **Evidence level.** Sections 1 and 2 were checked against Cisco Meraki documentation (see [Sources](#sources)). Sections 3 to 7 reflect product behaviour and common practice and were not each verified against a live Dashboard. Treat them as strong defaults and adjust to your environment. Timelines, rotation periods and thresholds are suggestions, not Meraki requirements.

## Top ten quick wins

If you only do ten things, do these.

- [ ] 1. Move all administrators to SAML SSO with phishing-resistant MFA at the identity provider (ADM-01, ADM-02)
- [ ] 2. Set Meraki Support Access to **Blocked**; enable only per approved case (ADM-04)
- [ ] 3. Reduce local accounts to two vaulted break-glass admins with forced 2FA (ADM-05, ADM-06)
- [ ] 4. Set the idle timeout to 10 minutes or less (ADM-09)
- [ ] 5. Enforce least-privilege, scoped administrator roles (ADM-07)
- [ ] 6. Block management services on the MX WAN and remove unneeded port forwards (MX-01, MX-02)
- [ ] 7. Turn on IPS in Prevention mode and keep firmware current (MX-04, DEV-04)
- [ ] 8. Forward syslog and the change log to a SIEM and alert on admin events (LOG-01 to LOG-03)
- [ ] 9. Retire open, WEP and shared-key SSIDs and isolate guest Wi-Fi (WLS-01, WLS-02, WLS-05)
- [ ] 10. Enable port authentication, BPDU guard and DHCP snooping on access switches (SW-01, SW-03, SW-05)

---

## 1. Dashboard administrator access and identity

The highest-risk area. Administrators sign in through SSO with phishing-resistant MFA, Meraki Support (TAC) access stays blocked by default, and local accounts exist only as tightly controlled break-glass.

> **Key design fact.** Meraki's native password, lockout, two-factor and login-IP settings do **not** apply to SAML administrator accounts; only the idle timeout does ([Organization Settings](https://documentation.meraki.com/General_Administration/Organizations_and_Networks/Organization_Menu/Organization_Settings)). Once SSO is on, MFA, conditional access, session lifetime and IP/geo restrictions must be enforced at the identity provider. The native settings then protect only the remaining local accounts.

Path: **Organization > Configure > Settings** unless stated.

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| ADM-01 | SAML SSO for all administrators | Enable SAML under Authentication using your corporate IdP (Entra ID, Okta, Duo SSO and others). Enable SP-initiated SAML with an SSO subdomain so the Meraki mobile app also signs in through the IdP | Central joiner/mover/leaver and one place to enforce MFA | P1 |
| ADM-02 | MFA at the IdP | Require phishing-resistant MFA (FIDO2/passkey or certificate-based) for the Meraki application; number-matching push as the minimum. No SMS or voice | SAML admins bypass Meraki native 2FA, so the IdP is the only MFA control | P1 |
| ADM-03 | Conditional Access at the IdP | Restrict the Meraki app to compliant/managed devices and corporate or VPN egress IPs; block legacy and anonymous-proxy sign-ins; require re-authentication for sensitive sessions | Replaces Login IP ranges, which do not cover SAML admins | P1 |
| ADM-04 | Block Meraki (Cisco) Support access by default | Set Meraki Support Access to **Blocked** ("Block Meraki Support"). Enable Full access only for the duration of an approved support case, then set it back (procedure below) | Prevents support engineers viewing or changing the organization without your knowledge | P1 |
| ADM-05 | Native 2FA for local accounts | Enable **Two-factor authentication** (force for all users). Store recovery codes in the vault | Protects break-glass and any non-SAML account. Once forced, users need Meraki Support to disable it | P1 |
| ADM-06 | Local (non-SAML) accounts | Keep exactly two organization-level Full-access break-glass accounts on a domain you control, with 2FA, unique 20+ character passwords in a vault, and alerting on any sign-in. Every other admin is SAML-only | Meraki advises at least two Full-access org admins so a lockout cannot strand the organization | P1 |
| ADM-07 | Least-privilege roles | Map IdP groups to SAML roles per scope: Organization Full only for the platform team; network- or tag-scoped Full, Read-only or Monitor-only for others; Guest-ambassador for helpdesk. Consultants and MSPs get time-bound, network-scoped access | Limits the blast radius of a compromised admin | P1 |
| ADM-08 | Password policy (local accounts) | Enable **Strong passwords** (including the 12-character minimum), **Used passwords** restriction and **Account lockout** (suggest 5 attempts); **Password expiration** only if policy requires it | Native controls for the break-glass accounts | P2 |
| ADM-09 | Idle timeout | **Idle timeout** of 10 minutes or less (applies to SAML and local admins) | Limits unattended sessions; the one native setting that covers SAML users | P1 |
| ADM-10 | Login IP ranges (local accounts) | Restrict Dashboard and API access to corporate/VPN egress ranges; use the "API access only" option for automation hosts. Review OAuth 2.0 integrations, which bypass these ranges, under Organization > Integrations > My Integrations | Reduces exposure of local credentials; OAuth is a known gap | P2 |
| ADM-11 | Account hygiene | Remove admins with no sign-in for 90 days; reconcile the Administrators list against HR/IdP quarterly; use corporate email addresses only | Stale admins are a common cause of unauthorised access | P2 |
| ADM-12 | Meraki mobile app | Allow SSO sign-in only; no shared devices; require a device lock | The app holds an authenticated management session | P3 |

### Procedure: temporary Meraki Support (TAC) access

1. Raise a change record and a Meraki/Cisco case; record the case number and approver.
2. A Full-access organization admin sets Support Access to **Full access**. Cisco recommends doing this temporarily while a case is open.
3. Support works the case; an engineer from your team shadows the session.
4. When the case closes, set Support Access back to **Blocked**. Suggested internal rule: if a case stays open, re-approve every 24 hours.
5. Check the change log (**Organization > Monitor > Configuration changes**) to confirm the grant and revoke entries, and review any changes made.

Blocking support access does **not** stop Meraki automatically pushing firmware upgrades, so control timing through firmware schedules (DEV-04).

---

## 2. Organization settings, API and integrations

Automation and integrations are the second way into the Dashboard and sit outside the human sign-in controls above. Each needs an owner, a scope and a rotation date.

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| ORG-01 | Dashboard API access | Leave API disabled on organizations that do not use it. Otherwise one key per integration on a dedicated service account with the narrowest role (Read-only unless writes are essential); rotate every 90 days; store in a secrets vault | API keys act with the full permissions of the user who created them | P1 |
| ORG-02 | API network restriction | Add automation hosts to Login IP ranges using the "API access only" option | Stolen keys are useless from other networks | P2 |
| ORG-03 | OAuth 2.0 integrations | Review Organization > Integrations > My Integrations quarterly; revoke anything unowned or unrecognised | OAuth integrations bypass login IP ranges | P2 |
| ORG-04 | Webhooks | HTTPS endpoints only, with a shared secret validated by the receiver; remove unused receivers under Network-wide > Alerts | Prevents spoofed or intercepted alert traffic | P2 |
| ORG-05 | SNMP | Disabled unless needed. If enabled, SNMPv3 with authentication and privacy (SHA, AES), access limited to NMS addresses; no v1/v2c community strings | v2c is cleartext with shared strings | P1 |
| ORG-06 | Alert recipients | Set Manage Alerts to include licensing, hardware defects and maintenance, sent to a monitored shared mailbox; allow-list noreply@meraki.com and noreply-support@meraki.com | Security and end-of-life notices are not lost to spam filters | P2 |
| ORG-07 | Special announcements | Send to all Full organization admins or a monitored distribution list | Advisories reach the people who can act | P3 |
| ORG-08 | Privacy setting | Enable Privacy so new networks start with privacy-sensitive features off | Safe-by-default network creation | P3 |
| ORG-09 | Organization separation | Keep production, lab and customer/MSP estates in separate organizations; never share admin accounts or API keys between them | Contains compromise and mistakes | P2 |
| ORG-10 | Licence and expiry monitoring | Track licence expiry at least 90 days ahead and alert on approach | An expired licence can take devices out of management and security-feature coverage | P3 |

---

## 3. Logging, monitoring and alerting

Dashboard keeps limited history, so anything needed for investigation or audit should be forwarded to a SIEM. The changes most worth catching are support-access changes, admin changes and firewall edits.

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| LOG-01 | Configuration change log | Review **Organization > Monitor > Configuration changes** weekly; export to the SIEM through the API on a schedule | Shows who changed what, including support-access grants and revokes | P1 |
| LOG-02 | Syslog to SIEM | Per network (**Network-wide > General > Reporting**), add the collector with roles: Appliance event log, Security events, Flows, URLs, Wireless event log, Switch event log, Air Marshal events | Preserves events beyond Dashboard retention | P1 |
| LOG-03 | Admin event alerting | Alert in the SIEM/IdP on any local (non-SAML) sign-in, new admin creation, role change, API key generation, and Support Access moved away from Blocked | Highest-signal management-plane events | P1 |
| LOG-04 | Network alerts | **Network-wide > Alerts**: enable email/webhook alerts for device offline, uplink/VPN down, rogue and new DHCP server, rogue AP, IDS/IPS and malware detections, firmware upgrades, settings changed | Fast detection of outages and attack indicators | P2 |
| LOG-05 | Time accuracy | Confirm the correct network time zone; normalise to UTC in the SIEM | Reliable event correlation | P3 |
| LOG-06 | Retention | Retain forwarded logs per policy (suggested: 12 months, 90 days hot) | Audit and incident-response needs | P2 |
| LOG-07 | Configuration backup | Snapshot configuration through the API (or an infrastructure-as-code repo) after each approved change and keep it in version control | Gives you a known-good reference for recovery | P2 |

---

## 4. Network-wide and device management

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| DEV-01 | Local device credentials | **Network-wide > General > Device configuration**: unique local username and strong password per network, vaulted, rotated at least annually and when staff with knowledge leave | Protects the local status page and direct device access, independent of Dashboard SSO | P1 |
| DEV-02 | Local status page exposure | Reachable from the management VLAN only. On MX, disable Web (local status and configuration) on the WAN and restrict LAN access with firewall rules | Stops the local page being an Internet-facing login | P1 |
| DEV-03 | Dedicated management VLAN | Put MS management interfaces and MR/MX management traffic in a dedicated VLAN reachable only from admin jump hosts | Separates management from user traffic | P1 |
| DEV-04 | Firmware currency | Use the stable release train; schedule upgrade windows per network (**Organization > Monitor > Firmware upgrades**); apply critical CVE fixes within 14 days and others within 30 (suggested); no device more than two releases behind | Meraki can push firmware even when support access is blocked, so the schedule is how you control timing | P1 |
| DEV-05 | Firmware staging | Upgrade a pilot network first, then production in waves | Limits the impact of a bad release | P2 |
| DEV-06 | Configuration templates | Use configuration templates or an IaC pipeline to apply the baseline consistently; document every per-site override | Prevents drift | P2 |
| DEV-07 | Tagging for scope | Tag devices and networks (site, criticality, owner) and scope admin roles and alerts by tag | Makes least-privilege roles practical | P3 |
| DEV-08 | Cloud reachability | Allow only the Meraki cloud destinations and ports Cisco publishes for your region on management-VLAN egress, not "any" | Reduces command-and-control and exfiltration paths | P2 |
| DEV-09 | Decommissioning | Remove retired devices from the network, unclaim from the organization and factory-reset before disposal or return | Prevents stale credentials and configuration leaving the estate | P2 |
| DEV-10 | Physical security | Locked cabinets for switches and gateways; tamper-evident labels at remote sites | Local access defeats cloud controls | P3 |

---

## 5. MX security appliance

Path: **Security & SD-WAN > Configure**. Threat-protection features need the appropriate licence; record an exception where a feature is unlicensed.

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| MX-01 | Management exposure on WAN | Firewall > Services: block remote status pages, Web (local status and configuration), SNMP and ICMP ping from the Internet; allow only from named management addresses where needed | Removes the appliance's management surface from the Internet | P1 |
| MX-02 | Inbound firewall | Default deny inbound; review port forwarding and 1:1 NAT quarterly; allow only required sources and ports; remove rules with no owner | Open forwards are the most common perimeter exposure | P1 |
| MX-03 | Outbound L3 firewall | Replace the default allow-any with explicit allows by VLAN or group policy and a logged final deny where feasible | Limits lateral movement and malware callback | P2 |
| MX-04 | Intrusion prevention | IDS/IPS in **Prevention** mode with the **Security** ruleset (Balanced where performance requires); allow-list only with a documented reason | Blocks known exploit traffic inline | P1 |
| MX-05 | Advanced Malware Protection | Enable AMP; keep the allow-list short and reviewed | Detects malicious downloads at the gateway | P2 |
| MX-06 | Content filtering | Block malware, phishing, newly registered domains and anonymiser categories; use Cisco Umbrella DNS security where licensed | Reduces web-borne threats | P2 |
| MX-07 | Geo-IP and L7 rules | Block countries with no business need; block high-risk applications (peer-to-peer, anonymisers) | Cuts exposure and abuse | P3 |
| MX-08 | Site-to-site VPN | Auto VPN hub-and-spoke; for non-Meraki peers use IKEv2, AES-256, SHA-256 or better, DH group 14 or above, PFS, and a unique 32+ character pre-shared key | Strong cryptography on third-party tunnels | P1 |
| MX-09 | Client VPN | Prefer certificate-based or RADIUS with MFA, or Cisco AnyConnect where licensed; restrict reachable subnets per group; no split tunnelling unless risk-accepted | Client VPN has no native two-factor and needs a third-party solution | P1 |
| MX-10 | Segmentation | Separate user, server, guest, IoT/OT and management VLANs with deny-by-default inter-VLAN rules | Limits blast radius; supports IEC 62443 zone and conduit design | P1 |
| MX-11 | Uplink and failover | Dual WAN with health checks; warm spare for critical sites | Availability of the gateway | P3 |
| MX-12 | DNS and DHCP | Trusted internal or Umbrella DNS; rogue DHCP alerts; disable unused scopes | Prevents DNS hijack and rogue servers | P2 |
| MX-13 | Security events review | Forward security events to the SIEM (LOG-02); weekly review of top blocked sources and IPS hits | Detection and tuning | P2 |

---

## 6. MR wireless

Path: **Wireless > Configure** (Access control, Firewall & traffic shaping, Radio settings) and **Wireless > Monitor > Air Marshal**.

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| WLS-01 | Corporate SSID | WPA3-Enterprise (or WPA2/WPA3-Enterprise transition) with 802.1X and RADIUS; EAP-TLS for managed devices | Per-user identity and strong encryption | P1 |
| WLS-02 | No weak protocols | No open, WEP or WPA1 SSIDs. For PSK networks use WPA3-Personal or WPA2 with a 20+ character key; prefer Identity PSK via RADIUS over one shared key | Removes broken or guessable authentication | P1 |
| WLS-03 | Management frame protection | Enable 802.11w (PMF): required for WPA3, optional or required for WPA2 where clients allow | Defends against deauthentication attacks | P2 |
| WLS-04 | RADIUS hardening | Two RADIUS servers, 32+ character shared secrets, RADSEC or IPsec where supported, source restricted to AP management addresses; use the Dashboard RADIUS test before rollout | Protects the authentication path | P1 |
| WLS-05 | Guest isolation | Client isolation on; Layer 3 rule denying local LAN; splash page with sign-on or sponsored access; bandwidth limit | Guests cannot reach corporate resources or each other | P1 |
| WLS-06 | IoT/OT SSIDs | Separate SSID and VLAN, Identity PSK or MAC-based RADIUS, firewall rules limited to required destinations | Constrains weakly secured devices | P2 |
| WLS-07 | Air Marshal | Enable rogue AP detection and alerts; review weekly; use containment only after legal review | Finds evil-twin and rogue devices | P2 |
| WLS-08 | Unused SSIDs | Disable unused SSIDs; do not rely on hidden SSIDs for security | Smaller attack surface | P2 |
| WLS-09 | Radio plan | Remove legacy data rates, use auto RF, disable unused bands | Reduces downgrade and interference attacks | P3 |
| WLS-10 | AP management | Place APs in the management VLAN, restrict the local status page (DEV-02), set local credentials (DEV-01) | Protects the AP itself | P1 |

---

## 7. MS switching

Path: **Switching > Configure** (Switch settings, Switch ports, Access policies, DHCP servers & ARP, ACL).

| ID | Control | Required setting | Why | Pri |
| --- | --- | --- | --- | --- |
| SW-01 | Port authentication | Access policies with 802.1X (MAB only as fallback); critical and guest VLAN for failures; host mode per device mix | Unknown devices cannot join the wired network | P1 |
| SW-02 | Unused ports | Disable all unused ports and place them in an unused VLAN; use port schedules where appropriate | Blocks rogue devices at the wall | P1 |
| SW-03 | DHCP snooping | Enable; trust only uplinks and DHCP server ports; alert on rogue DHCP servers | Stops rogue DHCP and spoofing | P1 |
| SW-04 | Dynamic ARP inspection | Enable on user VLANs once DHCP snooping is in place | Stops ARP spoofing and man-in-the-middle | P2 |
| SW-05 | Spanning-tree protection | BPDU guard on access ports, root guard toward non-core switches, loop guard on uplinks; set the root bridge deliberately | Prevents rogue switches and topology attacks | P1 |
| SW-06 | Storm control | Broadcast and multicast storm control on access ports | Contains loops and floods | P2 |
| SW-07 | Port isolation and ACLs | Port isolation where peer traffic is not needed; switch ACLs for inter-VLAN or management restrictions | Limits lateral movement | P2 |
| SW-08 | Allowed MACs | On static-device ports (printers, controllers) restrict to the known MAC | Detects device swaps | P3 |
| SW-09 | VLAN hygiene | Native VLAN set to an unused VLAN; trunks carry only required VLANs; management VLAN never used for user traffic | Reduces VLAN hopping | P1 |
| SW-10 | Switch management | Dedicated management VLAN (DEV-03), local credentials (DEV-01), firmware per DEV-04 | Protects the switch itself | P1 |
| SW-11 | Redundancy | Stacking or redundant uplinks at core and distribution; monitor uplink alerts | Availability | P3 |

---

## 8. Operations

**Change control.** All production changes go through a change record with a named approver. Emergency changes are retro-approved within two working days. A change that does not appear in the Dashboard change log under a named SAML user should be investigated.

**Break-glass use.** Local accounts (ADM-06) are used only when SSO or the IdP is unavailable. Each use needs an incident or change reference, vault checkout is logged, and the password is rotated afterwards.

**Exceptions.** Any deviation from a P1 control needs a written risk acceptance with an owner, a compensating control and an expiry no longer than six months. P2 and P3 deviations go in a register reviewed each cycle.

| Frequency | Activity |
| --- | --- |
| Continuous | SIEM alerts on LOG-03 events (local sign-in, role change, Support Access change) |
| Weekly | Review Configuration changes and Air Marshal; check security events and IPS hits |
| Monthly | Firmware status against DEV-04; review open exceptions |
| Quarterly | Administrator and role reconciliation; API keys and OAuth integrations; port forwards and firewall rules; confirm Support Access is Blocked |
| Annually | Full baseline audit; break-glass test; rotation of local device credentials |

---

## Automated audit script

[`scripts/audit_meraki_baseline.py`](scripts/audit_meraki_baseline.py) is a **read-only** checker for the organization-level controls the Dashboard API exposes: login security, administrator hygiene and SNMP. It uses only the Python standard library (Python 3.11 or later).

```bash
export MERAKI_API_KEY="<read-only service account key>"
python3 scripts/audit_meraki_baseline.py --list-orgs
python3 scripts/audit_meraki_baseline.py --org-id 123456
python3 scripts/audit_meraki_baseline.py --org-id 123456 --json > audit.json
```

It reports `PASS`, `WARN` or `FAIL` per control ID and exits non-zero if any `FAIL` is found, so it can run in a scheduled pipeline. It cannot check Support Access (not exposed by the API as far as the author knows), so confirm ADM-04 manually.

Use a dedicated read-only account for the key, and keep the key in a secrets manager.

## Framework mapping

Indicative only, to help evidence audits.

| Control group | NIST CSF 2.0 | ISO/IEC 27001:2022 Annex A | IEC 62443-3-3 / NIS2 Art. 21 |
| --- | --- | --- | --- |
| ADM (admin identity, MFA, SSO, support access) | PR.AA | 5.15, 5.16, 5.17, 5.18, 8.2, 8.5 | SR 1.1, SR 1.5, SR 2.1 / access control, MFA |
| ORG (API, integrations) | PR.AA, GV.SC | 5.19, 5.23, 8.2 | SR 1.2, SR 2.1 / supply chain and access control |
| LOG (logging, alerting) | DE.CM, DE.AE | 8.15, 8.16 | SR 6.1, SR 6.2 / incident handling and monitoring |
| DEV (device management, firmware) | PR.PS, ID.RA | 8.8, 8.9, 7.14 | SR 7.6, SR 2.12 / vulnerability handling, secure configuration |
| MX, WLS, SW (network security) | PR.IR, PR.PS | 8.20, 8.21, 8.22, 8.23 | SR 5.1, SR 5.2, SR 3.1 / network security, segmentation |

## Sources

- [Organization Settings, Cisco Meraki documentation](https://documentation.meraki.com/General_Administration/Organizations_and_Networks/Organization_Menu/Organization_Settings)
- [Managing Cisco Support Access to a Dashboard Organization](https://documentation.meraki.com/General_Administration/Privacy_and_Security/Managing_Cisco_Support_Access_to_a_Dashboard_Organization)
- [Cisco Administrator Access](https://documentation.meraki.com/General_Administration/Managing_Dashboard_Access/Cisco_Administrator_Access)
- [Managing Dashboard Administrators and Permissions](https://documentation.meraki.com/General_Administration/Managing_Dashboard_Access/Managing_Dashboard_Administrators_and_Permissions_(Modernized_View))
- [Configuring SAML Single Sign-on for Dashboard](https://documentation.meraki.com/General_Administration/Managing_Dashboard_Access/SAML_SSO_Integration/SAML_integration_for_Dashboard/)
- [SP-Initiated SAML SSO Configuration Guide](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Managing_Dashboard_Access/SP-Initiated_SAML_SSO_Configuration_Guide)
- [How to Configure and Manage Two-Factor Authentication](https://documentation.meraki.com/zGeneral_Administration/Other_Topics/Two-Factor_Authentication)
- [Meraki Dashboard API documentation](https://developer.cisco.com/meraki/api-v1/)

## Contributing

Issues and pull requests are welcome, especially corrections to menu paths, new Dashboard options, and verified evidence for controls in sections 3 to 7. Please cite Meraki documentation where possible.

## Licence

Released under the MIT Licence. See `LICENSE`.
