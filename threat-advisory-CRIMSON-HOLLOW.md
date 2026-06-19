# Threat Advisory: CRIMSON HOLLOW Targets Cloud-Hosted Indian SaaS Providers

**Tracking:** CRIMSON HOLLOW (Hollow Spider)
**Classification:** TLP:AMBER
**First observed:** Q1 2026 · **Last activity:** Ongoing
**Threat type:** Financially-motivated intrusion set / initial access broker with BEC monetization

---

## Key Judgments

- CRIMSON HOLLOW is a financially-motivated activity cluster conducting opportunistic intrusions
  against mid-market software and business-services organizations in India and the wider South Asia
  region. We assess with **moderate confidence** that the group operates as an initial access broker
  that also monetizes access directly through business email compromise (BEC) and data theft.
- The group favors **living-off-the-edge** tradecraft: it harvests exposed internet-facing services,
  validates credentials against cloud identity providers, and then operates inside Microsoft 365
  using legitimate sessions rather than malware. This keeps the endpoint footprint minimal and
  shifts the detectable signal into network, WAF, and cloud audit telemetry.
- A recurring hallmark is **infrastructure reuse across phases** — the same egress hosts used to
  probe the perimeter later appear in cloud sign-in activity, providing defenders a reliable
  cross-domain correlation opportunity.

## Background

CRIMSON HOLLOW activity has been characterized by a disciplined, repeatable operational sequence
rather than novel tooling. The group appears to triage targets at scale, prioritizing organizations
that expose a public web application alongside a Microsoft 365 tenant. Observed operations
consistently progress from external reconnaissance, through perimeter and identity probing, to
hands-on-cloud objectives — typically within a compressed timeframe once valid credentials are
obtained.

The actor demonstrates familiarity with ASP.NET/IIS web stacks and with Microsoft 365
administrative surfaces. There is no evidence of bespoke malware; the intrusion lifecycle is
executed almost entirely with commodity scanners, scripting toolkits, and native cloud functionality.

## Victimology

Confirmed and suspected targeting centers on:

- **Sector:** Software-as-a-service, IT services, and digital-commerce operators.
- **Geography:** India (primary), with opportunistic reach into neighboring markets.
- **Technology profile:** Public ASP.NET / IIS web portals fronted by cloud WAF services; Microsoft
  365 tenants (Exchange Online, SharePoint, OneDrive, Teams); FortiGate perimeter with SSL-VPN and
  web filtering; predominantly Windows endpoint estates.

## Technical Analysis

### Phase 1 — Reconnaissance of the public web estate
The intrusion begins with automated enumeration of the victim's internet-facing web application.
Operators use commodity reconnaissance scanners and scraping frameworks, interleaved with abuse of
aggressive content crawlers, to map application structure and probe for weak points. Activity
concentrates on metadata and configuration endpoints, error pages, and framework resource handlers
typical of ASP.NET deployments, as well as input-bearing application endpoints that accept query
parameters. A meaningful share of this traffic is rejected by the web application firewall, but the
volume and cadence reveal deliberate, tool-driven probing rather than organic browsing.

*ATT&CK:* T1595 Active Scanning · T1592 Gather Victim Host Information · T1190 Exploit Public-Facing Application (attempted)

### Phase 2 — Perimeter and remote-service probing
In parallel, CRIMSON HOLLOW probes the network perimeter. Telemetry shows sustained connection
attempts denied at the firewall, sweeps against legacy and administrative services (notably Telnet,
SSH, and RDP), and touches against the SSL-VPN portal consistent with credential validation.
Abnormal TLS negotiation against the perimeter has also been observed, indicative of non-standard
clients or evasion attempts. The group's interest in the VPN and remote-administration surfaces
reflects a preference for legitimate remote-access footholds over exploitation.

*ATT&CK:* T1133 External Remote Services · T1110 Brute Force · T1046 Network Service Discovery

### Phase 3 — Credential access and cloud account takeover
Where perimeter footholds are unavailable, the group pivots to the Microsoft 365 identity layer.
Authentication telemetry shows clusters of failed sign-ins resolving into successful logons —
consistent with password spraying and credential stuffing using previously harvested material.
Once authenticated, CRIMSON HOLLOW characteristically accesses the tenant through **scripted,
non-interactive HTTP clients** rather than standard browsers, indicative of automated tooling
operating against the Microsoft 365 service endpoints and the possible reuse of stolen session
material.

*ATT&CK:* T1078.004 Valid Accounts: Cloud Accounts · T1110 Brute Force · T1550 Use of Alternate Authentication Material

### Phase 4 — Persistence, collection, and exfiltration
With a foothold established, the actor moves to entrench access and achieve objectives. Observed
post-compromise behavior includes directory changes that create or add accounts, credential
manipulation through password changes and resets, and high-volume access to mailbox and file
content. Bulk download, upload, and external-sharing operations against SharePoint and OneDrive
indicate staging and exfiltration of business data, while mailbox access patterns are consistent
with reconnaissance for, and execution of, business email compromise.

*ATT&CK:* T1136.003 Create Account: Cloud Account · T1098 Account Manipulation · T1114 Email Collection · T1530 Data from Cloud Storage · T1567.002 Exfiltration to Cloud Storage

## Infrastructure and Indicators

CRIMSON HOLLOW operates from a mix of cloud-hosted and broadband-attributed source addresses,
reusing several hosts across the perimeter-probing and cloud-access phases. Source addresses
observed in both firewall egress and cloud sign-in activity should be treated as high-priority.
Operators favor commodity scanning and scripting toolkits whose client signatures persist in WAF
and cloud telemetry; the group has not been observed spoofing these signatures to mimic mainstream
browsers.

Defenders should note that high-volume corporate egress addresses and mainstream identity-provider
ranges will appear adjacent to malicious activity and must be baselined out to avoid false positives.

## Recommendations

- Enforce phishing-resistant MFA across all Microsoft 365 accounts and disable legacy/basic
  authentication paths.
- Alert on non-interactive or scripted HTTP client access to Microsoft 365 by user accounts.
- Restrict and monitor exposure of Telnet, SSH, RDP, and the SSL-VPN portal; alert on repeated
  authentication failures followed by success.
- Correlate WAF block/deny activity and firewall-denied sources against subsequent successful cloud
  sign-ins from the same infrastructure.
- Monitor directory and credential-management events (account creation, password change/reset) and
  anomalous bulk file download/share in SharePoint and OneDrive.

## Indicators of Compromise

Indicators below were observed in telemetry across the perimeter, WAF, and cloud audit sources.
Source addresses seen in both firewall and cloud sign-in activity are highest priority. Note that
the corporate NAT egress and Microsoft identity-provider ranges appear adjacent to malicious
activity and must be excluded from alerting.

| Indicator | Type | Context | Confidence |
|---|---|---|---|
| `203.192.232.58` | IPv4 | Seen in **both** cloud sign-in and firewall egress | High |
| `203.192.206.145` | IPv4 | Cloud sign-in | Medium |
| `35.154.127.29` | IPv4 | Cloud sign-in | Medium |
| `106.192.125.130` | IPv4 | Cloud sign-in | Medium |
| `83.111.193.170` | IPv4 | Cloud sign-in | Medium |
| `27.59.100.204` | IPv4 | Cloud sign-in | Low |
| `223.228.138.225` | IPv4 | Cloud sign-in | Low |
| `203.76.182.246` | IPv4 | Firewall egress | Low |
| `Go-http-client/1.1` | User-Agent | Scripted M365 access | High |
| `RecScan/1.0` | User-Agent | WAF-blocked recon scanner | High |
| `Scrapy/2.16.0` | User-Agent | WAF-blocked scraping framework | Medium |
| `Bytespider`, `Sogou web spider` | User-Agent | WAF-blocked aggressive crawlers | Low (context) |

**Exclusions (do not alert):** `192.46.214.96` (corporate NAT egress), `20.190.175.0/24`
(Microsoft identity provider), user agents beginning `Microsoft SkyDriveSync`.

## Detection — Sigma Rules

The following Sigma rules express the behaviors above as detection hypotheses. Field names follow
the environment's OCSF-mapped schema. Threshold/correlation logic is annotated where the base Sigma
format cannot express it directly.

```yaml
title: Scripted Non-Browser Access to Microsoft 365
id: 9c1f0a3e-0001-4a10-b001-crimsonhollow01
status: experimental
description: Access to M365 from automation/SDK HTTP clients rather than interactive browsers.
tags: [attack.initial-access, attack.t1078.004, attack.t1550]
logsource:
  product: office365
  service: unified_audit
detection:
  selection:
    metadata.product.name: 'Office 365'
    http_request.user_agent|startswith: ['Go-http-client', 'python-requests', 'curl', 'axios']
  condition: selection
falsepositives: [Approved backend integrations / service principals - baseline by actor.user.name]
level: high
```

```yaml
title: Microsoft 365 Password Spray / Credential Stuffing
id: 9c1f0a3e-0002-4a10-b001-crimsonhollow02
status: experimental
description: Multiple failed M365 logons from one source IP within a short window, then a success.
tags: [attack.credential-access, attack.t1110]
logsource:
  product: office365
  service: unified_audit
detection:
  selection:
    metadata.product.name: 'Office 365'
    activity_name: 'Logon'
    status: 'Failure'
  filter_known_good:
    src_endpoint.ip|cidr: '20.190.175.0/24'
  condition: selection and not filter_known_good
  # correlation: group_by src_endpoint.ip; event_count >= 10; timeframe 15m; then followed-by status=Success
falsepositives: [Misconfigured mail client looping on a stale password]
level: medium
```

```yaml
title: Cloud Account Persistence and Credential Manipulation
id: 9c1f0a3e-0003-4a10-b001-crimsonhollow03
status: experimental
description: Account creation or password change/reset that entrenches access after takeover.
tags: [attack.persistence, attack.t1136.003, attack.t1098]
logsource:
  product: office365
  service: unified_audit
detection:
  selection:
    metadata.product.name: 'Office 365'
    activity_name: ['Add User', 'Password Change', 'Password Reset']
  condition: selection
falsepositives: [Legitimate IT onboarding / helpdesk resets - correlate actor.user.name + src_endpoint.ip]
level: medium
```

```yaml
title: Bulk Mailbox and File Collection / Exfiltration (M365)
id: 9c1f0a3e-0004-4a10-b001-crimsonhollow04
status: experimental
description: High-volume download/upload/external-share of SharePoint/OneDrive content.
tags: [attack.collection, attack.exfiltration, attack.t1114, attack.t1530, attack.t1567.002]
logsource:
  product: office365
  service: unified_audit
detection:
  selection:
    metadata.product.name: 'Office 365'
    activity_name: ['Download', 'Upload', 'Share']
  condition: selection
  # correlation: group_by actor.user.name; event_count high vs per-user baseline; timeframe 1h
falsepositives: [Normal OneDrive sync - baseline http_request.user_agent startswith 'Microsoft SkyDriveSync']
level: low
```

```yaml
title: WAF Block/Deny Triggered by Reconnaissance Tooling
id: 9c1f0a3e-0005-4a10-b001-crimsonhollow05
status: experimental
description: WAF-denied requests from recon scanners / scraping frameworks against the web estate.
tags: [attack.reconnaissance, attack.t1595, attack.t1190]
logsource:
  product: f5_waf
  service: http
detection:
  verdict:
    metadata.product.name: 'F5 Distributed Cloud WAF'
    metadata.event_code: ['GET-block-403', 'GET-deny-403', 'POST-block-403', 'GET-block-200']
  tooling:
    http_request.user_agent|startswith: ['RecScan', 'Scrapy', 'Hello from Palo Alto Networks', 'Bytespider', 'Sogou']
  condition: verdict and tooling
falsepositives: [Benign SEO/search crawlers - context only, not standalone alert]
level: medium
```

```yaml
title: Exposure of Remote/Legacy Administration Services (Perimeter)
id: 9c1f0a3e-0006-4a10-b001-crimsonhollow06
status: experimental
description: Traffic to Telnet, SSH or RDP through the perimeter - remote-admin surface probing.
tags: [attack.discovery, attack.t1046, attack.t1133]
logsource:
  product: fortigate
  service: traffic
detection:
  selection:
    metadata.product.name: 'Fortigate'
    dst_endpoint.port: [23, 22, 3389]
  alt_app:
    app_name: 'TELNET'
  condition: selection or alt_app
falsepositives: [Sanctioned internal admin jump hosts - baseline by dst_endpoint.ip]
level: medium
```

```yaml
title: SSL-VPN Access and TLS Anomaly (Perimeter)
id: 9c1f0a3e-0007-4a10-b001-crimsonhollow07
status: experimental
description: SSL-VPN portal activity with abnormal TLS negotiation - credential validation/evasion.
tags: [attack.initial-access, attack.t1133, attack.t1110]
logsource:
  product: fortigate
  service: event
detection:
  vpn:
    metadata.product.name: 'Fortigate'
    unmapped.FTNTFGTsubtype: 'vpn'
  tls_anomaly:
    metadata.product.name: 'Fortigate'
    unmapped.FTNTFGTeventtype: 'ssl-anomaly'
  condition: vpn or tls_anomaly
falsepositives: [Legitimate remote workers - correlate failure->success and geo-velocity]
level: medium
```

```yaml
title: Infrastructure Reuse Across Perimeter and Cloud (Correlation)
id: 9c1f0a3e-0008-4a10-b001-crimsonhollow08
status: experimental
description: A source IP probing/egressing the firewall also appears in M365 sign-in activity.
tags: [attack.command-and-control, attack.t1078.004]
logsource:
  category: correlation
detection:
  # join: (src_endpoint.ip where metadata.product.name='Office 365')
  #       intersects (dst_endpoint.ip where metadata.product.name='Fortigate')
  condition: intersection_non_empty
falsepositives: [Shared CDN/cloud egress - exclude 192.46.214.96 and 20.190.175.0/24]
level: high
```

```yaml
title: CRIMSON HOLLOW Known Indicators (IOC Match)
id: 9c1f0a3e-0009-4a10-b001-crimsonhollow09
status: experimental
description: Atomic indicator match for observed infrastructure and tooling. Use as boost/enrichment.
tags: [attack.t1595, attack.t1078.004]
logsource:
  category: ioc
detection:
  src_ips:
    src_endpoint.ip: ['203.192.232.58', '203.192.206.145', '35.154.127.29', '106.192.125.130', '83.111.193.170', '27.59.100.204', '223.228.138.225']
  dst_ips:
    dst_endpoint.ip: ['203.192.232.58', '203.76.182.246']
  user_agents:
    http_request.user_agent|startswith: ['Go-http-client', 'RecScan', 'Scrapy']
  condition: src_ips or dst_ips or user_agents
falsepositives: [Corporate NAT egress 192.46.214.96 and Microsoft range 20.190.175.0/24 - exclude]
level: high
```

---
*Assessment reflects activity observed across network, web application firewall, and cloud audit
telemetry. Confidence levels are stated where attribution or intent is inferred.*
