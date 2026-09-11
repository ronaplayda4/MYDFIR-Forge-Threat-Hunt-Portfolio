# Microsoft Defender XDR – DefenderRemover / RDP Investigation

## Investigation Overview

This investigation was performed in an isolated MYDFIR lab environment using Microsoft Defender XDR.

The investigation began by reviewing the process tree and related endpoint activity. Suspicious execution involving `DefenderRemover.exe` was identified, followed by registry changes affecting Microsoft Defender security settings.

I then pivoted from the process evidence into Advanced Hunting to correlate process, registry, logon, and network activity.

The combined evidence showed remote access to the affected system followed by activity that attempted to weaken Microsoft Defender protections.

---

## Investigation Summary

**Affected Device:** `mts-dc.mts.local`

**Affected Account:** `mts\administrator`

**Primary Suspicious Activity:**
- Remote access to the affected device
- Execution of DefenderRemover-related activity
- Microsoft Defender registry modifications
- Multiple Defender security controls set to disabled
- Registry key deletion activity
- Suspicious remote IP activity

**Verdict:** True Positive – Malicious Activity

---

## Initial Process Analysis

The investigation began with the Microsoft Defender XDR process tree.

Process activity showed `DefenderRemover.exe` associated with the `administrator` account. The process evidence provided the initial lead for determining what occurred on the endpoint.

Additional process activity showed scripts and child processes associated with the suspicious execution chain.

This evidence was used as the starting point before pivoting into Advanced Hunting for deeper correlation.

---

## Registry Modification Evidence

Advanced Hunting identified `regedit.exe` importing the following registry file:

`Remove_defender\RemoveDefender.reg`

The activity occurred under the `administrator` account.

Multiple Windows Defender registry values were modified.

Examples included:

- `DisableIOAVProtection = 1`
- `DisableRealtimeMonitoring = 1`
- `DisableBehaviorMonitoring = 1`
- `DisableAntiSpyware = 1`
- `DisableScanningNetworkFiles = 1`

These changes are significant because they weaken or disable Microsoft Defender security protections.

Registry deletion activity associated with the same operation was also identified.

---

## Logon Correlation

I next reviewed `DeviceLogonEvents` for the `administrator` account around the suspicious activity.

The hunting results identified successful network and RemoteInteractive activity associated with two remote IP addresses:

- `131.109.131.82`
- `173.255.162.181`

The events included:

- `LogonSuccess`
- `RemoteInteractive`
- `Unlock`
- Network logons

The remote logon activity occurred shortly before the Defender registry modifications.

---

## Network / RDP Correlation

The investigation was then pivoted into `DeviceNetworkEvents`.

A network event showed:

**Source / Remote IP:** `173.255.162.181`

**Destination Device:** `mts-dc.mts.local`

**Destination IP:** `192.168.10.8`

**Destination Port:** `3389`

**Protocol:** TCP

**Action:** `InboundConnectionAccepted`

**Process:** `svchost.exe`

**Command Line:** `svchost.exe -k termsvcs -s TermService`

Port `3389` and the Windows Terminal Services process provide evidence consistent with an accepted RDP connection to the affected device.

This network evidence correlated with the RemoteInteractive logon activity observed in `DeviceLogonEvents`.

---

## IP Reputation Analysis

The remote IP addresses were reviewed using external threat-intelligence sources.

### 131.109.131.82

VirusTotal showed multiple security vendors flagging this IP as malicious, suspicious, phishing-related, or malware-related at the time of the investigation.

WHOIS information was also reviewed to understand the registered network allocation.

WHOIS registration information alone does not identify the individual responsible for the activity and was therefore treated only as contextual evidence.

### 173.255.162.181

This IP was directly associated with the accepted inbound RDP connection observed in Defender XDR.

Threat-intelligence results for this IP were not treated as proof of maliciousness by themselves. The stronger evidence was its direct correlation with the RDP and logon telemetry.

---

## Evidence Correlation

The investigation correlated multiple independent telemetry sources:

**Process Tree → Logon Events → Network/RDP Events → Registry Changes → Threat Intelligence**

The sequence showed:

1. Remote activity involving the `administrator` account.
2. Successful remote/network logons.
3. An accepted inbound RDP connection to TCP port 3389.
4. Suspicious DefenderRemover-related process activity.
5. Execution of `regedit.exe`.
6. Import of `RemoveDefender.reg`.
7. Multiple Microsoft Defender protections disabled.
8. Registry deletion activity.
9. Threat-intelligence findings associated with one of the observed remote IP addresses.

The correlation between endpoint, authentication, network, and registry telemetry increased confidence that the activity was malicious rather than an isolated administrative registry change.

---

## Verdict

**True Positive – Malicious Activity**

The evidence supports malicious activity involving remote access followed by attempts to weaken Microsoft Defender security controls.

The available telemetry identifies the affected account as `mts\administrator`, but it does **not conclusively establish the real-world identity of the person operating the account**.

The remote IP addresses should therefore be documented as infrastructure associated with the observed activity rather than definitive attribution to a specific attacker.

---

## Recommendations

- Isolate the affected endpoint if this activity occurs in a production environment.
- Reset or rotate credentials associated with the compromised administrator account.
- Review additional authentication activity involving the administrator account.
- Restore and verify Microsoft Defender security settings.
- Investigate the origin and execution of `DefenderRemover.exe` and `RemoveDefender.reg`.
- Review RDP exposure and restrict external RDP access where possible.
- Review other systems for connections involving the identified remote IP addresses.
- Search for similar Defender registry modifications across the environment.
- Preserve relevant Defender XDR telemetry for further investigation.

---

# Appendix – Process Analysis and Advanced Hunting

The detailed technical hunting was placed in this appendix so the primary investigation report remains concise while preserving the supporting evidence.

## A. Logon Investigation

`DeviceLogonEvents` was used to examine authentication activity involving the administrator account.

The investigation focused on:

- Timestamp
- Account domain
- Account name
- Action type
- Logon type
- Remote IP
- Remote device
- Initiating process

This identified the remote/network authentication activity associated with the investigation.

---

## B. Network Investigation

`DeviceNetworkEvents` was used to correlate the remote IP addresses with network connections involving the affected device.

This identified the accepted inbound connection:

`173.255.162.181 → 192.168.10.8:3389`

The associated Windows service process was:

`svchost.exe -k termsvcs -s TermService`

This provided network-level evidence supporting the RDP activity.

---

## C. Registry Investigation

`DeviceRegistryEvents` was used to identify Defender-related registry modifications.

The investigation identified `regedit.exe` importing:

`RemoveDefender.reg`

and setting multiple Defender security controls to `1`, indicating disabled protections.

Registry deletion events associated with the same activity were also identified.

---

## D. IOC Enrichment

The observed remote IP addresses were checked using external threat-intelligence and WHOIS sources.

Threat-intelligence findings were used as supporting evidence only and were correlated with Defender XDR telemetry before reaching the final verdict.

---

## Investigation Methodology

**Process Tree → Logs/Evidence → Advanced Hunting → Logon Correlation → Network/RDP Correlation → Registry Validation → IOC Enrichment → Verdict**

This investigation demonstrates how multiple sources of endpoint telemetry can be correlated to reconstruct suspicious activity instead of relying on a single alert or indicator.

---

## Lab Acknowledgment

This investigation was performed in an isolated MYDFIR lab environment for cybersecurity training and portfolio development.
