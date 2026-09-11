# Microsoft Defender XDR Investigation — Incident 2479

> **Lab Disclaimer:** This investigation was performed in an isolated MYDFIR cybersecurity training environment. The report is intended for defensive security training and portfolio documentation.

## Incident Overview

**Incident:** Hands-on keyboard attack was launched from a compromised account (Attack Disruption)  
**Severity:** High  
**Verdict:** True Positive — Compromised Account / Human-Operated Malicious Activity  
**Affected Host:** `mts-dc.mts.local`  
**Affected Account:** `MTS\administrator`  
**Date:** September 9, 2026  
**Timezone:** UTC  

---

## Executive Summary

Microsoft Defender XDR detected suspicious hands-on-keyboard activity involving the `MTS\administrator` account on `mts-dc.mts.local`.

Advanced Hunting identified an accepted inbound RDP connection from `173.255.162.181` to TCP port `3389` on the affected host. Shortly afterward, successful authentication and RemoteInteractive activity involving the `MTS\administrator` account were observed.

Later in the same attack window, `DefenderRemover.exe` executed from the administrator desktop. The process spawned `cmd.exe` to run `Script_Run.bat`, which then launched PowerShell, PowerRun, registry modification activity, and a system restart.

Registry telemetry confirmed multiple Microsoft Defender policy values were modified in an apparent attempt to weaken endpoint protection.

---

## Key Findings

- Remote RDP connection from `173.255.162.181` was accepted by `mts-dc.mts.local` on TCP/3389.
- `MTS\administrator` showed successful remote authentication and RemoteInteractive activity shortly afterward.
- `DefenderRemover.exe` executed under the administrator account.
- `DefenderRemover.exe` spawned `cmd.exe /c .\Script_Run.bat`.
- The batch script launched PowerShell with `-ExecutionPolicy Bypass`.
- PowerShell executed `RemoveSecHealthApp.ps1`.
- PowerRun was used to invoke `regedit.exe`.
- `RemoveDefender.reg` was silently imported.
- Multiple Defender-related registry values were modified.
- The same command chain initiated a forced system restart.
- `131.109.131.82` was also observed in successful administrator network authentication and had negative VirusTotal reputation, but its exact role in the compromise was not conclusively established.

---

## Timeline

| Time (UTC) | Activity |
|---|---|
| ~21:07 | `131.109.131.82` observed in successful Network authentication as `MTS\administrator` |
| 21:12:59 | `173.255.162.181` established an accepted inbound RDP connection to `mts-dc.mts.local:3389` |
| ~21:13 | `MTS\administrator` generated successful remote authentication and RemoteInteractive activity |
| 21:22:29 | `DefenderRemover.exe` observed on the administrator desktop; Defender detected PowerRun-related hacktool behavior |
| 21:24:29–21:24:31 | `DefenderRemover.exe` executed under `administrator` |
| 21:24:32 | `DefenderRemover.exe` spawned `cmd.exe /c .\Script_Run.bat` |
| 21:24:35 | PowerShell launched with execution-policy bypass and executed `RemoveSecHealthApp.ps1` |
| 21:24:42 | `PowerRun.exe` invoked `regedit.exe /s ...\RemoveDefender.reg` |
| 21:24:43 | Defender-related registry values were modified |
| ~21:25 | `shutdown.exe /r /f /t 10` initiated a forced restart |

---

## 5Ws + How

### Who
The compromised/used account was `MTS\administrator`. The actual human operator could not be identified from the available telemetry.

### What
A remote administrator session was followed by execution of `DefenderRemover.exe`, command-shell and PowerShell activity, PowerRun execution, Defender registry modification, and a system restart.

### When
The principal malicious activity occurred on September 9, 2026, approximately 21:12–21:25 UTC.

### Where
The affected system was `mts-dc.mts.local` (`192.168.10.8` in the RDP telemetry).

### Why
The observed behavior is consistent with Defense Evasion / Defense Impairment. The exact threat actor objective could not be determined.

### How
An inbound RDP connection from `173.255.162.181` was accepted by `mts-dc.mts.local` on TCP/3389. Shortly afterward, administrator remote-session activity was observed. `DefenderRemover.exe` later executed and launched a process chain that attempted to weaken Microsoft Defender security controls.

---

## Verdict

**True Positive — Compromised Account / Human-Operated Malicious Activity**

The evidence supports malicious use of the `MTS\administrator` account on `mts-dc.mts.local`.

The combination of:

```text
Accepted RDP connection
        ↓
Administrator remote-session activity
        ↓
DefenderRemover.exe
        ↓
cmd.exe / Script_Run.bat
        ↓
PowerShell / PowerRun
        ↓
Defender registry modification
        ↓
Forced reboot
```

strongly supports malicious hands-on-keyboard activity rather than legitimate administration.

---

## Recommendations

1. Keep `mts-dc.mts.local` isolated until the host is confirmed clean.
2. Reset or rotate credentials for `MTS\administrator` and review other privileged accounts.
3. Hunt across the environment for both suspicious IPs and the DefenderRemover SHA-256.
4. Search for `DefenderRemover.exe`, `RemoveDefender.reg`, `RemoveSecHealthApp.ps1`, `Script_Run.bat`, and PowerRun activity.
5. Verify and restore Microsoft Defender security settings.
6. Restrict RDP access to approved administrative systems, VPNs, or trusted networks.
7. Review the administrator account for lateral movement, persistence, privilege escalation, and credential-access activity.
8. Preserve relevant Advanced Hunting queries, screenshots, hashes, and timestamps.
9. Perform additional forensic review of the affected domain controller before returning it to normal operation.

---

---

# Appendix — Technical Investigation Evidence

The detailed process analysis, Advanced Hunting work, screenshots, and IOC enrichment are intentionally placed below the recommendations so the main report flows from **findings → summary → 5Ws → verdict → recommendations** before presenting the supporting technical evidence.

## Appendix A — Process Analysis

### A.1 Starting Point: Defender XDR Process Tree

![Process tree evidence](images/dbf76b9f-98c5-4e06-aedc-92451f5a71d6.png)

**Analyst note:** The investigation started in the Defender XDR process/story tree. The goal was to understand the parent/child relationships, identify suspicious processes, and collect pivots such as the host, account, timestamp, process names, command lines, and PIDs.

### A.2 Process and Command-Line Correlation

![Process correlation evidence](images/6c389da1-5a7c-4906-9c0e-ce0810f85d76.png)

**Analyst note:** After reviewing the process evidence, the investigation followed the suspicious execution chain rather than treating each alert independently. The key chain was:

```text
MTS\administrator
        ↓
explorer.exe
        ↓
DefenderRemover.exe
        ↓
cmd.exe /c .\Script_Run.bat
        ↓
PowerShell / PowerRun
        ↓
regedit.exe / RemoveDefender.reg
        ↓
Microsoft Defender configuration changes
```

Process IDs and a narrow **±5-minute window** were used as pivots to reduce noise and identify direct child processes.

## Appendix B — Advanced Hunting

Advanced Hunting was used **after** the initial process-tree and log review. Indicators discovered during the initial analysis were converted into targeted KQL pivots across process, logon, network, and registry telemetry.

### B.1 Administrator Authentication Activity

![Administrator logon evidence](images/116019cd-cf41-43c7-b811-25fe02139011.png)

**Analyst note:** `DeviceLogonEvents` was used to investigate the `MTS\administrator` account around the attack window. The objective was to determine whether remote authentication activity occurred before the malicious process execution.

### B.2 RDP Network Correlation

![RDP network evidence](images/ecad7c99-c17b-4f55-91c0-acbd70ee4448.png)

**Analyst note:** `DeviceNetworkEvents` identified an accepted inbound connection from `173.255.162.181` to local TCP port `3389` on `mts-dc.mts.local`. The event was associated with Windows Remote Desktop Services (`TermService`). This network evidence was correlated by timestamp with the administrator remote-session activity.

### B.3 Defender Registry Tampering

![Registry hunting evidence](images/4effd7ed-894b-4317-9b55-775566661306.png)

**Analyst note:** After process analysis identified `regedit.exe` and `RemoveDefender.reg`, `DeviceRegistryEvents` was used to verify the resulting changes. Defender-related values observed included:

```text
DisableIOAVProtection = 1
DisableRealtimeMonitoring = 1
DisableBehaviorMonitoring = 1
DisableAntiSpyware = 1
DisableScanningNetworkFiles = 1
```

This was direct telemetry supporting an attempt to impair Microsoft Defender protections.

### B.4 Investigation Correlation

The evidence was correlated chronologically:

```text
Defender XDR process tree
        ↓
Suspicious process/file indicators
        ↓
Advanced Hunting with host + account + timestamps + PIDs
        ↓
Remote authentication investigation
        ↓
RDP TCP/3389 network validation
        ↓
DefenderRemover process chain
        ↓
PowerShell / PowerRun / regedit
        ↓
Defender registry modifications
        ↓
Forced reboot
```

No single event was used to determine the verdict. The conclusion came from the **combined network, authentication, process, command-line, and registry evidence**.

## Appendix C — IOC and OSINT Analysis

### C.1 IP Indicators

| Indicator | Investigation context |
|---|---|
| `173.255.162.181` | Accepted inbound RDP connection to `mts-dc.mts.local:3389`; temporally correlated with administrator remote-session activity |
| `131.109.131.82` | Earlier successful `MTS\administrator` Network authentication; exact role in the later hands-on-keyboard activity was not conclusively established |

### C.2 VirusTotal Context

![VirusTotal IOC evidence](images/5195c9e0-50bc-4ffd-ae61-f573a1649978.png)

**Analyst note:** VirusTotal/OSINT was used as supporting context, not as the basis for the True Positive verdict. `131.109.131.82` showed multiple negative vendor classifications during analysis, while the relevance of `173.255.162.181` came primarily from Defender telemetry showing the accepted RDP connection.

### C.3 WHOIS Interpretation

WHOIS information was treated as **IP ownership/registration context only**. It was not used to claim the physical location or identity of the threat actor.

## Appendix D — Key Artifacts

| Artifact | Relevance |
|---|---|
| `DefenderRemover.exe` | Suspicious executable at the center of the process chain |
| `Script_Run.bat` | Batch file launched through `cmd.exe` |
| `RemoveSecHealthApp.ps1` | PowerShell script executed with execution-policy bypass |
| `PowerRun.exe` | Privileged execution/hacktool activity |
| `RemoveDefender.reg` | Registry file associated with Defender configuration changes |
| `shutdown.exe /r /f /t 10` | Forced restart initiated during the execution chain |

### SHA-256

```text
c8dfedfdb3ee6c5761ac119655d522850abd84649e13d0bf55efa8f0ad4f7fd7
```

---

## Investigation Method

**Process Tree → Logs/Evidence → Identify Pivots → Advanced Hunting → Process Correlation → Logon Correlation → Network/RDP Correlation → Registry Validation → IOC Enrichment → Verdict**

This structure preserves the technical evidence while keeping the primary incident report concise and readable.

### Additional Supporting Evidence

The following screenshots are retained as additional evidence so a reviewer can independently follow the pivots made during the investigation.

#### DefenderRemover launched from Explorer

![DefenderRemover launched from Explorer](images/defenderremover-explorer-process.png)

This event shows `DefenderRemover.exe` executing under the `administrator` account with `explorer.exe` as the initiating process. This helped establish the beginning of the suspicious execution chain.

#### Script_Run child-process activity

![Script Run child processes](images/script-run-child-processes.png)

Advanced Hunting identified multiple child processes tied to `cmd.exe /c .\\Script_Run.bat`, including PowerShell, `PowerRun.exe`, and `shutdown.exe`. This correlated the batch script with the later Defender-tampering activity.

#### DefenderRemover file details and reputation

![DefenderRemover file details](images/defenderremover-file-details-virustotal.png)

The process details show the executable path, hashes, unknown signer status, elevated execution context, and the Defender portal's VirusTotal detection ratio. These attributes strengthened the case that the executable required further investigation.

#### Registry key deletions associated with RemoveDefender.reg

![Registry key deletions](images/registry-key-deletions.png)

Registry hunting showed `regedit.exe` importing `RemoveDefender.reg` and performing registry deletions under both administrator and SYSTEM contexts. This supplements the Defender policy-value modifications documented above.

#### RemoteInteractive administrator logons

![RDP RemoteInteractive logons](images/rdp-remoteinteractive-logons.png)

Logon telemetry shows repeated `RemoteInteractive` activity for the `MTS\\administrator` account associated with remote IP `173.255.162.181`. This was correlated with the network evidence showing inbound TCP/3389 activity to the domain controller.

> **Analyst note:** WHOIS and VirusTotal enrichment provide infrastructure and reputation context; they do not by themselves identify the human operator behind an IP address.
