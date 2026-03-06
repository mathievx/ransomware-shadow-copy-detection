---
title: Ransomware Precursor Detection via Shadow Copy Monitoring
date: December 13, 2025
---

## Context & Objective

This case study evaluates detection and response logic for ransomware precursor activity within a controlled Windows endpoint environment. The focus is not on encryption itself, but on recovery inhibition, specifically deletion of Volume Shadow Copies as preparatory destructive behavior.

The testing environment consisted of:
- Windows 10 endpoint
- Sysmon (SwiftOnSecurity configuration)
- LimaCharlie EDR sensor
- Sliver C2 framework for adversary simulation

Although executed within the same lab used for LSASS credential dumping analysis, this scenario is treated as an independent detection engineering problem. The objective is to determine:

I. How shadow copy deletion manifests at the telemetry level

II. Whether command-line semantics provide sufficient detection fidelity

III. When automated containment is operationally justified

The goal is not to demonstrate tool capability, but to evaluate behavioral confidence and response thresholds for impact-stage activity.

## Threat Model Assumptions

This scenario models a financially motivated ransomware intrusion conducted by a hands-on-keyboard operator following successful initial compromise.

**Attacker Type**
- Human-operated ransomware affiliate
- Post-exploitation phase
- Interactive C2 session established

**Assumed Privilege Level**
- Local administrator privileges obtained
- Ability to invoke `vssadmin.exe` successfully
- No EDR tampering performed prior to shadow deletion

Shadow copy deletion requires administrative context. The simulation assumes privilege escalation has already occurred.

**Assumed C2 Persistence**
- Stable command-and-control channel
- Interactive shell access
- No network containment in place prior to recovery inhibition

Shadow deletion is modeled as a deliberate pre-encryption action after attacker confidence in foothold persistence.

**Assumed Telemetry Integrity**
- Sysmon operational and correctly configured
- Command-line logging enabled
- LimaCharlie sensor functioning and forwarding events
- No log tampering or sensor bypass

This case study evaluates detection capability under intact telemetry conditions. Evasion via sensor impairment is out of scope.

## Why Shadow Copy Deletion Matters

Before encrypting files, many ransomware families delete Volume Shadow Copies to prevent recovery.

The command:

```
vssadmin delete shadows /all
```

is a strong behavioral signal because:
- It directly inhibits system recovery
- It has limited legitimate use cases
- It often appears shortly before encryption begins

Unlike LSASS access, shadow copy deletion is less ambiguous. It is closer to intent than reconnaissance or credential access. That difference influenced the response strategy.

## Observed Tradecraft in Ransomware Operations

Shadow copy deletion is not theoretical or niche behavior, it's consistently observed across real-world ransomware intrusions. 
[Red Canary](https://redcanary.com/blog/threat-detection/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/) documented an intrusion chain in which a malicious batch script pulled a secondary payload from Pastebin and ultimately invoked `vssadmin.exe` to remove Windows Volume Shadow Copies prior to encryption. Their detection logic around shadow copy manipulation has surfaced hundreds of confirmed malicious events, reinforcing the reliability of this behavior as a high-confidence signal of impact-stage activity.

This tradecraft is widely used by ransomware families including **Ryuk**, **Conti**, **LockBit**, **REvil**, **BlackCat (ALPHV)**, **Netwalker**, and **RobbinHood**, among others. In most documented campaigns, shadow copy deletion occurs after:

I. Initial access

II. Privilege escalation

III. Lateral movement

IV. Credential access

and immediately precedes encryption.

From an ATT&CK perspective, this aligns with:
- **T1490 – Inhibit System Recovery**
- **T1059 – Command and Scripting Interpreter**
- **T1105 – Ingress Tool Transfer**
- **T1486 – Data Encrypted for Impact**        

The sequencing matters. Shadow copy deletion is rarely exploratory; it is preparatory destruction. Unlike reconnaissance or credential access, which expand attacker capability, recovery inhibition reduces defender options and signals imminent business impact.

This real-world prevalence strengthens the decision to treat `vssadmin delete shadows /all` as high-confidence malicious behavior rather than ambiguous administrative activity. In operational environments, behaviors that directly degrade recovery mechanisms carry materially higher containment justification thresholds.

## Attack Simulation

From the active Sliver session on the compromised endpoint, I opened a system shell and executed:
```
vssadmin delete shadows /all
```

The goal was not to verify whether shadow copies existed, but to generate telemetry representing recovery inhibition behavior.
Immediately after execution, LimaCharlie generated detection noise based on built-in Sigma logic.

![Image](https://imgur.com/U0tHpxW.png)

Instead of relying on the default detection, I examined the raw event in the timeline to understand how the behavior was represented.

## Telemetry Analysis

The relevant event captured:
- Process name (`vssadmin.exe`)
- Command-line arguments
- Parent process
- Execution context
- Timestamp

![Image](https://imgur.com/v8rFY9i.png)
The behavior was clearly visible in command-line arguments.
Unlike LSASS detection, where the behavioral abstraction (`SENSITIVE_PROCESS_ACCESS`) was the anchor, shadow copy deletion is most directly observable through command-line semantics.
This created a different detection design problem.

## Detection Design Decision

There were two possible approaches:

I. Detect command-line pattern (`delete shadows`)
   
II. Detect process invocation of `vssadmin.exe`

Option II alone is insufficient. `vssadmin.exe` can be used legitimately to list shadow copies.
The malicious intent appears in the arguments:

```
delete shadows /all
```

Therefore, the detection was anchored to command-line behavior rather than process name alone.
Instead of only alerting, I chose to implement an active response.

The response block included:

```
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - routing/parent
```

![Image](https://imgur.com/Cjq9dBC.png)

This configuration does two things:
1. Generates an alert.    
2. Terminates the parent process responsible for the deletion command.

The use of `deny_tree` ensures the entire process tree is terminated, not just the leaf process.

## Why Active Termination Was Appropriate Here

This differs from the LSASS detection strategy.
LSASS access can be legitimate in certain enterprise contexts.
Shadow copy deletion is far less common in routine operations, especially with `/all` flag.
Terminating the parent process in this scenario is operationally safer because:
- Legitimate use frequency is low.
- The command is high-confidence malicious precursor behavior.    
- Early interruption can prevent encryption stage.

This demonstrates differentiated response logic based on behavioral confidence.

## Validation

After saving the rule, I re-executed:

```
vssadmin delete shadows /all
```

The command appeared to run, but the shell behavior changed immediately.
When I attempted to execute `whoami` afterward, the shell became unresponsive. This confirmed that the parent process had been terminated by the D&R engine.
Simultaneously, the detection appeared in the Detections tab.

![Image](https://imgur.com/a4Dhfxc.png)

This validated both detection and response logic.

## Behavioral Position in the Attack Chain

Within the broader simulated attack lifecycle:

1. Initial execution

2. C2 establishment

3. Credential dumping (LSASS case study)    

4. Recovery inhibition (this case study)

Shadow copy deletion represents preparation for destructive action.
From a SOC perspective, this is a pivot point. Once this behavior appears, response urgency increases significantly.

## Telemetry Semantics Considerations

This detection relies on command-line visibility.

Limitations include:
- If an attacker invokes shadow copy deletion via alternate APIs without `vssadmin`, this rule may not fire.
- If command-line logging is suppressed or altered, visibility is reduced.
- If PowerShell or WMI methods are used instead, detection logic must expand.

The rule is effective for common tradecraft but not exhaustive.
This reinforces the importance of layered detection.

## MITRE ATT&CK Mapping

Shadow copy deletion directly maps to **Inhibit System Recovery** under the Impact tactic of the **MITRE ATT&CK** Enterprise Matrix.

T1490 captures adversary behavior intended to prevent restoration of systems to a known-good state. The invocation:

```
vssadmin delete shadows /all
```

satisfies the technique definition because it removes Volume Shadow Copies required for file recovery.

Unlike credential access techniques, which increase attacker capability, recovery inhibition reduces defender resilience. This distinction materially changes response thresholds. When T1490 is observed following C2 establishment or privilege escalation, it represents a pivot from expansion to destructive preparation.

In ransomware operations, this technique frequently precedes **T1486 – Data Encrypted for Impact**, forming part of the pre-encryption staging sequence.

## False Positive Modeling & Operational Baseline Considerations

Although shadow copy deletion is high-confidence malicious behavior in most enterprise environments, false positive analysis is still required.

Legitimate scenarios where `vssadmin delete shadows` may appear include:
- Backup software lifecycle management
- Storage maintenance operations
- Manual administrator cleanup
- Virtual machine snapshot pruning

However, several contextual factors reduce legitimate likelihood:

1. Use of the `/all` flag, which removes all shadow copies indiscriminately 
   
2. Execution from interactive shells rather than service accounts 
   
3. Execution outside defined maintenance windows
   
4. Parent process lineage originating from user sessions or remote C2

In a production environment, baseline modeling would include:
- Frequency analysis of shadow deletion events per host class
- Identification of authorized backup service accounts
- Scheduled task correlation
- Maintenance window whitelisting

Detection confidence increases significantly when:
- The parent process is a command shell spawned from suspicious ancestry
- The user context is not a designated backup operator
- The event occurs shortly after C2 establishment or credential access

In the lab environment, no legitimate shadow copy operations were present, so empirical false positive testing was not possible. In enterprise deployment, this rule would require controlled rollout with telemetry observation before enabling automated termination.

## Operational Risk of False Termination

Automated termination using `deny_tree` introduces operational risk and must be evaluated against legitimate edge cases.
### Scenario I: Backup Software Execution

Certain backup platforms may delete shadow copies during lifecycle management or snapshot rotation.

Risk factors:
- Execution under service account
- Scheduled task context
- Execution within maintenance window

Mitigation approach in production:
- Allowlist known backup service accounts
- Restrict automated termination to interactive or anomalous parent lineage
- Correlate with maintenance schedule metadata
### Scenario II: SCCM or Administrative Maintenance

System administrators may manually clear shadow copies during storage remediation or troubleshooting.

Indicators of legitimacy:
- Known administrative jump host
- Authenticated domain admin
- Change ticket correlation    
- Maintenance window alignment

Blind termination in such cases could:
- Interrupt administrative workflows
- Cause operational disruption
- Trigger unnecessary incident escalation
### Blast Radius of "`deny_tree`"

`deny_tree` terminates the full parent process tree.  
In a C2-driven intrusion, this is desirable. However, if the parent process is:
- A legitimate remote management agent
- A backup orchestration process
- A systems management platform

then termination could:
- Disrupt enterprise management tooling
- Trigger failover behaviors
- Cause cascading operational side effects    

therefore, in production environments automated termination should be conditional on:
- Suspicious parent ancestry
- User context anomalies
- Absence of maintenance window markers
- Correlation with other impact-stage behaviors

In the controlled lab, these risks were absent. In enterprise deployment, containment logic must be gated by contextual validation.

## Evasion Considerations and Detection Hardening

The implemented detection relies on command-line visibility of:
```
vssadmin delete shadows /all
```

This approach captures common ransomware tradecraft but is not exhaustive.

A plausible evasion strategy includes:
- Using PowerShell to invoke WMI for shadow deletion:
```
Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete(); }
```
- Leveraging `wmic shadowcopy delete`
- Direct API calls bypassing `vssadmin.exe`
- Obfuscating command-line arguments

These variants would evade a detection rule anchored strictly to `vssadmin` command-line semantics.

To harden detection, the following adjustments would be required:

1. Monitor invocation of:
- `wmic.exe shadowcopy`
- PowerShell modules interacting with `Win32_ShadowCopy`
2. Detect high-volume shadow deletion events regardless of parent process  
   
3. Correlate shadow deletion with:
- Rapid file modification spikes
- Known ransomware process signatures    
- Recent credential access behavior
    
A production-grade implementation would therefore shift from single-command detection to behavioral clustering around recovery inhibition patterns. The lab rule successfully demonstrates interruption capability against common tradecraft, but layered detection is necessary for resilient enterprise deployment.

## Limitations

- Lab environment had no legitimate shadow copy management activity.
- No enterprise baseline for false positive comparison.
- No evasion attempts performed (e.g., PowerShell-based deletion).    
- No encryption stage simulated.

This case study validates interruption capability, not full ransomware containment strategy.

## Conclusion

This case study demonstrates detection and interruption of ransomware recovery inhibition behavior through command-line analysis and process tree termination.

Unlike credential access detection scenarios (the other project), shadow copy deletion represents destructive preparation rather than capability expansion. The behavioral confidence is materially higher, and the operational risk is immediate. This distinction justifies automated containment in environments where false positive likelihood is low.

The implemented rule successfully:
- Identified `vssadmin delete shadows /all` as recovery inhibition behavior
- Generated structured alert telemetry
- Terminated the responsible process tree

However, production-grade deployment would require:
- Expanded coverage for WMI and PowerShell-based deletion
- Baseline validation against legitimate maintenance workflows
- Correlation with adjacent impact-stage behaviors

Shadow copy deletion is a pivot point in ransomware operations. Once observed, defender response urgency must shift accordingly. The primary engineering challenge is not recognizing the command, it is determining when destructive intent is sufficiently clear to justify active containment.