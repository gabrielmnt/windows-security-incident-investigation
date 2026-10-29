# Windows SOC Lab: Incident Investigation with Splunk

## Overview

This project demonstrates a small Security Operations Center (SOC) lab built to collect, monitor, and investigate Windows endpoint telemetry using Splunk Enterprise, Splunk Universal Forwarder, and Sysmon.

The project includes a simulated security incident involving failed authentication attempts, local account creation, and administrative privilege assignment. Windows Security logs and Sysmon process creation events were analyzed to reconstruct the sequence of activity, correlate evidence from different sources, and document the investigation findings.

The environment was built for learning and portfolio purposes. All incident activity was generated in a controlled lab environment.

## Objectives

- Build a Windows endpoint monitoring environment using Splunk.
- Collect Windows Security, System, Application, and Sysmon telemetry.
- Forward endpoint logs to Splunk Enterprise for centralized analysis.
- Investigate authentication and local account management activity.
- Correlate Windows Security events with Sysmon process execution telemetry.
- Develop searches and investigation workflows using Splunk Search Processing Language (SPL).
- Document findings, evidence, timeline, and investigation limitations.
- Map relevant observed behaviors to MITRE ATT&CK.

## Lab Architecture

The lab uses a Windows host running Splunk Enterprise and a Windows virtual machine monitored by Sysmon and Splunk Universal Forwarder.

```text
+--------------------------------+
|        Windows Host            |
|                                |
|        Splunk Enterprise       |
|        Search & Analysis       |
|        Index: main             |
+---------------^----------------+
                |
                | TCP 9997
                |
+---------------+----------------+
|        Windows 10 VM           |
|        Hostname: SOC-WIN10     |
|                                |
|        Windows Event Logs      |
|        Sysmon                  |
|        Splunk Universal        |
|        Forwarder               |
+--------------------------------+
```

### Components

| Component | Purpose |
|---|---|
| Windows 10 host | Runs Splunk Enterprise and provides the central analysis environment. |
| Windows 10 virtual machine (`SOC-WIN10`) | Generates endpoint and security telemetry. |
| Splunk Enterprise | Receives, indexes, searches, and correlates collected events. |
| Splunk Universal Forwarder | Forwards Windows event data from the monitored endpoint to Splunk Enterprise. |
| Sysmon | Provides detailed system activity telemetry, including process creation events. |
| Windows Security auditing | Records authentication, account creation, and local group membership changes. |

The Universal Forwarder sends collected events to Splunk Enterprise over TCP port `9997`. The investigation uses the `main` index.

## Data Sources

The lab collects and analyzes the following telemetry:

- **Windows Security logs:** authentication events, local account creation, and security-enabled local group membership changes.
- **Sysmon Operational logs:** process creation and command-line evidence.
- **Windows System and Application logs:** additional operating system and application activity available for investigation.

### Relevant Windows Event IDs

| Event ID | Description | Investigative Use |
|---|---|---|
| 4624 | Successful logon | Identify successful authentication and logon type. |
| 4625 | Failed logon | Investigate failed authentication attempts. |
| 4720 | User account created | Confirm local account creation. |
| 4732 | Member added to a security-enabled local group | Investigate local group membership changes. |
| Sysmon Event ID 1 | Process creation | Examine executed processes, command lines, and user context. |

Event interpretation depends on the full event context, including account fields, logon type, process information, and event message. An event should not be interpreted in isolation when additional context is available.

## Simulated Incident

### Scenario

The incident simulation focused on suspicious local account management activity on the `SOC-WIN10` endpoint.

The investigation examined a sequence of failed authentication attempts followed by the creation of a local account named `helpdesk` and its subsequent addition to the local `Administrators` group.

The objective was to determine what happened, correlate the available telemetry, assess the observed security impact, and establish whether there was evidence of subsequent use of the privileged account.

### Key Findings

- Five selected failed authentication attempts were observed between `18:31:12.896` and `18:31:24.437` on October 7, 2026.
- The failed attempts originated from `127.0.0.1` and used Logon Type 2 (`Interactive`). The recorded failure reason was `Unknown user name or bad password`.
- Two successful interactive logon events associated with `vboxuser` were recorded at `18:31:33.706`.
- At `18:40:10.650`, Windows Security Event ID 4720 confirmed the creation of the local `helpdesk` account under the `vboxuser` security context.
- At `18:40:10.670`, Event ID 4732 recorded the addition of the account to the local `Users` group.
- At `18:40:48.727`, Event ID 4732 confirmed the addition of the same account to the local `Administrators` group.
- Sysmon process creation telemetry provided complementary evidence of the account management commands executed under the `SOC-WIN10\vboxuser` context.
- Two Logon Type 5 events associated with `SYSTEM` were observed at `18:40:29.269` and `18:40:32.004`. These service logon events did not establish interactive use of the `helpdesk` account.
- No successful or failed authentication events involving `helpdesk`, or Sysmon process creation events under that account's user context, were identified during the investigated period.

All times above refer to the local timestamps recorded for the lab events on October 7, 2026.

### Investigation Outcome

The investigation confirmed that a local account was created and subsequently granted administrative privileges.

The failed authentication attempts preceded the account management activity, but the available telemetry did not establish a direct causal relationship between them. The process responsible for initiating the failed attempts and the intent behind them remained undetermined.

The investigation found no evidence of subsequent use of the `helpdesk` account within the collected telemetry and investigated period. This does not prove that activity outside the investigation scope did not occur.

The incident was a controlled simulation, not a confirmed real-world compromise.

## MITRE ATT&CK Mapping

The following techniques correspond to the account management behaviors documented in the investigation.

| Technique ID | Technique | Observed Behavior |
|---|---|---|
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Creation of the local `helpdesk` account, supported by Windows Security Event ID 4720 and Sysmon process execution telemetry. |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Addition of `helpdesk` to the local `Administrators` group, supported by Windows Security Event ID 4732 and Sysmon process execution telemetry. |

These mappings describe behaviors observed in the simulation. They do not independently establish malicious intent.

## Investigation Workflow

The investigation followed a structured workflow:

1. **Review authentication activity:** Search for Windows Security Event IDs 4624 and 4625 and examine the associated account context, source address, and logon type.
2. **Identify account management events:** Search for Event IDs 4720 and 4732 to identify local account creation and group membership changes.
3. **Analyze process execution:** Review Sysmon Event ID 1 events for the commands associated with account management activity.
4. **Correlate evidence:** Compare timestamps, account identifiers, user contexts, and event details across Windows Security and Sysmon telemetry.
5. **Build the timeline:** Arrange relevant events chronologically to reconstruct the observed sequence.
6. **Check for subsequent activity:** Search for authentication and process creation events involving the newly created account.
7. **Document the outcome:** Record confirmed findings, potential security impact, investigation limitations, and ATT&CK mappings.

## Tools and Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Splunk Processing Language (SPL)
- Windows 10
- Windows Security Event Logs
- Sysmon
- Oracle VirtualBox
- MITRE ATT&CK

## Skills Demonstrated

- Windows endpoint log collection and monitoring
- SIEM searches and event analysis
- Authentication event investigation
- Windows local account and group membership analysis
- Process execution and command-line investigation
- Correlation of Windows Security and Sysmon telemetry
- Timeline reconstruction
- Incident documentation and evidence handling
- MITRE ATT&CK behavior mapping
- Recognition of investigation limitations and evidentiary uncertainty

## Scope and Limitations

This project was conducted in a controlled virtual lab using a limited set of endpoint telemetry sources.

The conclusions are restricted to the events collected by the lab and reviewed during the investigation. The available data did not identify the process responsible for the failed authentication attempts or establish a direct relationship between those attempts and the subsequent account management actions.

The absence of matching authentication or process creation events involving `helpdesk` should be interpreted as a lack of observed evidence within the investigated scope, not proof that no activity occurred elsewhere or outside the collection period.

The project demonstrates a basic endpoint investigation workflow. It does not represent a production SOC deployment or a comprehensive enterprise detection and response capability.

## Repository Contents

The repository contains the lab documentation, investigation notes, queries, and evidence used to support the project.

Refer to the files and directories in the repository for the specific setup instructions, detection searches, event analysis, and incident evidence. Screenshots are intended to support the documented findings and should be reviewed for sensitive host, account, network, and credential information before publication.

## Disclaimer

This project is intended exclusively for educational purposes and cybersecurity portfolio demonstration.

All simulated incident activity was performed in a controlled lab environment. The project does not claim that a real-world compromise occurred, and its conclusions are limited to the evidence collected and analyzed.

