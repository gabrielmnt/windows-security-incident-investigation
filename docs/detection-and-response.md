# Detection and Response

## Detection Objective

The objective of this detection is to identify suspicious local account creation followed by privileged group membership assignment.

This behavior is relevant because attackers may create local accounts and assign administrative privileges to establish persistence or obtain elevated access on a Windows endpoint.

The detection combines Windows Security events with Sysmon process creation telemetry to identify both the resulting security changes and the commands responsible for them.

## Detection 1 — Local Account Creation

Windows Security Event ID 4720 can be used to identify the creation of a local user account.

### SPL Query

```spl
index=main host="SOC-WIN10" EventCode=4720
| rex field=Message "New Account:\s+Security ID:\s+.*?\s+Account Name:\s+(?<CreatedUser>\S+)"
| table _time host Account_Name CreatedUser Message
| sort _time
```

### Purpose

This query identifies account creation events and extracts the name of the newly created account from the Windows Security event message.

During the investigation, Event ID 4720 confirmed the creation of the `helpdesk` account.

## Detection 2 — Privileged Group Membership Change

Windows Security Event ID 4732 can be used to identify when a member is added to a security-enabled local group.

### SPL Query

```spl
index=main host="SOC-WIN10" EventCode=4732
| table _time host Account_Name Message
| sort _time
```

### Purpose

This query identifies local group membership changes that may result in privilege escalation.

During the investigation, Event ID 4732 confirmed that the `helpdesk` account was added to the local `Administrators` group.

## Sysmon Process Correlation

Windows Security events confirm that the account management actions occurred, but they do not necessarily show the exact command used to perform them.

Sysmon Event ID 1 provides process creation telemetry that can be correlated with the Security events.

For example, the following query searches for process creation events related to the `helpdesk` account:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventID="1" AND like(CommandLine,"%helpdesk%")
| table _time Image CommandLine User
| sort _time
```

This query revealed the execution of commands such as `net user helpdesk ... /add` and `net localgroup Administrators helpdesk /add`.

The investigation also showed that `net.exe` and `net1.exe` may appear as separate Sysmon process creation events for the same operation. These events represent the execution chain of the Windows command rather than two independent administrative actions.

## Incident Investigation Dashboard

A dedicated Splunk dashboard was created to support investigation of the simulated incident.

The dashboard provides a consolidated view of the main evidence identified during the investigation:

- Failed authentication attempts.
- Local account creation.
- Privileged group modification.
- Account management commands.

Unlike the general monitoring dashboard created in the previous project, this dashboard is focused on a specific security incident.

Its purpose is to help an analyst quickly correlate related events and understand the sequence of activity without manually reviewing large numbers of unrelated events.
