## Incident Title

Suspicious Local Account Creation and Privilege Assignment

## Incident ID

INC-001

## Severity

High — Simulated Environment

## Status

Closed - Investigation Completed

## Affected Host

`SOC-WIN10`

## Primary User Context

`SOC-WIN10\vboxuser`

## Incident Date

October 7, 2026

## Executive Summary

A suspicious sequence of authentication and local account management activity was identified on the Windows endpoint `SOC-WIN10`.

The investigation identified five failed authentication attempts originating from the local host, followed by two successful interactive logon events associated with `vboxuser`. At 18:40:10.650, a local account named `helpdesk` was created under the `vboxuser` security context.

The newly created account was subsequently added to the local `Users` group at 18:40:10.670 and to the local `Administrators` group at 18:40:48.727, granting it administrative privileges on the endpoint.

The account creation and group membership changes were supported by Windows Security auditing events. Sysmon Event ID 1 provided complementary process execution evidence for the account management commands.

Two additional successful logon events associated with `SYSTEM` and Logon Type 5 were observed at 18:40:29.269 and 18:40:32.004. These are service logon events and do not establish interactive use of the `helpdesk` account.

No successful or failed authentication events involving `helpdesk` were identified during the investigated period. No Sysmon process creation events under the `helpdesk` user context were identified either.

The investigation confirms the creation of a local privileged account but does not establish subsequent use of that account or prove that the preceding failed authentication attempts were directly related to the account management activity.

## Incident Timeline

The relevant activity occurred on October 7, 2026, in the following sequence. Timestamps include milliseconds where available.

| Time | Event |
|---|---|
| 18:31:12.896 | Failed authentication attempt associated with `vboxuser`, originating from `127.0.0.1`, Logon Type 2. |
| 18:31:15.796 | Second failed authentication attempt under the same observed conditions. |
| 18:31:18.454 | Third failed authentication attempt under the same observed conditions. |
| 18:31:21.802 | Fourth failed authentication attempt under the same observed conditions. |
| 18:31:24.437 | Fifth failed authentication attempt under the same observed conditions. |
| 18:31:33.706 | Two successful interactive logon events associated with `vboxuser`, Logon Type 2. |
| 18:40:10.650 | Windows Security Event ID 4720 confirmed creation of the local `helpdesk` account by `vboxuser`. |
| 18:40:10.670 | Windows Security Event ID 4732 recorded the addition of the `helpdesk` account SID to the local `Users` group. |
| 18:40:29.269 | Successful service logon event associated with `SYSTEM`, Logon Type 5. |
| 18:40:32.004 | Another successful service logon event associated with `SYSTEM`, Logon Type 5. |
| 18:40:48.727 | Windows Security Event ID 4732 recorded the addition of the `helpdesk` account SID to the local `Administrators` group. |

## Technical Findings

### Authentication Activity

Five failed authentication attempts were identified between 18:31:12.896 and 18:31:24.437.

The events originated from the local address `127.0.0.1` and used Logon Type 2, indicating interactive logon attempts. The recorded failure reason was:

`Unknown user name or bad password.`

Two successful interactive logon events associated with `vboxuser` were also observed at 18:31:33.706.

The available telemetry does not establish which process initiated the failed authentication attempts or whether they were directly related to the subsequent account creation. Their proximity to the successful logon events provides context for the investigation but does not, by itself, prove a causal relationship.

Therefore, the failed authentication activity is considered suspicious in the context of the subsequent account management actions, but its intent remains unconfirmed.

### Local Account Creation

At 18:40:10.650, Windows Security Event ID 4720 confirmed the creation of a local account named `helpdesk` under the `vboxuser` security context.

Sysmon Event ID 1 provided process execution telemetry showing the Windows `net user` command used to create the account.

The correlation between the process execution evidence and the Windows Security event supports the conclusion that the account was created through the observed command.

### Group Membership and Privilege Assignment

At 18:40:10.670, Windows Security Event ID 4732 recorded the addition of the `helpdesk` account SID to the local `Users` group.

At 18:40:48.727, another Event ID 4732 recorded the addition of the same account SID to the local `Administrators` group.

Sysmon Event ID 1 also recorded execution of the following command under the `SOC-WIN10\vboxuser` context:

`net localgroup Administrators helpdesk /add`

These findings confirm that the newly created account was added to the local `Administrators` group and granted administrative privileges on the endpoint.

This activity increases the security significance of the incident because a newly created local account with administrative privileges could potentially be used to perform privileged operations.

### Post-Creation Activity

The investigation searched for subsequent authentication and process execution activity involving the `helpdesk` account.

No Windows Security Event ID 4624 or 4625 events associated with `helpdesk` were identified during the investigated period.

No Sysmon Event ID 1 process creation events under the `helpdesk` user context were identified either.

The two successful Logon Type 5 events associated with `SYSTEM` occurred at 18:40:29.269 and 18:40:32.004. These service logon events do not establish that `helpdesk` authenticated or executed processes.

Based on the available telemetry, the investigation found no evidence of subsequent use of the newly created privileged account during the investigated period. This conclusion is limited to the collected logs and the scope of the investigation.

## MITRE ATT&CK Mapping

| Technique ID | Technique | Evidence |
|---|---|---|
| T1136.001 | Create Account: Local Account | The `helpdesk` account was created using `net user`, supported by Sysmon Event ID 1 and Windows Security Event ID 4720. |
| T1098 | Account Manipulation | The `helpdesk` account was added to the local `Administrators` group, supported by Sysmon Event ID 1 and Windows Security Event ID 4732. |
| T1087.001 | Account Discovery: Local Account | The original investigation documented a query of the `helpdesk` account using Windows account management commands. |

The failed authentication attempts were not mapped to a specific ATT&CK credential access technique because the available telemetry does not establish the mechanism or intent behind those attempts.

The ATT&CK mappings describe behaviors observed or documented during the simulation. They do not independently establish malicious intent.

## Impact Assessment

The primary security impact was the creation of a local account with administrative privileges.

If unauthorized, such an account could potentially be used to maintain access to the endpoint, modify system configuration, interfere with security controls, create additional accounts, or execute privileged processes.

However, the available telemetry did not establish subsequent authentication or process execution under the `helpdesk` account, nor did it show evidence of these potential follow-on activities.

The observed impact is therefore limited to the confirmed account creation and privilege assignment. No further impact was established within the scope of the investigation.

## Root Cause Assessment

This was a controlled simulation in which local Windows account management commands were intentionally executed under the `vboxuser` context to reproduce a suspicious account creation and privilege escalation scenario.

The available telemetry confirms the account management actions but does not establish how the operator obtained access to the `vboxuser` session.

It also does not establish a direct relationship between the preceding failed authentication attempts and the subsequent account creation. Those events should therefore be treated as related investigative context rather than a confirmed cause.

## Investigation Limitations

The investigation was limited to telemetry collected from the `SOC-WIN10` endpoint and the events available in Splunk for the investigated period.

The available logs did not provide sufficient evidence to identify the process responsible for the failed authentication attempts or establish the operator's intent.

No evidence was found showing subsequent authentication or process execution under the `helpdesk` account. However, the absence of matching events in the collected telemetry does not prove that the account could not have been used outside the investigated period or through activity not captured by the available data sources.

The investigation therefore cannot determine whether the account would have been used for additional activity beyond the observed events.

## Conclusion

The investigation confirmed a suspicious local account management sequence on `SOC-WIN10` on October 7, 2026.

Five failed authentication attempts were observed, followed by two successful interactive logon events associated with `vboxuser`. The `vboxuser` context subsequently created the local `helpdesk` account and added it first to the `Users` group and then to the `Administrators` group.

The account creation and group membership changes were supported by Windows Security auditing events and complementary Sysmon process execution telemetry.

Although the creation of a privileged local account represents a significant security risk, no evidence was identified showing subsequent authentication or process execution under the `helpdesk` account during the investigated period. The preceding failed authentication attempts remain suspicious, but a direct relationship with the account management activity was not established.

The investigation is closed as a completed simulation. Its findings confirm the account creation and privilege assignment, while the intent behind the authentication activity and any use of the privileged account beyond the observed telemetry remain undetermined.