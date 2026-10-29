# Timeline

This document reconstructs the relevant authentication and account management activity observed on the `SOC-WIN10` endpoint on October 7, 2026, using Windows Security and Sysmon telemetry.

## Authentication Context

Five failed authentication events (Windows Security Event ID 4625) were recorded between 18:31:12.896 and 18:31:24.437. The events were associated with `vboxuser`, originated from the local address `127.0.0.1`, and used Logon Type 2 (`Interactive`). The recorded failure reason was `Unknown user name or bad password`.

Two successful interactive logon events (Event ID 4624) associated with `vboxuser` were also observed at 18:31:33.706.

The available telemetry does not establish which process initiated the failed authentication attempts or prove that they were directly related to the subsequent account creation. The attempts are therefore treated as suspicious authentication activity rather than confirmed malicious authentication.

## Incident Timeline

The following table presents the relevant events in chronological order. Timestamps include milliseconds where available.

| Time | Event | Source | Interpretation |
|---|---|---|---|
| 18:31:12.896 | Failed authentication attempt | Windows Security Event ID 4625 | An interactive authentication attempt associated with `vboxuser` failed. The source address was `127.0.0.1`. |
| 18:31:15.796 | Failed authentication attempt | Windows Security Event ID 4625 | A second failed authentication attempt was recorded under the same observed conditions. |
| 18:31:18.454 | Failed authentication attempt | Windows Security Event ID 4625 | A third failed authentication attempt was recorded under the same observed conditions. |
| 18:31:21.802 | Failed authentication attempt | Windows Security Event ID 4625 | A fourth failed authentication attempt was recorded under the same observed conditions. |
| 18:31:24.437 | Failed authentication attempt | Windows Security Event ID 4625 | A fifth failed authentication attempt was recorded under the same observed conditions. |
| 18:31:33.706 | Two successful interactive logon events associated with `vboxuser` | Windows Security Event ID 4624 | Two events with the same recorded timestamp were observed with Logon Type 2. |
| 18:40:10.650 | Local account `helpdesk` created | Windows Security Event ID 4720 | Windows Security auditing confirmed the creation of the account under the `vboxuser` security context. |
| 18:40:10.670 | `helpdesk` added to the local `Users` group | Windows Security Event ID 4732 | The account SID associated with `helpdesk` was added to the local `Users` group. |
| 18:40:29.269 | Successful service logon | Windows Security Event ID 4624 | A Logon Type 5 event associated with `SYSTEM` was recorded. |
| 18:40:32.004 | Successful service logon | Windows Security Event ID 4624 | A second Logon Type 5 event associated with `SYSTEM` was recorded. |
| 18:40:48.727 | `helpdesk` added to the local `Administrators` group | Windows Security Event ID 4732 | Windows Security auditing confirmed the addition of the account SID to the local `Administrators` group. |

Sysmon Event ID 1 provided complementary process execution evidence for the account management commands, including the `net user` command used to create `helpdesk` and the `net localgroup Administrators helpdesk /add` command used to assign administrative privileges.

## Timeline Analysis

The selected authentication sequence began with five failed interactive logon attempts associated with `vboxuser` between 18:31:12.896 and 18:31:24.437. Two successful interactive logon events associated with the same account were recorded at 18:31:33.706.

Approximately eight minutes and thirty-seven seconds after the final selected failed authentication attempt, Windows Security Event ID 4720 confirmed the creation of the local `helpdesk` account at 18:40:10.650.

Twenty milliseconds later, Event ID 4732 recorded the addition of the new account's SID to the local `Users` group. At 18:40:48.727, another Event ID 4732 recorded its addition to the local `Administrators` group.

The account creation and group membership changes are supported by Windows Security auditing. Sysmon process creation telemetry provides complementary evidence of the commands executed under the `SOC-WIN10\vboxuser` context.

Two successful Logon Type 5 events associated with `SYSTEM` were recorded at 18:40:29.269 and 18:40:32.004. These represent service logons and do not establish interactive authentication or process execution under the `helpdesk` account.

The temporal sequence establishes that the failed authentication activity preceded the account management actions. However, the available evidence does not establish a direct causal relationship between them.

The account was created and subsequently granted administrative privileges. No subsequent use of the privileged account was observed in the investigated telemetry.

## Post-Creation Account Activity

The `helpdesk` account was investigated for subsequent authentication and process execution activity during the investigated period.

No Windows Security Event ID 4624 or 4625 events associated with `helpdesk` were identified.

A search for Sysmon Event ID 1 process creation events under the `helpdesk` user context also returned no matching events.

Based on the available telemetry, there is no evidence that the newly created privileged account was subsequently used during the investigated period.

This distinction is important: the creation of `helpdesk` and its addition to the local `Administrators` group were confirmed, but subsequent use of the account was not observed. These findings are limited to the collected telemetry and do not prove that activity outside the investigation scope did not occur.