# MITRE ATT&CK Mapping

## Overview

The observed activity was mapped to the MITRE ATT&CK framework based on behaviors directly supported by the collected telemetry.

Only techniques with sufficient evidence were included.

The purpose of this mapping is to demonstrate how observed endpoint activity can be translated into adversary behavior using a standardized threat-informed framework.

## Technique Mapping

| Technique ID | Technique                        | Observed Behavior                                                                  | Evidence Source                                      |
| ------------ | -------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------- |
| T1136.001    | Create Account: Local Account    | A local account named `helpdesk` was created using the Windows `net user` command. | Sysmon Event ID 1 and Windows Security Event ID 4720 |
| T1098        | Account Manipulation             | The `helpdesk` account was added to the local `Administrators` group.              | Sysmon Event ID 1 and Windows Security Event ID 4732 |
| T1087.001    | Account Discovery: Local Account | The `helpdesk` account was queried using the Windows `net user` command.           | Sysmon Event ID 1                                    |

## T1136.001 — Create Account: Local Account

### Observed Behavior

A new local account named `helpdesk` was created on the `SOC-WIN10` endpoint.

Sysmon process creation telemetry recorded the execution of:

```text
net user helpdesk <password> /add
```

Windows Security Event ID 4720 independently confirmed the creation of the account.

### Mapping Rationale

The observed behavior directly matches the creation of a local account and is therefore mapped to T1136.001.

---

## T1098 — Account Manipulation

### Observed Behavior

The `helpdesk` account was added to the local `Administrators` group.

Sysmon recorded the execution of:

```text
net localgroup Administrators helpdesk /add
```

Windows Security Event ID 4732 independently confirmed the group membership change.

### Mapping Rationale

The addition of the account to the `Administrators` group modified its effective privileges.

This behavior is mapped to T1098 because the account's access was modified through group membership.

---

## T1087.001 — Account Discovery: Local Account

### Observed Behavior

The newly created `helpdesk` account was queried using:

```text
net user helpdesk
```

### Mapping Rationale

The command was used to retrieve information about a local account.

The behavior is therefore mapped to T1087.001 as local account discovery.

This mapping is intentionally limited to the observed account query and does not imply broader account enumeration.

## Mapping Considerations

The failed authentication attempts were not mapped to a specific ATT&CK credential access technique because the available telemetry does not establish the mechanism or intent behind those attempts.

Similarly, broader discovery techniques such as System Owner/User Discovery, System Information Discovery and System Network Configuration Discovery were not included because sufficient evidence for those behaviors was not established in the final investigation dataset.

The mapping intentionally focuses on observed behavior rather than assuming techniques that were not directly supported by the available telemetry.
