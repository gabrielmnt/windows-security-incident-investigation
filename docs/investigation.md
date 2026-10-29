# Investigation

This document records the investigation process performed during the analysis of the simulated security incident.

The investigation follows an evidence-driven approach. Each step addresses a specific question and uses the available telemetry to determine the next investigation action.

## Investigation Objective

The objective of this investigation was to determine whether the observed authentication and account management activity on the `SOC-WIN10` endpoint represented suspicious behavior.

The investigation focused on:

- Failed authentication attempts.
- Local account creation.
- Privileged group membership changes.
- Process execution associated with the account management actions.
- Subsequent use of the newly created account.

---

## Step 1 — Authentication Analysis

### Investigation Question

Were multiple failed authentication attempts recorded on the monitored endpoint?

### Investigation Rationale

Repeated authentication failures can indicate incorrect credentials, automated activity, or other suspicious authentication behavior.

The first step was therefore to identify the failed authentication events and establish their timing and context.

### SPL Query

```
index=main host="SOC-WIN10" EventCode=4625
| rex field=Message "Account Name:\s+(?<FailedAccount>\S+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>\S+)"
| rex field=Message "Logon Type:\s+(?<ParsedLogonType>\d+)"
| rex field=Message "Failure Reason:\s+(?<ParsedFailureReason>.+)"
| table _time FailedAccount SourceIP ParsedLogonType ParsedFailureReason
| sort _time
```

### Findings

The final investigation identified `<NUMBER>` failed authentication attempts between `<FIRST_FAILED_TIMESTAMP>` and `<LAST_FAILED_TIMESTAMP>`.

The events originated from `<SOURCE_IP>` and used Logon Type `<LOGON_TYPE>`.

The recorded failure reason was:

`<FAILURE_REASON>`

The available telemetry did not establish which process initiated these authentication attempts.

The activity was therefore treated as suspicious authentication activity, but not as confirmed malicious behavior.

---

## Step 2 — Process Activity Analysis

### Investigation Question

Which processes were executed during the investigation period?

### Investigation Rationale

Sysmon process creation events provide visibility into commands executed on the endpoint.

Because Sysmon events were stored as XML in the `_raw` field, the relevant fields were extracted using `rex`.

### SPL Query

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| where EventID="1"
| table _time Image CommandLine User ParentImage
| sort _time
```

### Findings

The process creation data was used to identify the commands associated with the account management activity.

The investigation identified the execution of Windows account management commands involving the `helpdesk` account.

No sufficient evidence was found in the final telemetry to establish a broader reconnaissance phase involving commands that were not directly confirmed by the collected evidence.

---

## Step 3 — Local Account Creation

### Investigation Question

Was a new local account created on the endpoint?

### Investigation Rationale

Windows Security Event ID 4720 records the creation of a user account.

Sysmon process creation telemetry can then be correlated with the Security event to identify the command responsible for the change.

### SPL Query

```
index=main host="SOC-WIN10" EventCode=4720
| rex field=Message "New Account:\s+Security ID:\s+.*?\s+Account Name:\s+(?<CreatedUser>\S+)"
| table _time host Account_Name CreatedUser Message
| sort _time
```

### Findings

At `<ACCOUNT_CREATION_TIMESTAMP>`, Windows Security Event ID 4720 confirmed the creation of the local `helpdesk` account.

Sysmon process creation telemetry showed the execution of:

`net user helpdesk <password> /add`

The activity was executed under the `SOC-WIN10\vboxuser` security context.

The correlation between the process execution and the Security event confirmed both the action and the account that was created.

---

## Step 4 — Privilege Assignment

### Investigation Question

Was the newly created account granted elevated privileges?

### Investigation Rationale

Creating a local account becomes significantly more relevant when that account is added to a privileged group.

Windows Security Event ID 4732 records membership changes involving security-enabled local groups.

### SPL Query

```
index=main host="SOC-WIN10" EventCode=4732
| table _time host Account_Name Message
| sort _time
```

### Sysmon Correlation

The following query was used to identify the process responsible for the privilege assignment:

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventID="1" AND like(CommandLine,"%Administrators%") AND like(CommandLine,"%helpdesk%")
| table _time CommandLine User
| sort _time
```

### Findings

At `<PRIVILEGE_ASSIGNMENT_TIMESTAMP>`, Sysmon recorded the execution of:

`net localgroup Administrators helpdesk /add`

Windows Security Event ID 4732 independently confirmed that the `helpdesk` account was added to the local `Administrators` group.

The same security identifier associated with the newly created `helpdesk` account was observed in the group membership event, allowing the account creation and privilege assignment activities to be correlated.

The evidence confirms that the newly created account was granted administrative privileges.

---

## Step 5 — Investigation of Privileged Account Usage

### Investigation Question

Was the newly created privileged account used after it was created?

### Investigation Rationale

After confirming the creation and privilege assignment of the `helpdesk` account, the investigation was extended to determine whether the account was subsequently used for authentication or process execution.

### Successful Logon Search

```
index=main EventCode=4624
| search Account_Name="helpdesk"
| table _time host Account_Name Logon_Type Authentication_Package Source_Network_Address
| sort _time
```

### Failed Logon Search

```
index=main EventCode=4625
| search Account_Name="helpdesk"
| table _time host Account_Name Logon_Type Authentication_Package Source_Network_Address Failure_Reason
| sort _time
```

### Process Activity Search

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventID="1" AND User="SOC-WIN10\helpdesk"
| table _time Image CommandLine User
| sort _time
```

### Findings

No successful logon events associated with the `helpdesk` account were identified during the investigated period.

No failed logon events associated with the account were identified either.

The Sysmon process creation search also returned no process execution events performed under the `helpdesk` account.

Based on the available telemetry, there is no evidence that the newly created privileged account was subsequently used for authentication or process execution.

However, the account creation and subsequent assignment to the local `Administrators` group remain significant security events.

---

## Investigation Conclusion

The investigation confirmed that a local account named `helpdesk` was created on the `SOC-WIN10` endpoint and subsequently added to the local `Administrators` group.

The account management actions were independently supported by Windows Security events and Sysmon process creation telemetry.

The investigation did not identify subsequent authentication or process execution under the `helpdesk` account.

The failed authentication activity remains suspicious, but the available telemetry does not establish a direct relationship between those events and the subsequent account creation.
