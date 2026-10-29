# Incident Assessment

## Incident Summary

A suspicious sequence of local authentication and account management activity was identified on the Windows endpoint `SOC-WIN10`.

The investigation identified multiple failed authentication attempts followed shortly by the creation of a local account named `helpdesk` and the addition of that account to the local `Administrators` group.

The account management actions were performed under the `vboxuser` security context and were observed through both Sysmon process telemetry and Windows Security auditing events.

## Key Findings

The investigation identified the following confirmed behaviors:

- Multiple failed authentication attempts were observed from the local host address `127.0.0.1`.
- The `helpdesk` local account was created using the Windows `net user` command.
- Windows Security Event ID 4720 confirmed the creation of the account.
- The `helpdesk` account was added to the local `Administrators` group.
- Windows Security Event ID 4732 confirmed the group membership change.
- The account management commands were executed under the `SOC-WIN10\vboxuser` user context.
- No successful or failed authentication events involving the `helpdesk` account were identified after its creation.
- No Sysmon process creation events were identified under the `helpdesk` user context.

## Impact Assessment

The creation of a local account followed by its addition to the local Administrators group represents a significant security risk because the resulting account would have administrative privileges on the endpoint.

However, the available telemetry does not show that the `helpdesk` account was subsequently used to authenticate, execute processes, or perform additional actions.

Therefore, the investigation confirms the creation of a privileged account but does not establish subsequent exploitation or malicious use of that account.

## Severity Assessment

Within the context of this simulated laboratory environment, the incident is assessed as **High** severity.

The assessment is based primarily on the creation of a local account followed by the assignment of administrative privileges.

The absence of evidence showing subsequent use of the account limits the observed impact but does not eliminate the security significance of the activity.

## Confidence

**High confidence:**

- The `helpdesk` account was created.
- The account was added to the local `Administrators` group.
- The actions were executed under the `vboxuser` context.
- The relevant Windows Security events confirm the account management actions.
- Sysmon telemetry independently shows the commands responsible for the account management actions.

**Moderate confidence:**

* The failed authentication activity was suspicious and occurred shortly before the account creation.

**Low confidence / Not established:**

- A direct relationship between the failed authentication attempts and the account creation.
- Malicious intent behind the observed activity.
- Malicious use of the `helpdesk` account.
- Successful authentication using the newly created account.
- Execution of processes under the `helpdesk` account.

## Investigation Limitations

The investigation was performed using the telemetry available in the simulated environment.

The available logs did not provide sufficient evidence to establish which process was responsible for the failed authentication attempts.

The investigation also did not identify subsequent authentication or process execution using the newly created `helpdesk` account.

The failed authentication attempts and subsequent account creation therefore cannot be conclusively attributed to the same activity based on the available telemetry alone.

The conclusions are limited to the behaviors directly supported by the collected evidence.
