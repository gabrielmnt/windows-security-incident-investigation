# Evidence

This document provides a reference to the screenshots and telemetry used to support the incident investigation.

## Evidence 01 – Failed Authentication Attempts

**Evidence Sources**

- Windows Security Event ID 4625 – Failed Logon

**Description**

Five failed authentication attempts associated with `vboxuser` were identified on the `SOC-WIN10` endpoint. The events originated from the local address `127.0.0.1` and used Logon Type 2, indicating interactive logon attempts. The recorded failure reason was `Unknown user name or bad password`.

The five attempts occurred within a short time window on October 7, 2026, between 18:31:12.896 and 18:31:24.437.

### Screenshot

**File:** `screenshots/25-failed-authentication-analysis.png`

The screenshot shows the five failed authentication attempts, including their timestamps, source address, Logon Type, and failure reason.

---

## Evidence 02 – Local Account Creation

**Evidence Sources**

- Windows Security Event ID 4720 – User Account Created
- Sysmon Event ID 1 – Process Creation

**Description**

The investigation identified the creation of a local account named `helpdesk` on October 7, 2026, at 18:40:10.650.

Windows Security Event ID 4720 confirmed that the account was created under the `vboxuser` security context. Sysmon process creation telemetry independently showed the execution of the Windows `net user` command used to create the account.

The correlation between the Sysmon process creation event and the Windows Security event supports the conclusion that the account was created through the observed command.

### Sysmon Process Creation

**File:** `screenshots/21-helpdesk-account-creation.png`

The screenshot shows the execution of the `net user` command used to create the `helpdesk` account. Any password or credential visible in the command line should be redacted before publishing the screenshot.

### Windows Security Event 4720

**File:** `screenshots/23-helpdesk-account-created.png`

The screenshot shows Windows Security Event ID 4720 confirming the creation of the `helpdesk` account.

---

## Evidence 03 – Privileged Account Assignment

**Evidence Sources**

- Windows Security Event ID 4732 – Security-Enabled Local Group Membership Change
- Sysmon Event ID 1 – Process Creation

**Description**

The investigation confirmed that the `helpdesk` account was added to the local `Administrators` group on October 7, 2026, at 18:40:48.727.

Windows Security Event ID 4732 confirmed the group membership change. Sysmon process creation telemetry showed the execution of the `net localgroup Administrators helpdesk /add` command under the `SOC-WIN10\vboxuser` security context.

The same security identifier associated with the newly created `helpdesk` account was observed in the group membership event, allowing the account creation and privilege assignment activities to be correlated.

An earlier Event ID 4732, recorded at 18:40:10.670, showed the addition of the same account SID to the local `Users` group. This is distinct from the later addition to `Administrators`.

The assignment of administrative privileges significantly increases the security relevance of the incident because the newly created account was granted elevated local permissions.

### Sysmon Process Creation

**File:** `screenshots/22-helpdesk-admin-privilege.png`

The screenshot shows the execution of the `net localgroup Administrators helpdesk /add` command.

### Windows Security Event 4732

**File:** `screenshots/24-helpdesk-added-to-administrators.png`

The screenshot shows Windows Security Event ID 4732 confirming that the `helpdesk` account was added to the local `Administrators` group.

---

## Evidence 04 – Authentication Context and Account Usage

**Evidence Sources**

- Windows Security Event ID 4624 – Successful Logon
- Windows Security Event ID 4625 – Failed Logon
- Sysmon Event ID 1 – Process Creation

**Description**

Five failed logon events associated with `vboxuser` were observed between 18:31:12.896 and 18:31:24.437.

Two successful logon events associated with `vboxuser`, both using Logon Type 2, were recorded at 18:31:33.706. These events provide evidence of a successful interactive logon context in the investigated timeline.

Additional successful logon events involving the `SYSTEM` account and Logon Type 5 were recorded at 18:40:29.269 and 18:40:32.004. Logon Type 5 represents a service logon and does not establish an interactive logon by `vboxuser` or use of the `helpdesk` account.

No successful or failed authentication events associated with `helpdesk` were identified during the investigated period. No Sysmon process creation events running under the `helpdesk` account were identified either.

The available telemetry therefore provides no evidence that the newly created privileged account was used to log on or execute processes during the investigated period. This limits the observed scope of the incident but does not eliminate the security significance of the account creation and privilege assignment activity.

---

## Evidence Correlation

The incident was not determined from a single log source. Windows Security auditing provided evidence of failed logons, successful logons, account creation, and group membership changes. Sysmon provided process execution telemetry showing which commands were executed and under which user context.

The correlation between these telemetry sources supports the reconstruction of the incident timeline and increases confidence in the findings. It also demonstrates how multiple log sources can be used together during a SOC investigation.

The investigation established the creation of the `helpdesk` account and its subsequent addition to the local `Administrators` group. However, the available evidence did not establish that the `helpdesk` account was subsequently used to authenticate or execute processes during the investigated period.