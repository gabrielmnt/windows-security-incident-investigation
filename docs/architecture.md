# Architecture

## Overview

This project reuses the Windows and Splunk monitoring infrastructure developed in the previous SOC Monitoring Lab.

Instead of building a new monitoring environment, the project focuses on simulating a security incident and investigating the resulting telemetry.

The architecture consists of a Windows 10 virtual machine monitored by Sysmon and the Splunk Universal Forwarder. The collected events are forwarded to a Splunk Enterprise instance running on the host machine.

The incident investigation is performed using Windows Security events and Sysmon process creation telemetry.

## Architecture Flow

```text
SOC-WIN10
    |
    +--> Windows Security Events
    |
    +--> Sysmon
            |
            v
    Splunk Universal Forwarder
            |
            | TCP 9997
            v
    Splunk Enterprise
            |
            v
        index=main
            |
            +--> Windows Security Events
            |
            +--> Sysmon Telemetry
            |
            v
    SPL Investigation
            |
            v
    Incident Analysis
```

## Main Components

### SOC-WIN10

Windows 10 virtual machine used as the monitored endpoint.

The simulated incident was intentionally generated on this system to produce realistic security telemetry.

### Sysmon

Sysmon was used to collect detailed endpoint telemetry, particularly process creation events.

Sysmon Event ID 1 was used to identify commands executed during the incident, including the Windows `net.exe` and `net1.exe` processes responsible for account management actions.

### Windows Security Auditing

Windows Security events provided independent evidence of authentication and account management activity.

The investigation primarily used:

* Event ID 4624 – Successful Logon
* Event ID 4625 – Failed Logon
* Event ID 4720 – User Account Created
* Event ID 4732 – Member Added to Security-Enabled Local Group

### Splunk Enterprise

Splunk Enterprise was used as the SIEM platform for centralized log ingestion, search, correlation and investigation.

The collected events were stored in the `main` index and investigated using SPL queries.

## Investigation Approach

The investigation combined multiple telemetry sources instead of relying on a single event.

Windows Security events were used to confirm authentication and account management actions, while Sysmon was used to identify the processes and commands that generated those actions.

This approach allows the analyst to correlate an observed system change with the process responsible for performing it.
