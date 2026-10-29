# Incident Scenario

## Overview

This document defines a simulated security incident investigated using the Windows/Splunk SOC Monitoring Lab.

The scenario focuses on a sequence of failed authentication attempts, followed by the creation of a local user account and its addition to the local Administrators group.

## Initial Alert

| Field | Details |
|---|---|
| Alert Name | Suspicious Local Account Creation and Privilege Assignment |
| Priority | Medium |
| Affected Host | `SOC-WIN10` |
| Date | October 7, 2026 |
| Environment | Controlled Windows 10 lab |
| Status | Investigation completed |

## Investigation Objectives

The investigation aims to determine:

- Whether the authentication failures are relevant to the subsequent account-management activity.
- Which user performed the account creation and group-membership changes.
- Whether the new account received administrative privileges.
- Whether there is evidence of subsequent authentication or process execution under the new account.
- What conclusions can be supported by the available logs.

## Scope and Data Sources

The investigation is limited to events collected from the lab endpoint during the simulated activity.

Relevant data sources include:

- Windows Security logs: Event IDs `4624`, `4625`, `4720`, and `4732`.
- Sysmon Operational logs: Event ID `1` for process creation.

## Investigation Approach

Correlate authentication events, account-management events, group-membership changes, and process-creation records in Splunk. Document the supporting evidence, identify limitations, and avoid attributing malicious intent without sufficient evidence.

**Note:** This scenario is a controlled lab simulation and does not represent a confirmed real-world security incident.

See `Evidence.md` for supporting evidence, `Timeline.md` for the event chronology, and `incident-report.md` for the investigation findings and conclusions.