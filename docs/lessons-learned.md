# Lessons Learned

## Investigation Lessons

This project demonstrated the importance of correlating multiple telemetry sources during a security investigation.

Windows Security events provided evidence of authentication, account creation and group membership changes, while Sysmon provided process execution telemetry that helped identify the commands responsible for those actions.

A single event was not sufficient to understand the complete sequence. Correlating Event IDs 4720 and 4732 with Sysmon Event ID 1 provided stronger evidence of the account creation and privilege assignment.

## Importance of Evidence Correlation

The investigation also demonstrated the importance of distinguishing confirmed evidence from assumptions.

Although the failed authentication attempts occurred shortly before the account creation, the available telemetry did not establish a direct relationship between the two activities.

The investigation therefore treated the authentication failures as suspicious activity rather than confirmed malicious behavior.

## Detection and Investigation Limitations

The project showed that log collection quality directly affects investigation capabilities.

Some Sysmon fields were not automatically extracted by Splunk and required `rex` extraction from the raw XML data.

The investigation also demonstrated that the absence of telemetry does not necessarily prove that an action did not occur. It only indicates that no corresponding evidence was found in the available logs and investigated time period.

## Practical Skills Developed

Through this project, the following skills were practiced:

- Windows Security event analysis.
- Sysmon process investigation.
- SPL query development.
- Event correlation across multiple log sources.
- Local account and privilege escalation investigation.
- Timeline reconstruction.
- Evidence-based incident assessment.
- MITRE ATT&CK technique mapping.
- Incident documentation and reporting.

## Final Takeaway

The main lesson from the project was that effective SOC investigation requires more than finding suspicious events.

The analyst must establish what happened, correlate independent evidence sources, identify what can and cannot be concluded, and document the findings without assuming facts that are not supported by the available telemetry.
