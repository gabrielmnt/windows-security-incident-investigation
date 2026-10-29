index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventID="1"
    AND (
        like(CommandLine,"%net user%")
        OR like(CommandLine,"%net localgroup%")
    )
| table _time Image CommandLine User
| sort _time