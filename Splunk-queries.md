# Splunk SPL Queries — Brute Force Investigation

## Detect Failed Login Attempts
```spl
index=linux_logs sourcetype=syslog "Failed password"
| table _time, host, src_ip, user, action
```

## Count Failed Attempts by Source IP
```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort -failed_attempts
```

## Threshold Alert — More Than 10 Failures in 5 Minutes
```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats count as attempts by _time, src_ip
| where attempts > 10
```

## Detect Lateral Movement Indicator — Multiple Usernames from Same IP
```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex "for (invalid user )?(?<username>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(username) as unique_users, count as total_attempts by src_ip
| where unique_users > 3
| sort -total_attempts
```

## Successful Login After Multiple Failures (Potential Compromise)
```spl
index=linux_logs sourcetype=syslog ("Failed password" OR "Accepted password")
| rex "(?<status>Failed|Accepted) password for (invalid user )?(?<username>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(status="Failed")) as failures, count(eval(status="Accepted")) as successes by src_ip
| where failures > 5 AND successes > 0
```
