# Phase 3 — Splunk Detection Pack

These searches are designed for the synthetic CSV datasets in this repository. Adjust index names if you ingest into a different index.

## 1. Multiple Failed Authentication Attempts
```spl
index=windows action=failure
| bin _time span=5m
| stats count as failures values(host) as hosts values(dest_ip) as destinations by _time user src_ip
| where failures>=20
| eval severity="medium"
| sort - _time
```

## 2. Successful Login After Repeated Failures
```spl
index=windows
| sort 0 user src_ip _time
| streamstats window=30 count(eval(action="failure")) as recent_failures by user src_ip
| where action="success" AND recent_failures>=10
| table _time user src_ip host dest_ip recent_failures
```

## 3. Suspicious PowerShell / Encoded Command Indicator
```spl
index=sysmon process_name="powershell.exe"
| eval cmd=lower(command_line)
| where like(cmd,"%encoded%") OR like(cmd,"%frombase64string%") OR like(cmd,"% -enc %")
| table _time host user parent_process process_name command_line process_id parent_process_id
```

## 4. Rare Parent-Child Process Chain
```spl
index=sysmon
| stats count by parent_process process_name host
| eventstats sum(count) as total by parent_process
| eval pct=round((count/total)*100,2)
| where count<5 OR pct<1
| sort count
```

## 5. Proxy IOC Match
```spl
index=proxy
| lookup threat_intel_iocs.csv ioc_value as domain OUTPUT classification confidence source
| where isnotnull(classification) AND classification!="BENIGN"
| table _time user src_ip host domain url action classification confidence source
```

## 6. DNS IOC Match
```spl
index=dns
| lookup threat_intel_iocs.csv ioc_value as query OUTPUT classification confidence source
| where isnotnull(classification) AND classification!="BENIGN"
| table _time host user src_ip query query_type response classification confidence
```

## 7. Periodic Outbound Beaconing Heuristic
```spl
index=firewall direction=outbound action=allowed
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev_time by src_ip dest_ip
| eval delta=_time-prev_time
| stats count avg(delta) as avg_interval stdev(delta) as jitter values(dest_port) as ports by src_ip dest_ip
| where count>=5 AND avg_interval>0 AND jitter<20
| sort jitter
```

## 8. Privileged Group Membership Change
```spl
index=windows event_code=4728 OR event_code=4732 OR event_code=4756
| table _time host user src_ip event_code action status
```

## 9. Lateral Movement Candidate to Critical Server
```spl
index=windows dest_ip="10.20.20.30" (logon_type=3 OR logon_type=10) action=success
| stats count values(src_ip) as sources values(host) as hosts by user dest_ip
| where count>0
```

## 10. Abnormal Outbound Transfer
```spl
index=firewall direction=outbound action=allowed
| stats sum(bytes_out) as total_bytes_out sum(bytes_in) as total_bytes_in by src_ip dest_ip
| eval total_mb=round(total_bytes_out/1024/1024,2)
| where total_mb>=5
| sort - total_mb
```

## Analyst rule
Do not treat a single query hit as proof of compromise. Correlate identity, asset criticality, authentication, endpoint, proxy, DNS, EDR-style and firewall evidence before escalation.
