# Core SPL Detections

## 1. Multiple failed authentications
```spl
index=windows sourcetype="soc:windows:auth" action=failure
| bin _time span=5m
| stats count as failures values(host) as hosts values(dest_ip) as destinations by _time user src_ip
| where failures>=20
| sort _time
```

## 2. Success after repeated failures
```spl
index=windows sourcetype="soc:windows:auth"
| sort 0 user src_ip _time
| streamstats window=25 count(eval(action="failure")) as recent_failures by user src_ip
| where action="success" AND recent_failures>=10
| table _time user src_ip host dest_ip recent_failures
```

## 3. Suspicious PowerShell / encoded-command telemetry
```spl
index=sysmon sourcetype="soc:sysmon:process" process_name="powershell.exe"
| where match(lower(command_line), "(-e|-enc|-encodedcommand)")
| table _time host user parent_process process_name command_line process_id parent_process_id
```

## 4. Proxy IOC match
```spl
index=proxy sourcetype="soc:proxy:web"
| lookup threat_intel_iocs.csv ioc_value as domain OUTPUT classification confidence
| where like(classification,"SYNTHETIC_%")
| table _time user src_ip host domain url action classification confidence
```

## 5. DNS IOC match
```spl
index=dns sourcetype="soc:dns:query"
| lookup threat_intel_iocs.csv ioc_value as query OUTPUT classification confidence
| where like(classification,"SYNTHETIC_%")
| table _time host user src_ip query response classification confidence
```

## 6. Periodic outbound connections (hunting heuristic)
```spl
index=firewall sourcetype="soc:firewall:traffic" direction=outbound action=allowed
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev by src_ip dest_ip
| eval delta=_time-prev
| stats count avg(delta) as avg_interval stdev(delta) as jitter sum(bytes_out) as bytes_out by src_ip dest_ip dest_port
| where count>=5 AND avg_interval>0 AND jitter<10
```

## 7. Privileged group change
```spl
index=windows sourcetype="soc:windows:auth" event_code IN (4728,4732,4756)
| table _time host user src_ip event_code action
```

## 8. High-volume outbound transfer
```spl
index=firewall sourcetype="soc:firewall:traffic" direction=outbound action=allowed
| stats sum(bytes_out) as total_bytes values(dest_port) as ports by src_ip dest_ip
| where total_bytes>5000000
| sort - total_bytes
```

Thresholds are lab defaults, not universal production values. Tune against baseline, asset criticality, user role, approved admin activity, travel, scanners, and service accounts.
