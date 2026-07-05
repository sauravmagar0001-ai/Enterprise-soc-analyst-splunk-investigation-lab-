# Final Detection Catalog

Use these after ingesting the supplied synthetic datasets. A hit is a lead, not automatic proof of compromise.

| ID | Detection | Primary data | Severity | Analyst goal |
|---|---|---|---|---|
| DET-001 | Multiple Failed Authentication Attempts | Windows auth | Medium | Validate burst, user, source and destination |
| DET-002 | Success After Failure Burst | Windows auth | High | Identify possible credential compromise |
| DET-003 | Suspicious PowerShell Indicator | Sysmon | High | Review command line and parent-child context |
| DET-004 | Rare Parent-Child Process Chain | Sysmon | Medium | Separate admin activity from abnormal execution |
| DET-005 | Proxy IOC Match | Proxy + TI | High | Correlate web access with synthetic IOC lookup |
| DET-006 | DNS IOC Match | DNS + TI | High | Identify suspicious name resolution |
| DET-007 | Periodic Outbound Beaconing | Firewall | High | Test interval regularity and endpoint context |
| DET-008 | Privileged Group Membership Change | Windows auth | Critical | Validate actor, target and authorization |
| DET-009 | Critical Server Remote Access | Windows auth | High | Investigate lateral movement candidate |
| DET-010 | Abnormal Outbound Transfer | Firewall | High | Scope destination, volume and business justification |

The copy-paste SPL is in `phase3-detection-pack.md`. Tune thresholds against the supplied benign noise before presenting any result as confirmed malicious activity.
