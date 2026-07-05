# Splunk Free/Trial Ingestion Guide

This lab uses synthetic CSV telemetry. Create separate indexes where your Splunk license allows; otherwise use one `soc_lab` index and preserve sourcetypes.

| Dataset | Suggested index | Sourcetype | Time field |
|---|---|---|---|
| windows_auth.csv | windows | `soc:windows:auth` | `_time` |
| sysmon_process.csv | sysmon | `soc:sysmon:process` | `_time` |
| vpn_auth.csv | vpn | `soc:vpn:auth` | `_time` |
| firewall_traffic.csv | firewall | `soc:firewall:traffic` | `_time` |
| proxy_web.csv | proxy | `soc:proxy:web` | `_time` |
| dns_queries.csv | dns | `soc:dns:query` | `_time` |
| edr_alerts.csv | edr | `soc:edr:alert` | `_time` |
| email_security.csv | email | `soc:email:security` | `_time` |

Use timestamp format `%Y-%m-%dT%H:%M:%SZ`. Upload `asset_inventory.csv`, `identity_context.csv`, and `threat_intel_iocs.csv` as lookups.

## Validation searches

```spl
| tstats count where index=* by index sourcetype
```

```spl
index=windows sourcetype="soc:windows:auth" | stats count min(_time) as first max(_time) as last
```

The project does not require Splunk Enterprise Security. ES concepts are referenced only as learning context.
