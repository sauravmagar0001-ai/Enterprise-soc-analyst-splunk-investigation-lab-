# Guided Investigation — INC-2026-0042

## Starting point
You are the L1 analyst. Begin only with the **Multiple Failed Authentication Attempts** alert involving `sjenkins`, `SOC-WKS-084` (`10.20.10.142`) and `SOC-DC-01`.

## Investigation sequence
1. Validate the user and source endpoint against identity and asset context.
2. Review authentication failures and search for a success after failures.
3. Pivot to Sysmon process telemetry on the source endpoint.
4. Review suspicious PowerShell and parent-child process context.
5. Pivot to proxy and DNS activity around the same time window.
6. Identify the related email event and extract synthetic IOCs.
7. Review historical EDR-style telemetry and confirm whether it reached the SIEM queue.
8. Correlate outbound firewall sessions and test for beacon-like periodicity.
9. Review VPN activity for location anomalies and synthetic TOR classification.
10. Search for privileged group changes and access to the critical SQL server.
11. Assess abnormal outbound transfer and determine final incident scope.

## Required analyst output
Record evidence, confidence, alternative benign explanations, severity changes, escalation reason, containment recommendations, remediation recommendations and detection gaps.

Do not read `answer-key/ground-truth.md` until your investigation is complete.
