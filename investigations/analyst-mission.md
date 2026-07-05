# Analyst Mission

You are the L1 analyst. Start only from the **Multiple Failed Authentication Attempts** alert involving `sjenkins`, `10.20.10.142`, `SOC-WKS-084`, and `SOC-DC-01`. Do not read `answer-key/ground-truth.md` first.

Your job is to decide whether the alert is benign, compromised-account activity, or part of a wider incident. Validate identity and asset context, search for success after failures, then pivot only when evidence justifies it. Build an evidence-backed timeline across Windows authentication, Sysmon, proxy, DNS, email, EDR-style, firewall, and VPN telemetry.

Record for every pivot: hypothesis, SPL/search, evidence found, alternative benign explanation, confidence, and next action. Escalate from L1 to L2 when evidence shows multi-source compromise, credential-access behavior, C2-like traffic, privilege escalation, lateral movement, or critical-asset impact.
