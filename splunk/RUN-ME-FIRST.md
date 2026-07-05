# How to Run This Project

This repository is **not a normal localhost website**. Its main runtime is Splunk.

## Option A — Recommended: Splunk on your PC
1. Install Splunk Enterprise Free/Trial.
2. Start Splunk.
3. Open a browser to `http://localhost:8000`.
4. Sign in with the admin account created during installation.
5. Create indexes: `windows`, `sysmon`, `vpn`, `firewall`, `proxy`, `dns`, `edr`, `email`, `threatintel`, `assets`, `identity`.
6. Upload each CSV from `datasets/` using **Settings → Add Data → Upload**.
7. Map each file to the index listed in `splunk/ingestion-guide.md`.
8. For event datasets, set `_time` from the `_time` CSV field.
9. Upload `threat_intel_iocs.csv` as a lookup table if you want IOC-match searches.
10. Run searches from `detections/phase3-detection-pack.md`.
11. Import `dashboards/soc-investigation-dashboard.xml` into a Classic dashboard.

## Option B — Read-only project review
Open `README.md` in VS Code/Cursor and use Markdown Preview. This shows documentation only; it does not execute SIEM searches.

## Option C — GitHub portfolio
Push the folder to a GitHub repository. GitHub renders README and Markdown files, but the Splunk searches still need Splunk to execute.

## Important
`localhost:8000` is the Splunk web interface. The repository itself is not a web app and should not be presented as one.
