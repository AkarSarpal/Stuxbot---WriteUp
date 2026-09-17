# Stuxbot — Threat Hunt Writeup

A narrative writeup of a threat hunting exercise tracing a "Stuxbot" intrusion through Sysmon and Zeek logs in Kibana, from initial phishing delivery through lateral movement and credential theft.

## Summary

Starting from a threat intel report on Stuxbot's known playbook (phishing → OneNote lure → batch script → in-memory PowerShell → RAT persistence), this writeup documents the full investigation:

- **Delivery** — `invoice.one` downloaded via Edge from Gmail, tunneled through file.io
- **Execution** — OneNote's embedded-button trick launching `invoice.bat`
- **C2** — Hidden PowerShell pulling a stager from Pastebin, `default.exe` beaconing over ngrok
- **Recon** — SharpHound collecting Active Directory attack paths
- **Lateral movement** — PsExec used to reach a second host (`PKI`) under a service account
- **Credential theft** — Password spraying leading to compromised `svc-sql1` credentials

The investigation correlates evidence across Sysmon process/network/file events and Zeek DNS/connection logs, using a matched SHA256 hash to pivot from a single infected host to a full two-host compromise.

## Contents

- [`WriteUp.md`](./WriteUp.md) — the full writeup, including queries used, findings at each stage, and closing lessons learned

## Key takeaways

- No single log source told the whole story — browser, network (Zeek), process, and auth logs each filled a different gap.
- A missing log (empty Sysmon network events) was itself a clue, not a dead end.
- Behavioral indicators (parent/child process relationships, hidden PowerShell flags, tool misuse like PsExec) proved more durable than hashes or filenames, which attackers can easily change.
