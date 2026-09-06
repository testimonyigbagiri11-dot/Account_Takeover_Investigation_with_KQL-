# CLD-0001 — Executive Account Takeover Investigation

**Simulated client engagement — MyFirstHack community training program**

> ⚠️ This is a **fictional training scenario**. Cloudora, all named individuals, and all data referenced are simulated for educational purposes as part of the [MyFirstHack](https://myfirstcyberjob.com) beginner-friendly SOC analyst training pack. This is not real employment or a real client engagement — see [Portfolio Framing](#portfolio-framing) below for how this is presented on a CV.

## Scenario

Investigated a simulated executive account takeover during a fictional client engagement for **Cloudora**, a 150-person B2B HR software company. At 08:55, an IT admin flagged a sign-in to the CEO's account from Lagos, Nigeria at 03:12 — while he was reportedly asleep in London. With the company days from closing its largest enterprise deal, the task was to confirm or rule out compromise, reconstruct the full attack timeline, identify any attacker persistence, determine whether other accounts were affected, and produce a client-ready incident report.

**Attack chain uncovered:** password spray → account takeover → MFA persistence → BEC (invoice fraud) staging.

## What I Did

- Queried 8 days of Entra ID sign-in logs and audit logs using **KQL** in Azure Data Explorer
- Confirmed the Lagos sign-in was a genuine compromise (not travel) by establishing the CEO's sign-in baseline and comparing failed/successful login sequencing
- Traced the intrusion backward to a **three-night password-spray campaign** against 26 employee accounts from three shared source IPs
- Identified a **second compromised account** beyond the initial alert, missed by the original triage
- Found attacker persistence: a rogue MFA device registration and a concealed inbox rule designed to hide finance/invoice correspondence — staging for Business Email Compromise
- Ruled out a **false positive** on a third account (legitimate business travel, correctly distinguished from the malicious pattern using login timing, device consistency, and first-attempt success)
- Scoped the full blast radius: 26 targeted accounts, 2 breached, 24 requiring precautionary credential resets
- Wrote a full incident report using the **NIST SP 800-61** incident response lifecycle, with findings mapped to **MITRE ATT&CK**

## Skills Demonstrated

- KQL (Kusto Query Language) — Microsoft Sentinel / Azure Data Explorer
- Entra ID (Azure AD) sign-in log analysis
- Account takeover (ATO) investigation methodology
- Distinguishing true positives from false positives using behavioral baselines
- Persistence detection (MFA abuse, mailbox rule abuse)
- Incident scoping and blast-radius analysis
- MITRE ATT&CK mapping
- Incident report writing (NIST SP 800-61 lifecycle)

## MITRE ATT&CK Techniques Identified

| Technique | ID |
|---|---|
| Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Device Registration | [T1098.005](https://attack.mitre.org/techniques/T1098/005/) |
| Email Hiding Rules | [T1564.008](https://attack.mitre.org/techniques/T1564/008/) |

## Repository Contents

```
├── README.md                          # This file
├── CLD-0001_Incident_Report.md        # Full incident report (NIST SP 800-61 format)
├── queries/
│   └── kql_queries.kql                # All KQL queries used, with comments
└── evidence/
    └── *.png                          # Query result screenshots referenced in the report
```

## Sample Finding

Password-spray attempts by source IP, scoped to failed logins across the full 8-day window:

```kql
CloudoraSignIn_CL
| where ResultType == "50126"
| summarize Failures = count(), TargetedAccounts = dcount(UserPrincipalName) by IPAddress, Country
| order by Failures desc
```

**Result:** 3 IPs in a shared Nigerian range generated 114 failed logins across 26 distinct accounts over 3 nights — few attempts per account, broad account coverage, consistent with password spraying rather than brute force.

## Read the Full Report

📄 [CLD-0001_Incident_Report.md](./CLD-0001_Incident_Report.md)

## Portfolio Framing

This project is listed on my CV under a clearly labeled **"Simulated Client Engagements — MyFirstHack"** section, never presented as employment history.

**How I describe it in interviews:**

> "I investigated an executive account takeover end to end — traced a password spray to the initial access, found MFA persistence and a BEC inbox rule, scoped a second compromised account, and wrote the incident report. I can walk you through every decision."

---

*Training resource: [MyFirstHack](https://myfirstcyberjob.com) community — beginner-friendly SOC analyst engagements.*
