# MITRE ATT&CK Mapping

This project analyzes SSH authentication logs to identify suspicious authentication activity, detect brute-force attacks, and monitor remote access behavior. The following ATT&CK techniques are relevant to the detections implemented in this project.

---

# Detection 1 - Failed SSH Login Attempts

## Security Scenario

Multiple failed authentication attempts from a single source IP may indicate an attacker attempting to guess user passwords.

### Detection Query

```spl
index=ssh_logs event_type="Failed SSH Login"
| stats count by id.orig_h
| sort -count
```

### MITRE ATT&CK Mapping

| Category    | Value               |
| ----------- | ------------------- |
| Tactic      | Credential Access   |
| Technique   | Brute Force         |
| ATT&CK ID   | T1110               |
| Data Source | Authentication Logs |

### Security Insight

Repeated authentication failures are one of the earliest indicators of brute-force attacks. Monitoring these events allows security teams to identify malicious IP addresses before successful compromise occurs.

---

# Detection 2 - Multiple Failed Authentication Attempts

## Security Scenario

An attacker repeatedly attempts authentication against the same server within a short period of time.

### Detection Query

```spl
index=ssh_logs event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h,id.resp_h
| where count > 5
```

### MITRE ATT&CK Mapping

| Category    | Value               |
| ----------- | ------------------- |
| Tactic      | Credential Access   |
| Technique   | Brute Force         |
| ATT&CK ID   | T1110               |
| Data Source | Authentication Logs |

### Security Insight

Large numbers of authentication failures from the same IP address often indicate automated password guessing or brute-force activity.

---

# Detection 3 - Successful SSH Authentication

## Security Scenario

Successful logins should be reviewed to establish normal administrative activity. When successful authentication follows repeated failures, compromised credentials may be involved.

### Detection Query

```spl
index=ssh_logs event_type="Successful SSH Login"
| stats count by id.orig_h,id.resp_h
```

### MITRE ATT&CK Mapping

| Category    | Value                            |
| ----------- | -------------------------------- |
| Tactic      | Defense Evasion / Initial Access |
| Technique   | Valid Accounts                   |
| ATT&CK ID   | T1078                            |
| Data Source | Authentication Logs              |

### Security Insight

Adversaries commonly use stolen or compromised credentials instead of exploiting software vulnerabilities. Correlating successful logins with previous failed attempts helps identify potential account compromise.

---

# Detection 4 - SSH Connections Without Authentication

## Security Scenario

Attackers often probe exposed SSH services before attempting authentication.

### Detection Query

```spl
index=ssh_logs event_type="Connection Without Authentication"
| stats count by id.orig_h
```

### MITRE ATT&CK Mapping

| Category    | Value                   |
| ----------- | ----------------------- |
| Tactic      | Reconnaissance          |
| Technique   | Active Scanning         |
| ATT&CK ID   | T1595                   |
| Data Source | Network Connection Logs |

### Security Insight

Repeated SSH connections without completing authentication may indicate reconnaissance, service enumeration, or automated scanning.

---

# Detection 5 - SSH Activity Timeline

## Security Scenario

Monitoring authentication events over time helps identify spikes in login activity that may indicate ongoing attacks.

### Detection Query

```spl
index=ssh_logs
| timechart span=1h count by event_type
```

### MITRE ATT&CK Mapping

| Category  | Value             |
| --------- | ----------------- |
| Tactic    | Credential Access |
| Technique | Brute Force       |
| ATT&CK ID | T1110             |

### Security Insight

Time-based visualizations help analysts quickly recognize abnormal authentication patterns and determine when an attack began.

---

# Detection Rule Summary

| Detection                               | ATT&CK Tactic                    | Technique       | ATT&CK ID | Severity      |
| --------------------------------------- | -------------------------------- | --------------- | --------- | ------------- |
| Failed SSH Login Attempts               | Credential Access                | Brute Force     | T1110     | Medium        |
| Multiple Failed Authentication Attempts | Credential Access                | Brute Force     | T1110     | High          |
| Successful Login After Failures         | Defense Evasion / Initial Access | Valid Accounts  | T1078     | High          |
| SSH Connections Without Authentication  | Reconnaissance                   | Active Scanning | T1595     | Low           |
| Authentication Timeline Monitoring      | Credential Access                | Brute Force     | T1110     | Informational |

---

# SOC Analyst Notes

These detections demonstrate how SSH authentication logs can be leveraged to identify common attacker behaviors, including brute-force attacks, credential misuse, and reconnaissance activity. In a production SOC environment, these searches would typically be converted into scheduled correlation searches or real-time alerts. Detection accuracy can be further improved by correlating authentication events with firewall, endpoint, or identity provider logs.