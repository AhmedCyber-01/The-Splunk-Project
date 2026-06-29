# MITRE ATT&CK Mapping

This project focuses on hunting for brute-force attacks, password spraying, and suspicious authentication activity using Windows Security Event Logs in Splunk. The following MITRE ATT&CK techniques are related to the detections implemented in this project.

---

# Detection 1 - Failed Login Attempts

## Security Scenario

A high number of failed login attempts against one or more accounts may indicate password guessing or brute-force activity.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode=4625
| stats count by Account_Name, src_ip
| sort -count
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Password Guessing | T1110.001 |

---

# Detection 2 - Password Spraying

## Security Scenario

An attacker attempts the same password against multiple user accounts to avoid account lockouts.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode=4625
| stats dc(Account_Name) as Targeted_Accounts values(Account_Name) as Accounts by src_ip
| where Targeted_Accounts >= 5
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Password Spraying | T1110.003 |

---

# Detection 3 - Brute Force Attack

## Security Scenario

Repeated failed authentication attempts against a single account may indicate a brute-force attack.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode=4625
| stats count by Account_Name, src_ip
| where count >= 10
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Password Guessing | T1110.001 |

---

# Detection 4 - Successful Login After Multiple Failures

## Security Scenario

A successful login immediately following multiple failed attempts may indicate that an attacker successfully guessed valid credentials.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode IN (4624,4625)
| stats values(EventCode) as Events count by Account_Name, src_ip
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Valid Accounts | T1078 |
| Brute Force | T1110 |

---

# Detection 5 - Account Lockouts

## Security Scenario

Account lockouts caused by repeated authentication failures may indicate brute-force attempts.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode=4740
| table _time Account_Name Caller_Computer_Name
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

# Detection 6 - Authentication Timeline Analysis

## Security Scenario

Monitoring authentication activity over time helps identify spikes in failed logins that may indicate automated attacks.

### SPL Query

```spl
index=main source="winodws_logs.json" EventCode IN (4624,4625)
| timechart span=5m count by EventCode
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Password Spraying | T1110.003 |

---

# Detection 7 - Suspicious Source IP Activity

## Security Scenario

A single source IP generating authentication attempts against multiple accounts may indicate malicious scanning or credential attacks.

### SPL Query

```spl
index=main source="winodws_logs.json" 
EventCode=4625
| stats count dc(Account_Name) as Targeted_Accounts by src_ip
| where Targeted_Accounts > 5
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Password Spraying | T1110.003 |
| Brute Force | T1110 |

---

# Summary

| Detection | Windows Event ID | MITRE ATT&CK |
|-----------|------------------|--------------|
| Failed Login Attempts | 4625 | T1110 - Brute Force |
| Password Spraying | 4625 | T1110.003 - Password Spraying |
| Brute Force Detection | 4625 | T1110.001 - Password Guessing |
| Successful Login After Failures | 4624, 4625 | T1078 - Valid Accounts |
| Account Lockout | 4740 | T1110 - Brute Force |
| Authentication Timeline | 4624, 4625 | T1110 - Brute Force |
| Suspicious Source IP | 4625 | T1110.003 - Password Spraying |