# MITRE ATT&CK Mapping

This project analyzes Windows Security Event Logs using Splunk to monitor authentication activity, detect suspicious behavior, and identify potential security threats. The following MITRE ATT&CK techniques are related to the detections implemented in this project.

---

# Detection 1 - Failed Logon Attempts

## Security Scenario

Multiple failed login attempts against the user account may indicate a brute-force or password guessing attack.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode=4625
| stats count by Account_Name, src_ip
| sort -count
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Valid Accounts | T1078 |

---

# Detection 2 - Successful Logons

## Security Scenario

Successful logons should be monitored to identify unusual authentication activity, especially after multiple failed attempts.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode=4624
| stats count by Account_Name, Computer
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Valid Accounts | T1078 |

---

# Detection 3 - Account Lockouts

## Security Scenario

Account lockouts often occur after repeated failed login attempts and may indicate brute-force activity.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode=4740
| table _time Account_Name Caller_Computer_Name
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

# Detection 4 - New User Account Creation

## Security Scenario

Attackers may create new user accounts to maintain persistence after compromising a system.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode=4720
| table _time Target_Account Created_By
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Create Account | T1136 |

---

# Detection 5 - Privileged Logons

## Security Scenario

Monitoring privileged logons helps identify administrator account misuse or privilege escalation.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode=4672
| table _time Account_Name Computer
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Account Manipulation | T1098 |
| Valid Accounts | T1078 |

---

# Detection 6 - Security Group Changes

## Security Scenario

Adding users to privileged groups can provide attackers with elevated access across the environment.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode IN (4728,4732)
| table _time Member_Name Group_Name Added_By
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Account Manipulation | T1098 |

---

# Detection 7 - Kerberos Authentication Activity

## Security Scenario

Kerberos authentication events can help identify unusual authentication patterns and account activity.

### SPL Query

```spl
index=index=main source="winodws_logs.json" EventCode IN (4768,4769)
| stats count by Account_Name
```

### MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Valid Accounts | T1078 |

---

# Summary

| Detection | Event ID | MITRE ATT&CK |
|-----------|----------|--------------|
| Failed Logons | 4625 | T1110 - Brute Force |
| Successful Logons | 4624 | T1078 - Valid Accounts |
| Account Lockout | 4740 | T1110 - Brute Force |
| User Account Creation | 4720 | T1136 - Create Account |
| Privileged Logon | 4672 | T1098 - Account Manipulation |
| Group Membership Changes | 4728, 4732 | T1098 - Account Manipulation |
| Kerberos Authentication | 4768, 4769 | T1078 - Valid Accounts |