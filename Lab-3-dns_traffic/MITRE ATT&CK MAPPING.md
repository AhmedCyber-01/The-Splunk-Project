
# MITRE ATT&CK Mapping

This project analyzes **Zeek DNS logs** to identify suspicious DNS activity, detect potential malware communication, and monitor network behavior. DNS is commonly abused by adversaries for command-and-control (C2), domain generation algorithms (DGA), phishing, reconnaissance, and DNS tunneling. The following MITRE ATT&CK techniques are relevant to the detections implemented in this project.

---

# Detection 1 - Most Frequently Queried Domains

## Security Scenario

Attackers often generate repeated DNS requests to command-and-control servers, phishing domains, or malicious infrastructure.

### Detection Query

```spl
index=dns_lab
| stats count by query
| sort -count
```

### MITRE ATT&CK Mapping

| Category    | Value                           |
| ----------- | ------------------------------- |
| Tactic      | Command and Control             |
| Technique   | Application Layer Protocol: DNS |
| ATT&CK ID   | T1071.004                       |
| Data Source | DNS Logs                        |

### Security Insight

Monitoring frequently queried domains helps establish normal DNS behavior while highlighting suspicious domains that may be associated with malware communication or phishing campaigns.

---

# Detection 2 - Top Source IP Addresses

## Security Scenario

A compromised endpoint may generate significantly more DNS requests than normal due to malware activity, automated scripts, or reconnaissance.

### Detection Query

```spl
index=dns_lab
| stats count by id.orig_h
| sort -count
```

### MITRE ATT&CK Mapping

| Category    | Value                                  |
| ----------- | -------------------------------------- |
| Tactic      | Discovery                              |
| Technique   | System Network Configuration Discovery |
| ATT&CK ID   | T1016                                  |
| Data Source | DNS Logs                               |

### Security Insight

Monitoring client DNS activity helps identify endpoints exhibiting abnormal behavior, such as malware beaconing, automated tools, or excessive network discovery.

---

# Detection 3 - DNS Query Type Distribution

## Security Scenario

Attackers may abuse uncommon DNS record types such as **TXT** records to transfer encoded data or establish covert communication channels.

### Detection Query

```spl
index=dns_lab
| stats count by qtype
```

### MITRE ATT&CK Mapping

| Category    | Value                           |
| ----------- | ------------------------------- |
| Tactic      | Command and Control             |
| Technique   | Application Layer Protocol: DNS |
| ATT&CK ID   | T1071.004                       |
| Data Source | DNS Logs                        |

### Security Insight

Monitoring DNS query types allows analysts to identify abnormal spikes in TXT or other uncommon record types that may indicate DNS tunneling or malware communication.

---

# Detection 4 - Failed DNS Queries

## Security Scenario

Malware often attempts to resolve domains that no longer exist or have been taken down. Large numbers of failed DNS lookups may also indicate reconnaissance or misconfigured software.

### Detection Query

```spl
index=dns_lab
| search rcode!=0
| stats count by rcode
```

### MITRE ATT&CK Mapping

| Category    | Value               |
| ----------- | ------------------- |
| Tactic      | Command and Control |
| Technique   | Dynamic Resolution  |
| ATT&CK ID   | T1568               |
| Data Source | DNS Logs            |

### Security Insight

Repeated DNS failures may reveal malware attempting to reach inactive command-and-control infrastructure, expired domains, or typo-squatted domains.

---

# Detection 5 - DNS Response Time Analysis

## Security Scenario

Slow DNS responses may indicate overloaded DNS infrastructure, remote DNS resolvers, or suspicious external communications.

### Detection Query

```spl
index=dns_lab
| stats avg(rtt) AS Average_RTT max(rtt) AS Maximum_RTT
```

### MITRE ATT&CK Mapping

| Category    | Value                           |
| ----------- | ------------------------------- |
| Tactic      | Command and Control             |
| Technique   | Application Layer Protocol: DNS |
| ATT&CK ID   | T1071.004                       |
| Data Source | DNS Logs                        |

### Security Insight

Monitoring DNS response latency helps analysts identify network issues and investigate unusual communication patterns that may indicate malicious activity.

---

# Detection 6 - Clients Querying the Most Unique Domains

## Security Scenario

Malware using Domain Generation Algorithms (DGA) typically generates hundreds or thousands of unique domain requests within a short period.

### Detection Query

```spl
index=dns_lab
| stats dc(query) AS Unique_Domains by id.orig_h
| sort -Unique_Domains
```

### MITRE ATT&CK Mapping

| Category    | Value               |
| ----------- | ------------------- |
| Tactic      | Command and Control |
| Technique   | Dynamic Resolution  |
| ATT&CK ID   | T1568               |
| Data Source | DNS Logs            |

### Security Insight

Endpoints generating unusually high numbers of unique DNS queries may indicate DGA malware, automated reconnaissance, or suspicious scripts.

---

# Detection 7 - Domains Returning DNS Errors

## Security Scenario

Repeated DNS failures for the same domain may indicate malware attempting to reach unavailable command-and-control servers or misconfigured applications.

### Detection Query

```spl
index=dns_lab
| search rcode!=0
| stats count by query
| sort -count
```

### MITRE ATT&CK Mapping

| Category    | Value               |
| ----------- | ------------------- |
| Tactic      | Command and Control |
| Technique   | Dynamic Resolution  |
| ATT&CK ID   | T1568               |
| Data Source | DNS Logs            |

### Security Insight

Reviewing failed domain resolutions helps analysts identify suspicious infrastructure and detect malware that relies on unavailable or sinkholed domains.

---

# Detection 8 - DNS Activity Timeline

## Security Scenario

Visualizing DNS activity over time helps identify traffic spikes that may correspond to malware execution, phishing campaigns, or automated reconnaissance.

### Detection Query

```spl
index=dns_lab
| timechart span=1h count
```

### MITRE ATT&CK Mapping

| Category    | Value                           |
| ----------- | ------------------------------- |
| Tactic      | Command and Control             |
| Technique   | Application Layer Protocol: DNS |
| ATT&CK ID   | T1071.004                       |
| Data Source | DNS Logs                        |

### Security Insight

Time-based visualizations enable analysts to quickly identify unusual increases in DNS traffic and correlate activity with other security events.

---

# Detection Rule Summary

| Detection                                | ATT&CK Tactic       | Technique                              | ATT&CK ID | Severity      |
| ---------------------------------------- | ------------------- | -------------------------------------- | --------- | ------------- |
| Most Frequently Queried Domains          | Command and Control | Application Layer Protocol: DNS        | T1071.004 | Medium        |
| Top Source IP Addresses                  | Discovery           | System Network Configuration Discovery | T1016     | Medium        |
| DNS Query Type Distribution              | Command and Control | Application Layer Protocol: DNS        | T1071.004 | Medium        |
| Failed DNS Queries                       | Command and Control | Dynamic Resolution                     | T1568     | High          |
| DNS Response Time Analysis               | Command and Control | Application Layer Protocol: DNS        | T1071.004 | Low           |
| Clients Querying the Most Unique Domains | Command and Control | Dynamic Resolution                     | T1568     | High          |
| Domains Returning DNS Errors             | Command and Control | Dynamic Resolution                     | T1568     | High          |
| DNS Activity Timeline                    | Command and Control | Application Layer Protocol: DNS        | T1071.004 | Informational |

---

# SOC Analyst Notes

These detections demonstrate how DNS logs can be leveraged to identify common attacker behaviors, including command-and-control communication, malware beaconing, DNS tunneling, Domain Generation Algorithm (DGA) activity, and suspicious DNS resolutions. In a production SOC environment, these SPL searches can be converted into scheduled correlation searches or real-time alerts. Detection accuracy can be further improved by enriching DNS events with threat intelligence feeds, newly registered domain (NRD) lookups, passive DNS data, and endpoint telemetry to provide additional context during investigations.

---