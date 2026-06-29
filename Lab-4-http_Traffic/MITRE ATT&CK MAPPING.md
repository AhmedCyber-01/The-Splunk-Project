# MITRE ATT&CK Mapping

This document maps the detections implemented in **Project 04 – HTTP Traffic Analysis Using Splunk** to the MITRE ATT&CK Framework. HTTP logs provide valuable visibility into web-based attacks, reconnaissance activity, exploitation attempts, and suspicious client behavior. While not every HTTP event directly maps to an ATT&CK technique, many detections provide important context for identifying adversary activity during security investigations.

---

# Detection 1 – High Volume HTTP Requests from a Client

## Security Scenario

A client generating an unusually high number of HTTP requests may indicate automated reconnaissance, vulnerability scanning, web scraping, or denial-of-service activity.

### Detection Query

```spl
index=http_lab sourcetype="json"
| stats count AS Requests by id.orig_h
| sort -Requests
| head 10
```

### MITRE ATT&CK Mapping

| Category    | Value           |
| ----------- | --------------- |
| Tactic      | Reconnaissance  |
| Technique   | Active Scanning |
| ATT&CK ID   | T1595           |
| Data Source | HTTP Logs       |

### Detection Metadata

**Severity:** Medium

**Priority:** P2

### Possible False Positives

* Search engine crawlers
* Load testing tools
* Internal vulnerability scanners
* Monitoring systems

### Recommended Response

* Verify the source IP.
* Review request frequency and requested resources.
* Correlate with firewall and IDS logs.
* Block or rate-limit malicious clients if necessary.

### Security Insight

High request volumes often represent reconnaissance or automated scanning activity that precedes exploitation attempts.

---

# Detection 2 – HTTP Server Errors (5xx)

## Security Scenario

Repeated server-side errors may indicate exploitation attempts against vulnerable web applications or backend service failures.

### Detection Query

```spl
index=http_lab sourcetype="json"
status_code>=500 status_code<600
| stats count AS server_errors
```

### MITRE ATT&CK Mapping

| Category    | Value                             |
| ----------- | --------------------------------- |
| Tactic      | Initial Access                    |
| Technique   | Exploit Public-Facing Application |
| ATT&CK ID   | T1190                             |
| Data Source | HTTP Logs                         |

### Detection Metadata

**Severity:** High

**Priority:** P2

### Possible False Positives

* Application bugs
* Backend service outages
* Misconfigured web applications

### Recommended Response

* Review web server and application logs.
* Identify requests preceding the server errors.
* Investigate vulnerable endpoints.

### Security Insight

Unexpected increases in HTTP 5xx responses may indicate attackers attempting to exploit application vulnerabilities.

---

# Detection 3 – Suspicious User-Agent Strings

## Security Scenario

Many penetration testing frameworks and automated attack tools identify themselves using recognizable User-Agent strings.

### Detection Query

```spl
index=http_lab sourcetype="json"
user_agent IN (
"sqlmap/1.5.1",
"curl/7.68.0",
"python-requests/2.25.1",
"botnet-checker/1.0"
)
| stats count by user_agent
```

### MITRE ATT&CK Mapping

| Category    | Value           |
| ----------- | --------------- |
| Tactic      | Reconnaissance  |
| Technique   | Active Scanning |
| ATT&CK ID   | T1595           |
| Data Source | HTTP Logs       |

### Detection Metadata

**Severity:** Medium

**Priority:** P2

### Possible False Positives

* Security assessments
* Internal penetration testing
* Automated deployment scripts
* Monitoring tools

### Recommended Response

* Verify whether the activity is authorized.
* Review source IP addresses.
* Investigate targeted resources.
* Correlate with additional security telemetry.

### Security Insight

Tools such as **sqlmap**, **curl**, and **Python Requests** are commonly used during reconnaissance, vulnerability testing, and exploitation.

---

# Detection 4 – Large HTTP File Transfers

## Security Scenario

Large HTTP responses may indicate legitimate downloads or potential data exfiltration.

### Detection Query

```spl
index=http_lab sourcetype="json"
resp_body_len>500000
| table ts id.orig_h id.resp_h uri resp_body_len
| sort -resp_body_len
```

### MITRE ATT&CK Mapping

| Category    | Value                         |
| ----------- | ----------------------------- |
| Tactic      | Exfiltration                  |
| Technique   | Exfiltration Over Web Service |
| ATT&CK ID   | T1567                         |
| Data Source | HTTP Logs                     |

### Detection Metadata

**Severity:** Medium

**Priority:** P2

### Possible False Positives

* Software downloads
* Backup transfers
* Large media files
* Business-related file sharing

### Recommended Response

* Validate the transferred content.
* Review the requesting client.
* Compare against normal download patterns.
* Investigate unexpected outbound transfers.

### Security Insight

Large HTTP responses may represent unauthorized data movement and should be correlated with endpoint activity when investigating potential data exfiltration.

---

# Detection 5 – Access to Sensitive Resources

## Security Scenario

Attackers frequently attempt to access administrative pages, web shells, or sensitive system files while performing reconnaissance or exploitation.

### Detection Query

```spl
index=http_lab sourcetype="json"
uri IN ("/admin","/shell.php","/etc/passwd")
| stats count by uri,id.orig_h
```

### MITRE ATT&CK Mapping

| Category    | Value                             |
| ----------- | --------------------------------- |
| Tactic      | Initial Access                    |
| Technique   | Exploit Public-Facing Application |
| ATT&CK ID   | T1190                             |
| Data Source | HTTP Logs                         |

### Detection Metadata

**Severity:** High

**Priority:** P1

### Possible False Positives

* Security testing
* Administrator activity
* Vulnerability assessments

### Recommended Response

* Review the source IP.
* Investigate repeated requests.
* Examine associated web server logs.
* Block malicious clients if necessary.

### Security Insight

Requests targeting resources such as **/admin**, **/shell.php**, or **/etc/passwd** often indicate reconnaissance or attempts to exploit vulnerable web applications.

---

# Detection 6 – HTTP Traffic Spikes

## Security Scenario

A sudden increase in HTTP requests over a short period may indicate automated scanning, web scraping, or denial-of-service activity.

### Detection Query

```spl
index=http_lab
| timechart span=1h count
```

### MITRE ATT&CK Mapping

| Category    | Value           |
| ----------- | --------------- |
| Tactic      | Reconnaissance  |
| Technique   | Active Scanning |
| ATT&CK ID   | T1595           |
| Data Source | HTTP Logs       |

### Detection Metadata

**Severity:** Informational

**Priority:** P3

### Possible False Positives

* Marketing campaigns
* Software updates
* Normal traffic spikes
* Scheduled maintenance

### Recommended Response

* Compare against historical baselines.
* Investigate unusual spikes.
* Correlate with firewall and IDS events.

### Security Insight

Traffic timelines provide valuable context during investigations and help identify unusual activity that may warrant further analysis.

---

# Detection Summary

| Detection                     | ATT&CK Tactic  | Technique                         | ATT&CK ID | Severity      |
| ----------------------------- | -------------- | --------------------------------- | --------- | ------------- |
| High HTTP Request Volume      | Reconnaissance | Active Scanning                   | T1595     | Medium        |
| HTTP Server Errors (5xx)      | Initial Access | Exploit Public-Facing Application | T1190     | High          |
| Suspicious User-Agent Strings | Reconnaissance | Active Scanning                   | T1595     | Medium        |
| Large File Transfers          | Exfiltration   | Exfiltration Over Web Service     | T1567     | Medium        |
| Sensitive URI Access          | Initial Access | Exploit Public-Facing Application | T1190     | High          |
| HTTP Traffic Spikes           | Reconnaissance | Active Scanning                   | T1595     | Informational |

---

# SOC Analyst Notes

HTTP logs provide critical visibility into web application activity and are one of the primary data sources used by Security Operations Centers to detect attacks targeting internet-facing applications.

Although individual HTTP events do not always represent malicious activity, correlating request patterns, response codes, User-Agent strings, and requested resources enables analysts to identify reconnaissance, exploitation attempts, and potential data exfiltration.

In a production SOC environment, these detections can be further enhanced by integrating:

* Web Application Firewall (WAF) logs
* Threat intelligence feeds
* GeoIP enrichment
* Firewall and IDS/IPS telemetry
* Endpoint Detection and Response (EDR) data
* Risk-based alerting
* Automated Splunk Enterprise Security correlation searches

These enhancements improve detection fidelity and provide greater context for incident investigations.
