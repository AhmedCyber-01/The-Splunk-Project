# MITRE ATT&CK Mapping

This document maps the security detections implemented in the **Apache Web Traffic Monitoring Dashboard** to the MITRE ATT&CK Framework. The purpose of these mappings is to demonstrate how web server logs can be leveraged to identify adversary behavior and support SOC investigations.

---

# Detection 1 – HTTP Client Errors (4xx)

## Security Scenario

A large number of HTTP 403 (Forbidden) or HTTP 404 (Not Found) responses may indicate an attacker attempting to discover hidden resources, administrative portals, or sensitive files.

### Detection Query

```spl
source="apache_logs.json"
host="webserver"
sourcetype="_json"
| where status>=400 AND status<500
| stats count by ip,status
```

### MITRE ATT&CK Mapping

| Category | Value |
|----------|-------|
| Tactic | Reconnaissance |
| Technique | Active Scanning |
| ATT&CK ID | T1595 |
| Data Source | Web Server Logs |

### Detection Metadata

**Severity:** Medium

**Priority:** P2

### Possible False Positives

- Users requesting outdated links
- Broken bookmarks
- Typographical errors in URLs
- Web crawlers

### Recommended Response

- Review requested URIs.
- Identify repeated requests from the same IP.
- Block malicious IPs if reconnaissance is confirmed.

### Security Insight

Attackers frequently enumerate web applications by requesting directories and files that may expose sensitive information. A high volume of 404 or 403 responses often indicates forced browsing or reconnaissance activity.

---

# Detection 2 – Server Errors (5xx)

## Security Scenario

Repeated HTTP 500-series responses may indicate exploitation attempts, application failures, or backend service issues.

### Detection Query

```spl
source="apache_logs.json"
host="webserver"
sourcetype="_json"
| where status>=500 AND status<600
| stats count by uri
```

### MITRE ATT&CK Mapping

| Category | Value |
|----------|-------|
| Tactic | Initial Access |
| Technique | Exploit Public-Facing Application |
| ATT&CK ID | T1190 |
| Data Source | Web Server Logs |

### Detection Metadata

**Severity:** High

**Priority:** P2

### Possible False Positives

- Application bugs
- Backend service failures
- Database outages

### Recommended Response

- Review server logs.
- Correlate with application logs.
- Investigate unusual requests before each server error.

### Security Insight

A sudden increase in HTTP 5xx responses may indicate attackers attempting to exploit vulnerabilities in a public-facing web application.

---

# Detection 3 – Top Requested URIs

## Security Scenario

Monitoring the most frequently requested resources helps identify attempts to access sensitive endpoints, administrative interfaces, or hidden directories.

### Detection Query

```spl
source="apache_logs.json"
host="webserver"
sourcetype="_json"
| stats count by uri
| sort -count
```

### MITRE ATT&CK Mapping

| Category | Value |
|----------|-------|
| Tactic | Reconnaissance |
| Technique | Gather Victim Network Information |
| ATT&CK ID | T1590 |
| Data Source | Web Server Logs |

### Detection Metadata

**Severity:** Low

**Priority:** P3

### Possible False Positives

- Popular website pages
- Static resources
- Search engine crawlers

### Recommended Response

- Review unexpected URIs.
- Investigate requests targeting administrative pages or backup files.

### Security Insight

Unexpected requests to endpoints such as `/admin`, `/backup`, `/config`, or `/phpmyadmin` may indicate reconnaissance or exploitation attempts.

---

# Detection 4 – High Request Volume from a Client IP

## Security Scenario

An unusually high number of requests from a single IP address may indicate automated scanning, bots, or denial-of-service activity.

### Detection Query

```spl
source="apache_logs.json"
host="webserver"
sourcetype="_json"
| stats count by ip
| sort -count
```

### MITRE ATT&CK Mapping

| Category | Value |
|----------|-------|
| Tactic | Reconnaissance |
| Technique | Active Scanning |
| ATT&CK ID | T1595 |
| Data Source | Web Server Logs |

### Detection Metadata

**Severity:** Medium

**Priority:** P2

### Possible False Positives

- Load balancers
- Monitoring systems
- Search engine crawlers

### Recommended Response

- Verify IP reputation.
- Compare request rate with normal baseline.
- Investigate unusual user-agent strings.

### Security Insight

Large request volumes originating from a single client may indicate automated reconnaissance or malicious web scanning.

---

# Detection 5 – Geographic Traffic Analysis

## Security Scenario

GeoIP enrichment helps analysts identify unexpected countries accessing the web application.

### Detection Query

```spl
source="apache_logs.json"
host="webserver"
sourcetype="_json"
method=GET
| table ip
| iplocation ip
| stats count by Country
| geom geo_countries featureIdField="Country"
```

### MITRE ATT&CK Mapping

| Category | Value |
|----------|-------|
| Tactic | Reconnaissance |
| Technique | Active Scanning *(Contextual)* |
| ATT&CK ID | T1595 |
| Data Source | Web Server Logs |

### Detection Metadata

**Severity:** Informational

**Priority:** P4

### Possible False Positives

- Remote employees
- VPN users
- CDN infrastructure
- Cloud providers

### Recommended Response

- Investigate traffic originating from unexpected countries.
- Compare with business operations and expected user locations.

### Security Insight

Geographic analysis provides valuable context during investigations and helps identify unexpected access patterns.

---

# Detection Summary

| Detection | ATT&CK Tactic | Technique | ATT&CK ID | Severity |
|-----------|---------------|-----------|-----------|----------|
| HTTP Client Errors (4xx) | Reconnaissance | Active Scanning | T1595 | Medium |
| HTTP Server Errors (5xx) | Initial Access | Exploit Public-Facing Application | T1190 | High |
| Top Requested URIs | Reconnaissance | Gather Victim Network Information | T1590 | Low |
| High Request Volume by Client IP | Reconnaissance | Active Scanning | T1595 | Medium |
| Geographic Traffic Analysis | Reconnaissance | Active Scanning *(Contextual)* | T1595 | Informational |

---

# SOC Analyst Notes

This project demonstrates how Apache web server logs can be analyzed using Splunk to identify suspicious web activity, detect reconnaissance attempts, monitor application health, and support incident investigations.

While not every dashboard visualization directly represents an ATT&CK technique, several panels provide valuable context for identifying adversary behavior when correlated with additional telemetry such as firewall logs, Web Application Firewall (WAF) events, endpoint telemetry, or threat intelligence.

In a production SOC environment, these detections could be extended by:

- Detecting directory brute-force attacks
- Monitoring suspicious User-Agent strings
- Detecting SQL Injection attempts
- Detecting Cross-Site Scripting (XSS) payloads
- Monitoring access to administrative interfaces
- Creating automated Splunk alerts
- Mapping detections to additional MITRE ATT&CK techniques
