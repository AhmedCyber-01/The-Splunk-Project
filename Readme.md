# Splunk SIEM Log Analysis Projects

This repository contains multiple projects that demonstrate how to analyze different types of logs using Splunk SIEM. Each project includes sample log files, SPL queries, dashboards, and security analysis techniques.

## Labs

### 1. SSH Log Analysis
Analyze SSH authentication logs to identify:
- Successful and failed login attempts
- Brute-force attacks
- Suspicious IP addresses
- User authentication activity

### 2. Web Traffic (Apache) Log Analysis
Analyze Apache web server logs to:
- Monitor total web requests and response statistics
- Identify top requested URIs and active users
- Detect client and server errors
- Investigate geographic traffic distribution

### 3. DNS Log Analysis using Splunk
Analyze DNS query logs to:
- Analyze DNS query types (A, AAAA, CNAME, PTR, MX)
- Identify most frequently queried domains
- Find top clients generating DNS traffic
- Spot failed or suspicious queries (e.g., NXDOMAIN responses)
- Detect high-latency DNS lookups (possible DNS tunneling or misconfigurations)

### 4. HTTP Log Analysis using Splunk
Analyzw HTTP access logs to:
- Analyze HTTP request methods (GET, POST, PUT, DELETE, CONNECT, OPTIONS)
- Detect client errors (4xx) and server errors (5xx)
- Identify suspicious user agents (curl, sqlmap, botnet-checker, python-requests)
- Flag suspicious URIs (e.g., /admin, /shell.php, /etc/passwd)
- Spot large data transfers (possible exfiltration)

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)
- Sample Network & Security Logs

## Goal
The goal of these projects is to build hands-on experience with log analysis, threat detection, and security monitoring using Splunk SIEM.