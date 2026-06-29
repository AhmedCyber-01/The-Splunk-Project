# Project 1 - SSH Authentication Log Analysis Using Splunk

## Overview

Secure Shell (SSH) is one of the most widely used protocols for remote administration of Linux and Unix systems. Because SSH provides direct access to servers, authentication logs are an important source of security telemetry. Monitoring these logs allows security analysts to detect unauthorized access attempts, brute-force attacks, password spraying, and suspicious authentication behavior.

In this project, I imported SSH authentication logs into Splunk Enterprise and analyzed the data using the Search Processing Language (SPL). The goal was to validate log ingestion, investigate authentication events, identify suspicious login activity, and build a foundation for future security monitoring and alerting.

---

# Objectives

* Import SSH authentication logs into Splunk
* Verify successful log ingestion and field extraction
* Analyze successful and failed SSH authentication events
* Detect repeated failed login attempts
* Identify suspicious SSH connections
* Understand how SSH logs support SOC investigations

---

# Lab Environment

| Component     | Details           |
| ------------- | ----------------- |
| SIEM Platform | Splunk Enterprise |
| Dataset       | ssh_log.json      |
| Log Format    | JSON              |
| Index         | ssh_logs          |
| Source Type   | _json             |


---

# Step 1 - Import SSH Logs

The SSH dataset was uploaded into Splunk using the **Add Data** workflow.

Navigation

```text
Settings → Add Data → Upload
```

The dataset was indexed under the **ssh_logs** index using the **_json** sourcetype to enable automatic field extraction.

### Screenshot

![Image](<Import ssh_logs.png>)

---

# Step 2 - Validate Log Ingestion

After indexing the dataset, the following SPL query was executed to verify that the events were successfully imported.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" | stats count by event_type
```

### Why this query?

This query validates that Splunk successfully indexed the dataset and categorized events by their authentication type.

### Screenshot

![Image](image.png)

---

# Step 3 - Investigate Failed SSH Authentication

Failed authentication events are often the first indicator of password guessing, brute-force attacks, or unauthorized access attempts.

The following query identifies source IP addresses responsible for failed logins.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" index="main" event_type="Failed SSH Login"
| stats count by id.orig_h
| sort -count
```

### Security Insight

Repeated failed authentication attempts originating from a single IP address may indicate brute-force activity. In a production SOC environment, these IP addresses would be investigated further or automatically blocked depending on the organization's security policy.

### Screenshot

> Failed Login Analysis
![alt text](image-1.png)

---

# Step 4 - Detect Multiple Failed Authentication Attempts

To identify more aggressive authentication attacks, the following search was performed.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" index="main" event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h, id.resp_h
```

### Security Insight

A large number of authentication failures within a short period is a common indicator of brute-force attacks. This type of detection is frequently implemented as a scheduled alert within a SIEM platform.

### Screenshot

> Multiple Failed Authentication Attempts
![alt text](image-2.png)

---

# Step 5 - Analyze Successful SSH Logins

Successful authentication events were analyzed to understand legitimate remote access activity.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" index="main" event_type="Successful SSH Login"
| stats count by id.orig_h, id.resp_h
| sort -count
```

### Security Insight

Successful logins following several failed attempts may indicate compromised credentials. Correlating successful and failed authentication events is a common SOC investigation technique.

### Screenshot

> Successful Login Analysis
![alt text](image-3.png)

---

# Step 6 - Identify Unauthenticated SSH Connections

Not every SSH connection results in successful authentication. The following search identifies connection attempts where authentication was never completed.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" index="main"  event_type="Connection Without Authentication"
| stats count by id.orig_h
```
![alt text](image-4.png)

To visualize authentication trends over time, the following query was used.

```spl
source="ssh_logs_new.json" host="webserver" sourcetype="_json" index="main" event_type="Connection Without Authentication"
| timechart span=1h count
```

### Security Insight

Repeated SSH connections without authentication can indicate reconnaissance activity, automated scanning, or attackers probing exposed SSH services before launching authentication attacks.

### Screenshot

> Unauthenticated SSH Connections
![alt text](image-5.png)

---



# Dashboard Components

The following visualizations can be created using the collected SSH authentication data:

* Failed Login Attempts by Source IP
* Successful Logins by Source IP
* Authentication Events by Type
* Multiple Failed Authentication Attempts
* SSH Activity Timeline
* Top Destination Hosts

### Screenshot

> SSH Security Dashboard
![alt text](image-6.png)

---

# Key Findings

During the investigation:

* SSH authentication logs were successfully ingested into Splunk.
* Authentication events were categorized based on event type.
* Failed login attempts were grouped by source IP address.
* Repeated authentication failures were identified for further investigation.
* Successful logins were analyzed to establish normal authentication activity.
* Unauthenticated SSH connections were identified as potential reconnaissance events.

---

# Skills Demonstrated

* Splunk Enterprise
* Search Processing Language (SPL)
* Log Ingestion
* JSON Log Analysis
* SSH Authentication Monitoring
* Security Event Investigation
* Threat Detection
* Dashboard Development

---

# Key Takeaways

This project demonstrates how Splunk can be used to transform raw SSH authentication logs into actionable security insights. By validating log ingestion, writing SPL queries, and investigating authentication activity, I gained hands-on experience with core SOC analyst tasks such as monitoring remote access, identifying suspicious login behavior, and detecting brute-force attack patterns.

The techniques used in this project can be extended further by creating real-time alerts, correlating authentication events with other security logs, and mapping detections to the MITRE ATT&CK framework.
