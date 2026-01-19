# sql-incident-detection-lab

**SQL-Based Incident Detection Lab (Google Cybersecurity Certificate)**

This repository contains the advanced SQL queries and detailed documentation used to perform log analysis and incident detection, which is a core skill for Security Operations Center (SOC) roles.

**Project Goal**

To use SQL to parse large security datasets (authentication logs, system events) to quickly identify Indicators of Compromise (IOCs) such as brute-force attacks and lateral movement, thereby accelerating the detection and analysis phases of the Incident Response lifecycle.

**Tools and Frameworks**

- Database: SQL (Simulated via BigQuery/PostgreSQL structure)

- Framework: NIST Cybersecurity Framework (CSF) for Incident Response documentation

**Key Files**

- queries.sql: Contains the specific, commented SQL queries used for threat hunting.

- incident_response_report.md: Documentation detailing the containment and recovery steps applied in a simulated breach scenario.

**Detection Focus**

The queries focus on identifying anomalous user behavior, including:

1. Users attempting to log in multiple times (brute force).

2. Successful logins immediately following a high number of failures (credential stuffing).

3. Logins from geographically unusual or new IP addresses.
