# VulnScan Lite - Scanning Logic Documentation

## Overview
VulnScan Lite is a passive web vulnerability scanner. It inspects a target website without performing aggressive exploitation, brute force, or intrusive penetration testing.

The scanner provides a security health report based on:
- security headers
- SSL/TLS configuration
- CMS detection clues
- a score and grade
- remediation guidance

---

## Passive Analysis Disclaimer
This tool performs passive analysis only. It is intended to scan websites that the user owns or is authorized to test.

It does **not**:
- brute-force logins
- exploit vulnerabilities
- inject payloads into forms
- perform active penetration testing
- run destructive probes

---

## Header Analysis
The scanner checks for the presence of the following security headers:

### 1. Content-Security-Policy
Purpose:
- helps reduce XSS and content injection risks

Pass condition:
- header exists in the HTTP response

Fail condition:
- header is missing

### 2. X-Frame-Options
Purpose:
- helps prevent clickjacking

Pass condition:
- header exists in the HTTP response

Fail condition:
- header is missing

### 3. Strict-Transport-Security
Purpose:
- forces browsers to prefer HTTPS

Pass condition:
- header exists in the HTTP response

Fail condition:
- header is missing

### Header Scoring
For each required header:
- present = +10
- missing = -10

---

## SSL/TLS Inspection
The scanner checks HTTPS and TLS details using Python's SSL and socket libraries.

### Checks performed

#### 1. HTTPS Usage
Pass:
- target uses HTTPS

Fail:
- target does not use HTTPS

#### 2. Certificate Expiration
Pass:
- certificate is valid and not near expiration

Warning/Fail:
- certificate expires soon

Fail:
- certificate is already expired

#### 3. Cipher Strength
Pass:
- strong cipher in use

Fail:
- weak cipher detected

#### 4. Certificate Issuer
Informational:
- issuer details are captured for visibility

### SSL/TLS Scoring
- HTTPS enabled = positive score
- valid certificate = positive score
- strong cipher = positive score
- expired/weak/misconfigured TLS = negative score

---

## CMS Detection
The scanner performs lightweight CMS fingerprinting using passive clues.

### Detection sources

#### 1. HTML meta generator tag
Examples:
- WordPress
- Drupal
- Joomla

#### 2. X-Powered-By header
Examples:
- PHP
- ASP.NET
- Express

#### 3. Common HTML/path fingerprints
Examples:
- `wp-content`
- `wp-includes`
- `/sites/default/`

### CMS Version Exposure
If a generator tag exposes a version number, the scanner reports that the CMS version may be publicly exposed.

---

## Outdated CMS Detection
The scanner can flag CMS versions as potentially outdated when:
- a version is exposed
- the version is below the configured baseline for that CMS

This is a passive approximation and should be treated as an advisory signal, not a definitive vulnerability statement.

---

## Scoring Logic
The scanner combines scores from:
- header checks
- SSL/TLS checks
- CMS detection checks

### Final score
A base score is adjusted up or down according to findings, then normalized to a 0-100 scale.

### Grade mapping
- 90+ = A+
- 80-89 = A
- 70-79 = B+
- 60-69 = B
- 50-59 = C
- 40-49 = D
- below 40 = F

---

## Reporting
The scanner returns:
- overall score
- grade
- passed checks
- failed checks
- detailed findings
- remediation guidance

The UI also shows:
- a gauge score visualization
- per-user scan history
- score improvement over time
- downloadable PDF report

---

## Rate Limiting
The backend uses rate limiting to reduce abuse risk. This limits:
- scan creation frequency
- repeated result/status requests
- excessive history access

---

## Limitations
VulnScan Lite is designed for safe, passive inspection. As a result:

- it may not always detect hidden technologies
- CMS detection may be approximate
- outdated version detection depends on publicly exposed version clues
- it does not confirm exploitability
- it should not be treated as a full penetration test