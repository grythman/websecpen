# WebSecPen: Security Scanning Tool

## MVP Goal
The MVP enables authenticated users to scan a URL for SQLi/XSS vulnerabilities using OWASP ZAP, view results in a dashboard, and read an NLP-generated summary of findings.

### Features:
- User authentication
- URL scan input
- Scan initiation with OWASP ZAP
- Basic result display
- NLP summary of vulnerabilities using HuggingFace model

### Non-goals:
- Advanced admin features
- Complex analytics
- Extensive export options

### Success Criteria:
A user can log in, submit a URL, receive a scan report with an NLP-generated summary, and view results in the UI. 