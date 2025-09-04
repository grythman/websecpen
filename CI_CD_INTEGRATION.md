# CI/CD Integration Guide

This document provides instructions for integrating WebSecPen security scanning into your CI/CD pipelines.

## GitHub Actions Integration

### Prerequisites

1. **API Key**: Obtain an API key from your WebSecPen dashboard
2. **Repository Secrets**: Add the following secrets to your GitHub repository:
   - `SECURESCAN_API_KEY`: Your WebSecPen API key
   - `SECURESCAN_BASE_URL`: Your WebSecPen instance URL (e.g., `https://your-backend.onrender.com`)
   - `TARGET_URL`: The URL to scan (optional, defaults to localhost)
   - `FAIL_ON_CRITICAL`: Set to "true" to fail builds on critical vulnerabilities (optional, defaults to true)

### Setup

1. Copy the provided GitHub Actions workflow file to `.github/workflows/security-scan.yml` in your repository
2. Configure the repository secrets mentioned above
3. Push your changes to trigger the workflow

### Workflow Features

- **Automatic Triggering**: Runs on push to main/develop branches, pull requests, and daily at 2 AM UTC
- **Build Integration**: Automatically builds your application before scanning
- **Result Artifacts**: Uploads scan results as build artifacts
- **PR Comments**: Automatically comments on pull requests with scan results
- **Failure Control**: Optionally fails builds when critical vulnerabilities are found

### API Endpoints for CI/CD

#### Start Scan
```bash
curl -X POST "${SECURESCAN_BASE_URL}/api/scan/start" \
  -H "X-API-Key: ${SECURESCAN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com",
    "scan_type": "active",
    "ci_cd": true,
    "github_context": {
      "repository": "owner/repo",
      "ref": "refs/heads/main",
      "sha": "commit-sha",
      "run_id": "12345"
    }
  }'
```

#### Check Scan Status
```bash
curl -X GET "${SECURESCAN_BASE_URL}/api/scan/status/${SCAN_ID}" \
  -H "X-API-Key: ${SECURESCAN_API_KEY}"
```

#### Get Scan Results
```bash
curl -X GET "${SECURESCAN_BASE_URL}/api/scan/result/${SCAN_ID}" \
  -H "X-API-Key: ${SECURESCAN_API_KEY}"
```

## Other CI/CD Platforms

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - |
      SCAN_RESPONSE=$(curl -s -X POST "${SECURESCAN_BASE_URL}/api/scan/start" \
        -H "X-API-Key: ${SECURESCAN_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"${TARGET_URL}\", \"scan_type\": \"active\"}")
      
      SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
      
      # Wait for completion and get results
      while true; do
        STATUS=$(curl -s "${SECURESCAN_BASE_URL}/api/scan/status/${SCAN_ID}" \
          -H "X-API-Key: ${SECURESCAN_API_KEY}" | jq -r '.status')
        
        if [ "$STATUS" = "completed" ]; then break; fi
        if [ "$STATUS" = "failed" ]; then exit 1; fi
        
        sleep 30
      done
      
      curl -s "${SECURESCAN_BASE_URL}/api/scan/result/${SCAN_ID}" \
        -H "X-API-Key: ${SECURESCAN_API_KEY}" > scan-results.json
        
  artifacts:
    reports:
      junit: scan-results.json
    when: always
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        SECURESCAN_API_KEY = credentials('securescan-api-key')
        SECURESCAN_BASE_URL = 'https://your-backend.onrender.com'
        TARGET_URL = 'https://your-app.com'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def scanResponse = sh(
                        script: """
                            curl -s -X POST "${SECURESCAN_BASE_URL}/api/scan/start" \
                              -H "X-API-Key: ${SECURESCAN_API_KEY}" \
                              -H "Content-Type: application/json" \
                              -d '{"url": "${TARGET_URL}", "scan_type": "active"}'
                        """,
                        returnStdout: true
                    ).trim()
                    
                    def scanData = readJSON text: scanResponse
                    def scanId = scanData.scan_id
                    
                    // Wait for completion
                    timeout(time: 30, unit: 'MINUTES') {
                        waitUntil {
                            def statusResponse = sh(
                                script: "curl -s '${SECURESCAN_BASE_URL}/api/scan/status/${scanId}' -H 'X-API-Key: ${SECURESCAN_API_KEY}'",
                                returnStdout: true
                            ).trim()
                            
                            def statusData = readJSON text: statusResponse
                            return statusData.status == 'completed'
                        }
                    }
                    
                    // Get results
                    sh """
                        curl -s "${SECURESCAN_BASE_URL}/api/scan/result/${scanId}" \
                          -H "X-API-Key: ${SECURESCAN_API_KEY}" > scan-results.json
                    """
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
                }
            }
        }
    }
}
```

## Configuration Options

### Scan Types
- `passive`: Fast, non-intrusive scanning
- `active`: Comprehensive scanning with active testing
- `api`: API-specific security testing

### Failure Conditions
You can configure when the CI/CD pipeline should fail:
- Critical vulnerabilities found
- High-severity vulnerabilities above threshold
- Total vulnerability count above limit

### Custom Headers
For applications requiring authentication:
```json
{
  "url": "https://your-app.com",
  "scan_type": "active",
  "headers": {
    "Authorization": "Bearer your-token",
    "X-Custom-Header": "value"
  }
}
```

## Best Practices

1. **Staging Environment**: Always scan staging environments, not production
2. **Regular Scans**: Schedule daily or weekly scans for comprehensive coverage
3. **Baseline Security**: Establish security baselines and track improvements
4. **Team Notifications**: Configure notifications for security teams
5. **Documentation**: Keep security scan results as part of your documentation

## Troubleshooting

### Common Issues

1. **API Key Invalid**: Ensure your API key is correctly set in repository secrets
2. **Network Timeout**: Increase timeout values for large applications
3. **Scan Failures**: Check application logs and ensure the target URL is accessible
4. **Result Parsing**: Verify JSON parsing in your CI/CD scripts

### Support

For additional support with CI/CD integration:
1. Check the API documentation at `/api/docs`
2. Review scan logs in the WebSecPen dashboard
3. Contact support with your scan ID for specific issues

## Security Considerations

1. **API Key Security**: Never expose API keys in logs or code
2. **Network Access**: Ensure CI/CD runners can access your WebSecPen instance
3. **Result Storage**: Securely store and manage scan result artifacts
4. **Access Control**: Limit API key permissions to CI/CD specific operations
