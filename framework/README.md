# API Testing Framework

A comprehensive test automation framework for API testing with support for functional testing, performance testing, and security testing.

## Features

- **Functional API Testing**: Test CRUD operations, authentication, data validation
- **Performance Testing**: Load, stress, and spike testing with K6
- **Security Testing**: SQL injection, XSS, authentication bypass testing
- **Test Automation Framework**: Reusable base classes and utilities
- **Multiple Report Formats**: HTML, JSON, JUnit XML
- **Parallel Test Execution**: Run tests concurrently for faster execution
- **Environment Management**: Support for multiple environments (dev, staging, prod)
- **Tag-based Filtering**: Run specific subsets of tests using tags

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd API-Testing-and-Performance-Validation-Suite
   ```

2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

3. **Install K6 for performance testing** (optional):
   ```bash
   # On Windows (using Chocolatey)
   choco install k6

   # On macOS (using Homebrew)
   brew install k6

   # On Linux
   sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
   echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
   sudo apt-get update
   sudo apt-get install k6
   ```

## Quick Start

### Running All Tests

```bash
# Run all tests with default settings
npm test

# Or use the test runner directly
node framework/run-tests.js
```

### Running Specific Test Suites

```bash
# Run only JSONPlaceholder tests
node framework/run-tests.js --tests jsonplaceholder

# Run only ReqRes tests
node framework/run-tests.js --tests reqres

# Run multiple specific test suites
node framework/run-tests.js --tests jsonplaceholder,reqres
```

### Running Tests with Tags

```bash
# Run tests tagged as 'smoke'
node framework/run-tests.js --tags smoke

# Run tests tagged as 'api' or 'integration'
node framework/run-tests.js --tags api,integration
```

### Running Tests in Different Environments

```bash
# Run tests in staging environment
node framework/run-tests.js --env staging

# Run tests in production environment
node framework/run-tests.js --env prod
```

### Parallel Test Execution

```bash
# Run tests in parallel with default concurrency (5)
node framework/run-tests.js --parallel

# Run tests in parallel with custom concurrency
node framework/run-tests.js --parallel --concurrency 10
```

## Test Suites

### 1. JSONPlaceholder API Tests

Tests the JSONPlaceholder API (https://jsonplaceholder.typicode.com):

- **Posts Management**: CRUD operations for posts
- **Users Management**: User data validation and retrieval
- **Comments Management**: Comment operations and validation
- **Data Validation**: Schema validation and data integrity checks

```bash
# Run JSONPlaceholder tests
npm run test:jsonplaceholder
```

### 2. ReqRes API Tests

Tests the ReqRes API (https://reqres.in):

- **Authentication**: Login and token validation
- **User Management**: User CRUD operations
- **Resource Management**: Resource data operations
- **Pagination**: List operations with pagination
- **Delayed Responses**: Testing timeout handling

```bash
# Run ReqRes tests
npm run test:reqres
```

## Performance Testing

### K6 Performance Tests

Run performance tests using K6:

```bash
# Load testing
npm run test:load

# Stress testing
npm run test:stress

# Spike testing
npm run test:spike
```

## Security Testing

Run security tests to check for common vulnerabilities:

```bash
# Run security tests
npm run test:security
```

Security tests include:
- SQL Injection attempts
- XSS payload testing
- Authentication bypass attempts
- Rate limiting validation
- Security headers verification

## Postman Collections

### Running Postman Collections

```bash
# Run JSONPlaceholder collection
npm run test:postman:jsonplaceholder

# Run ReqRes collection
npm run test:postman:reqres

# Run all Postman collections
npm run test:postman:all
```

### Collection Contents

- **JSONPlaceholder Collection**: Complete API testing for posts, users, comments
- **ReqRes Collection**: Authentication and user management testing
- **Environment Variables**: Dynamic data handling and token management

## Framework Usage

### Creating New Tests

1. **Extend the BaseTest class**:

```javascript
const BaseTest = require('../framework/src/BaseTest');

class MyApiTests extends BaseTest {
  constructor() {
    super('My API Tests', 'Tests for my custom API');
    this.addTag('api');
    this.addTag('custom');
  }

  async testGetUsers() {
    const response = await this.apiClient.get('/users');
    
    this.assertEquals(response.status, 200, 'Should return 200 status');
    this.assertTrue(Array.isArray(response.data), 'Should return array');
    this.assertGreaterThan(response.data.length, 0, 'Should have users');
  }

  async testCreateUser() {
    const userData = {
      name: 'Test User',
      email: 'test@example.com'
    };

    const response = await this.apiClient.post('/users', userData);
    
    this.assertEquals(response.status, 201, 'Should return 201 status');
    this.assertNotNull(response.data.id, 'Should return user ID');
    this.assertEquals(response.data.name, userData.name, 'Name should match');
  }
}

module.exports = MyApiTests;
```

2. **Add tests to the runner**:

```javascript
const TestRunner = require('./framework/src/TestRunner');
const MyApiTests = require('./tests/MyApiTests');

const runner = new TestRunner();
runner.addTest(MyApiTests);

runner.runTests().then(() => {
  runner.printSummary();
});
```

### Available Assertion Methods

- `assertEquals(actual, expected, message)`
- `assertNotEquals(actual, expected, message)`
- `assertTrue(condition, message)`
- `assertFalse(condition, message)`
- `assertNull(value, message)`
- `assertNotNull(value, message)`
- `assertGreaterThan(actual, expected, message)`
- `assertLessThan(actual, expected, message)`
- `assertContains(container, item, message)`
- `assertMatches(text, pattern, message)`

### Configuration Management

The framework supports multiple environments through configuration files:

```javascript
const { getInstance: getConfig } = require('./framework/src/ConfigManager');

const config = getConfig();

// Get current environment
const env = config.getEnvironment(); // 'dev', 'staging', 'prod'

// Get API configuration
const apiConfig = config.getApiConfig();
const baseUrl = apiConfig.jsonplaceholder.baseUrl;

// Get test configuration
const testConfig = config.getTestConfig();
const timeout = testConfig.timeout;
```

## Reporting

### Generated Reports

After test execution, reports are generated in the `reports/` directory:

- **HTML Report**: `test-results.html` - Interactive web report
- **JSON Report**: `test-results.json` - Machine-readable results
- **JUnit XML**: `test-results.xml` - CI/CD integration format

### Performance Reports

K6 performance tests generate HTML reports in the `reports/performance/` directory:

- Load test results with graphs and metrics
- Response time distributions
- Error rate analysis
- Custom metrics tracking

## CI/CD Integration

### GitHub Actions Example

```yaml
name: API Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: npm install
    
    - name: Run API tests
      run: npm test
    
    - name: Upload test results
      uses: actions/upload-artifact@v2
      with:
        name: test-results
        path: reports/
```

### Jenkins Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Install Dependencies') {
            steps {
                sh 'npm install'
            }
        }
        
        stage('Run Tests') {
            steps {
                sh 'npm test'
            }
        }
        
        stage('Publish Results') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'test-results.html',
                    reportName: 'Test Results'
                ])
                
                junit 'reports/test-results.xml'
            }
        }
    }
}
```

## Command Line Options

```bash
node framework/run-tests.js [options]

Options:
  -h, --help              Show help message
  -t, --tests <tests>     Comma-separated list of test suites to run
  --tags <tags>           Comma-separated list of tags to filter tests
  -e, --env <env>         Environment to run tests against
  -p, --parallel          Run tests in parallel
  -c, --concurrency <n>   Maximum number of concurrent tests
  --no-reports            Skip generating test reports
  --stop-on-failure       Stop execution when a test fails
```

## Troubleshooting

### Common Issues

1. **Connection Errors**:
   - Check your internet connection
   - Verify API endpoints are accessible
   - Check firewall settings

2. **Timeout Errors**:
   - Increase timeout values in configuration
   - Check network latency
   - Consider using retry mechanisms

3. **Authentication Failures**:
   - Verify API credentials
   - Check token expiration
   - Ensure proper environment configuration

### Debug Mode

Enable debug logging:

```bash
DEBUG=true node framework/run-tests.js
```

### Verbose Output

Run tests with verbose output:

```bash
node framework/run-tests.js --verbose
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support, please open an issue in the GitHub repository.