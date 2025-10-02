const fs = require('fs');
const path = require('path');
const { getInstance: getConfig } = require('../src/ConfigManager');

/**
 * Test Runner for API Testing Framework
 * Manages test execution, reporting, and result aggregation
 */
class TestRunner {
  constructor() {
    this.config = getConfig();
    this.tests = [];
    this.results = [];
    this.startTime = null;
    this.endTime = null;
    this.totalTests = 0;
    this.passedTests = 0;
    this.failedTests = 0;
    this.errorTests = 0;
  }

  /**
   * Add a test to the test suite
   */
  addTest(testClass, ...args) {
    if (typeof testClass === 'function') {
      this.tests.push({ testClass, args });
    } else {
      throw new Error('Test must be a class constructor');
    }
  }

  /**
   * Add multiple tests from directory
   */
  addTestsFromDirectory(directory) {
    const testFiles = fs.readdirSync(directory)
      .filter(file => file.endsWith('.js') && file.includes('Test'))
      .map(file => path.join(directory, file));

    testFiles.forEach(testFile => {
      try {
        const TestClass = require(testFile);
        this.addTest(TestClass);
      } catch (error) {
        console.error(`Failed to load test file ${testFile}: ${error.message}`);
      }
    });
  }

  /**
   * Filter tests by tags
   */
  filterTestsByTags(tags) {
    if (!tags || tags.length === 0) {
      return this.tests;
    }

    return this.tests.filter(({ testClass, args }) => {
      const testInstance = new testClass(...args);
      return tags.some(tag => testInstance.hasTag(tag));
    });
  }

  /**
   * Run all tests
   */
  async runTests(options = {}) {
    const { 
      tags = [], 
      parallel = false, 
      maxConcurrency = 5,
      generateReports = true,
      stopOnFailure = false 
    } = options;

    console.log('\n🚀 Starting API Test Suite Execution\n');
    
    this.startTime = Date.now();
    const testsToRun = this.filterTestsByTags(tags);
    
    if (testsToRun.length === 0) {
      console.log('❌ No tests found to run');
      return this.generateSummary();
    }

    console.log(`📋 Running ${testsToRun.length} test(s)${tags.length > 0 ? ` with tags: ${tags.join(', ')}` : ''}`);
    
    if (parallel) {
      await this.runTestsInParallel(testsToRun, maxConcurrency, stopOnFailure);
    } else {
      await this.runTestsSequentially(testsToRun, stopOnFailure);
    }

    this.endTime = Date.now();
    
    if (generateReports) {
      await this.generateReports();
    }

    return this.generateSummary();
  }

  /**
   * Run tests sequentially
   */
  async runTestsSequentially(tests, stopOnFailure) {
    for (const { testClass, args } of tests) {
      const testInstance = new testClass(...args);
      
      console.log(`\n🧪 Running: ${testInstance.name}`);
      
      try {
        const result = await testInstance.run();
        this.results.push(result);
        this.updateCounters(result);
        
        if (stopOnFailure && (result.status === 'FAILED' || result.status === 'ERROR')) {
          console.log('\n⏹️ Stopping execution due to test failure');
          break;
        }
      } catch (error) {
        console.error(`💥 Failed to run test ${testInstance.name}: ${error.message}`);
        this.errorTests++;
      }
    }
  }

  /**
   * Run tests in parallel with concurrency control
   */
  async runTestsInParallel(tests, maxConcurrency, stopOnFailure) {
    const executing = [];
    let stopped = false;

    for (const { testClass, args } of tests) {
      if (stopped) break;

      const testInstance = new testClass(...args);
      
      const promise = this.executeTest(testInstance)
        .then(result => {
          this.results.push(result);
          this.updateCounters(result);
          
          if (stopOnFailure && (result.status === 'FAILED' || result.status === 'ERROR')) {
            stopped = true;
          }
          
          return result;
        })
        .catch(error => {
          console.error(`💥 Failed to run test ${testInstance.name}: ${error.message}`);
          this.errorTests++;
        });

      executing.push(promise);

      if (executing.length >= maxConcurrency) {
        await Promise.race(executing);
        executing.splice(executing.findIndex(p => p === promise), 1);
      }
    }

    // Wait for remaining tests to complete
    await Promise.allSettled(executing);
  }

  /**
   * Execute a single test
   */
  async executeTest(testInstance) {
    console.log(`\n🧪 Running: ${testInstance.name}`);
    return await testInstance.run();
  }

  /**
   * Update test counters
   */
  updateCounters(result) {
    this.totalTests++;
    
    switch (result.status) {
      case 'PASSED':
        this.passedTests++;
        break;
      case 'FAILED':
        this.failedTests++;
        break;
      case 'ERROR':
        this.errorTests++;
        break;
    }
  }

  /**
   * Generate test reports
   */
  async generateReports() {
    const reportDir = this.config.getTestConfig().reportDir || './reports';
    
    // Ensure report directory exists
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    // Generate JSON report
    await this.generateJsonReport(reportDir);
    
    // Generate HTML report
    await this.generateHtmlReport(reportDir);
    
    // Generate JUnit XML report
    await this.generateJUnitReport(reportDir);
    
    console.log(`\n📊 Reports generated in: ${reportDir}`);
  }

  /**
   * Generate JSON report
   */
  async generateJsonReport(reportDir) {
    const report = {
      summary: this.generateSummary(),
      config: {
        environment: this.config.getEnvironment(),
        startTime: new Date(this.startTime).toISOString(),
        endTime: new Date(this.endTime).toISOString(),
        duration: this.endTime - this.startTime
      },
      results: this.results
    };

    const jsonPath = path.join(reportDir, 'test-results.json');
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
    console.log(`  ✅ JSON report: ${jsonPath}`);
  }

  /**
   * Generate HTML report
   */
  async generateHtmlReport(reportDir) {
    const htmlContent = this.generateHtmlContent();
    const htmlPath = path.join(reportDir, 'test-results.html');
    fs.writeFileSync(htmlPath, htmlContent);
    console.log(`  ✅ HTML report: ${htmlPath}`);
  }

  /**
   * Generate JUnit XML report
   */
  async generateJUnitReport(reportDir) {
    const xmlContent = this.generateJUnitXml();
    const xmlPath = path.join(reportDir, 'test-results.xml');
    fs.writeFileSync(xmlPath, xmlContent);
    console.log(`  ✅ JUnit XML report: ${xmlPath}`);
  }

  /**
   * Generate HTML report content
   */
  generateHtmlContent() {
    const summary = this.generateSummary();
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>API Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #2196F3; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2196F3; margin: 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; color: white; }
        .summary-card h3 { margin: 0 0 10px 0; }
        .summary-card p { margin: 0; font-size: 24px; font-weight: bold; }
        .total { background: #2196F3; }
        .passed { background: #4CAF50; }
        .failed { background: #F44336; }
        .error { background: #FF9800; }
        .duration { background: #9C27B0; }
        .success-rate { background: #607D8B; }
        .test-result { margin: 20px 0; padding: 20px; border-radius: 8px; border-left: 5px solid; }
        .test-result.PASSED { border-left-color: #4CAF50; background-color: #E8F5E8; }
        .test-result.FAILED { border-left-color: #F44336; background-color: #FFEBEE; }
        .test-result.ERROR { border-left-color: #FF9800; background-color: #FFF3E0; }
        .test-details { margin-top: 15px; font-size: 14px; }
        .assertion { margin: 5px 0; padding: 8px; border-radius: 4px; }
        .assertion.passed { background-color: #C8E6C9; }
        .assertion.failed { background-color: #FFCDD2; }
        .error-list { background-color: #FFECB3; padding: 10px; border-radius: 4px; margin-top: 10px; }
        .tags { margin-top: 10px; }
        .tag { display: inline-block; background: #E3F2FD; color: #1976D2; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧪 API Test Results</h1>
            <p>Generated on: ${new Date().toISOString()}</p>
            <p>Environment: ${this.config.getEnvironment()}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card total">
                <h3>Total Tests</h3>
                <p>${summary.totalTests}</p>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <p>${summary.passedTests}</p>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <p>${summary.failedTests}</p>
            </div>
            <div class="summary-card error">
                <h3>Errors</h3>
                <p>${summary.errorTests}</p>
            </div>
            <div class="summary-card duration">
                <h3>Duration</h3>
                <p>${(summary.duration / 1000).toFixed(1)}s</p>
            </div>
            <div class="summary-card success-rate">
                <h3>Success Rate</h3>
                <p>${summary.successRate.toFixed(1)}%</p>
            </div>
        </div>
        
        <h2>Test Results</h2>
        ${this.results.map(result => `
            <div class="test-result ${result.status}">
                <h3>${result.name}</h3>
                <p><strong>Status:</strong> ${result.status}</p>
                <p><strong>Duration:</strong> ${result.executionTime}ms</p>
                <p><strong>Assertions:</strong> ${result.passedAssertions}/${result.totalAssertions} passed</p>
                
                ${result.description ? `<p><strong>Description:</strong> ${result.description}</p>` : ''}
                
                ${result.tags.length > 0 ? `
                    <div class="tags">
                        <strong>Tags:</strong> ${result.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                ` : ''}
                
                ${result.errors.length > 0 ? `
                    <div class="error-list">
                        <strong>Errors:</strong>
                        <ul>
                            ${result.errors.map(error => `<li>${error.message}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                
                <div class="test-details">
                    <strong>Assertions:</strong>
                    ${result.results.map(assertion => `
                        <div class="assertion ${assertion.passed ? 'passed' : 'failed'}">
                            ${assertion.assertion}: ${assertion.passed ? '✅' : '❌'} 
                            ${assertion.message || ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('')}
    </div>
</body>
</html>`;
  }

  /**
   * Generate JUnit XML report
   */
  generateJUnitXml() {
    const summary = this.generateSummary();
    
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<testsuites name="API Test Suite" tests="${summary.totalTests}" failures="${summary.failedTests}" errors="${summary.errorTests}" time="${(summary.duration / 1000).toFixed(3)}">\n`;
    
    this.results.forEach(result => {
      xml += `  <testsuite name="${result.name}" tests="${result.totalAssertions}" failures="${result.failedAssertions}" time="${(result.executionTime / 1000).toFixed(3)}">\n`;
      
      result.results.forEach(assertion => {
        xml += `    <testcase name="${assertion.assertion}" time="0">\n`;
        if (!assertion.passed) {
          xml += `      <failure message="${assertion.message || 'Assertion failed'}">${assertion.assertion}: Expected ${assertion.expected}, but got ${assertion.actual}</failure>\n`;
        }
        xml += `    </testcase>\n`;
      });
      
      xml += `  </testsuite>\n`;
    });
    
    xml += `</testsuites>\n`;
    return xml;
  }

  /**
   * Generate test summary
   */
  generateSummary() {
    const duration = this.endTime - this.startTime;
    const successRate = this.totalTests > 0 ? (this.passedTests / this.totalTests) * 100 : 0;
    
    return {
      totalTests: this.totalTests,
      passedTests: this.passedTests,
      failedTests: this.failedTests,
      errorTests: this.errorTests,
      duration: duration,
      successRate: successRate,
      startTime: this.startTime,
      endTime: this.endTime
    };
  }

  /**
   * Print summary to console
   */
  printSummary() {
    const summary = this.generateSummary();
    
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST EXECUTION SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${summary.totalTests}`);
    console.log(`✅ Passed: ${summary.passedTests}`);
    console.log(`❌ Failed: ${summary.failedTests}`);
    console.log(`💥 Errors: ${summary.errorTests}`);
    console.log(`⏱️  Duration: ${(summary.duration / 1000).toFixed(1)} seconds`);
    console.log(`📈 Success Rate: ${summary.successRate.toFixed(1)}%`);
    console.log('='.repeat(60));
    
    if (summary.failedTests > 0 || summary.errorTests > 0) {
      console.log('\n❌ Some tests failed. Check the detailed reports for more information.');
    } else {
      console.log('\n🎉 All tests passed successfully!');
    }
  }

  /**
   * Run specific test methods
   */
  async runTestMethod(testClass, methodName, ...args) {
    const testInstance = new testClass(...args);
    
    if (typeof testInstance[methodName] !== 'function') {
      throw new Error(`Method ${methodName} not found in test class`);
    }
    
    console.log(`\n🧪 Running method: ${testInstance.name}.${methodName}`);
    
    await testInstance.setup();
    
    try {
      await testInstance[methodName]();
    } catch (error) {
      testInstance.addError(error.message);
    }
    
    await testInstance.cleanup();
    
    return testInstance.getResults();
  }
}

module.exports = TestRunner;