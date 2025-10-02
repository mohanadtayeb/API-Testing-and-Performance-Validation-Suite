/**
 * Base Test Class for API Testing Framework
 * Provides common functionality and structure for all API tests
 */
class BaseTest {
  constructor(name, description = '') {
    this.name = name;
    this.description = description;
    this.results = [];
    this.startTime = null;
    this.endTime = null;
    this.status = 'PENDING';
    this.errors = [];
    this.warnings = [];
    this.data = {};
    this.tags = [];
  }

  /**
   * Setup method - called before test execution
   */
  async setup() {
    console.log(`🔧 Setting up test: ${this.name}`);
    this.startTime = Date.now();
    this.status = 'RUNNING';
  }

  /**
   * Cleanup method - called after test execution
   */
  async cleanup() {
    console.log(`🧹 Cleaning up test: ${this.name}`);
    this.endTime = Date.now();
  }

  /**
   * Main test execution method - to be overridden by subclasses
   */
  async execute() {
    throw new Error('execute() method must be implemented by subclass');
  }

  /**
   * Run the complete test lifecycle
   */
  async run() {
    try {
      await this.setup();
      await this.execute();
      
      if (this.errors.length === 0) {
        this.status = 'PASSED';
        console.log(`✅ Test passed: ${this.name}`);
      } else {
        this.status = 'FAILED';
        console.log(`❌ Test failed: ${this.name}`);
      }
    } catch (error) {
      this.status = 'ERROR';
      this.addError(error.message);
      console.log(`💥 Test error: ${this.name} - ${error.message}`);
    } finally {
      await this.cleanup();
    }

    return this.getResults();
  }

  /**
   * Add a test result
   */
  addResult(assertion, expected, actual, message = '') {
    const result = {
      assertion,
      expected,
      actual,
      passed: this.compareValues(expected, actual),
      message,
      timestamp: new Date().toISOString()
    };

    this.results.push(result);

    if (!result.passed) {
      this.addError(`Assertion failed: ${assertion}. Expected: ${expected}, Actual: ${actual}. ${message}`);
    }

    return result.passed;
  }

  /**
   * Add a test result with explicit condition
   */
  addResultWithCondition(assertion, passed, expected, actual, message = '') {
    const result = {
      assertion,
      expected,
      actual,
      passed,
      message,
      timestamp: new Date().toISOString()
    };

    this.results.push(result);

    if (!result.passed) {
      this.addError(`Assertion failed: ${assertion}. Expected: ${expected}, Actual: ${actual}. ${message}`);
    }

    return result.passed;
  }

  /**
   * Compare two values for equality
   */
  compareValues(expected, actual) {
    if (expected === actual) return true;
    
    // Deep object comparison
    if (typeof expected === 'object' && typeof actual === 'object') {
      return JSON.stringify(expected) === JSON.stringify(actual);
    }
    
    return false;
  }

  /**
   * Assert that a condition is true
   */
  assertTrue(condition, message = '') {
    return this.addResultWithCondition('assertTrue', condition === true, 'true', condition, message);
  }

  /**
   * Assert that a condition is false
   */
  assertFalse(condition, message = '') {
    return this.addResultWithCondition('assertFalse', condition === false, 'false', condition, message);
  }

  /**
   * Assert that two values are equal
   */
  assertEqual(expected, actual, message = '') {
    return this.addResult('assertEqual', expected, actual, message);
  }

  /**
   * Assert that two values are not equal
   */
  assertNotEqual(notExpected, actual, message = '') {
    return this.addResult('assertNotEqual', `not ${notExpected}`, actual, message);
  }

  /**
   * Assert that a value is null
   */
  assertNull(value, message = '') {
    const passed = value === null || value === undefined;
    return this.addResultWithCondition('assertNull', passed, 'null', value, message);
  }

  /**
   * Assert that a value is not null
   */
  assertNotNull(value, message = '') {
    const passed = value !== null && value !== undefined;
    return this.addResultWithCondition('assertNotNull', passed, 'not null', value, message);
  }

  /**
   * Assert that an array/object contains a value
   */
  assertContains(container, value, message = '') {
    let contains = false;
    
    if (Array.isArray(container)) {
      contains = container.includes(value);
    } else if (typeof container === 'object') {
      contains = Object.values(container).includes(value);
    } else if (typeof container === 'string') {
      contains = container.includes(value);
    }
    
    return this.addResultWithCondition('assertContains', contains, `contains ${value}`, container, message);
  }

  /**
   * Assert HTTP status code
   */
  assertStatusCode(response, expectedCode, message = '') {
    const actualCode = response.status || response.statusCode;
    return this.addResult('assertStatusCode', expectedCode, actualCode, message);
  }

  /**
   * Assert response time is within limit
   */
  assertResponseTime(response, maxTime, message = '') {
    const responseTime = response.responseTime || 0;
    const passed = responseTime <= maxTime;
    return this.addResultWithCondition('assertResponseTime', passed, `<= ${maxTime}ms`, `${responseTime}ms`, message);
  }

  /**
   * Assert that response contains specific headers
   */
  assertHeader(response, headerName, expectedValue = null, message = '') {
    const headers = response.headers || {};
    const headerValue = headers[headerName.toLowerCase()];
    
    if (expectedValue === null) {
      // Just check if header exists
      const exists = headerValue !== undefined;
      return this.addResult('assertHeader', `header ${headerName} exists`, exists, message);
    } else {
      // Check header value
      return this.addResult('assertHeader', expectedValue, headerValue, message);
    }
  }

  /**
   * Assert JSON response structure
   */
  assertJsonStructure(response, expectedStructure, message = '') {
    try {
      const jsonData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
      const hasStructure = this.validateJsonStructure(jsonData, expectedStructure);
      return this.addResultWithCondition('assertJsonStructure', hasStructure, 'valid structure', hasStructure, message);
    } catch (error) {
      return this.addResultWithCondition('assertJsonStructure', false, 'valid JSON', 'invalid JSON', message);
    }
  }

  /**
   * Validate JSON structure recursively
   */
  validateJsonStructure(data, structure) {
    for (const key in structure) {
      if (!data.hasOwnProperty(key)) {
        return false;
      }
      
      const expectedType = structure[key];
      const actualValue = data[key];
      
      if (typeof expectedType === 'string') {
        // Type check
        if (typeof actualValue !== expectedType) {
          return false;
        }
      } else if (typeof expectedType === 'object') {
        // Nested structure check
        if (!this.validateJsonStructure(actualValue, expectedType)) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Add an error to the test
   */
  addError(error) {
    this.errors.push({
      message: error,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Add a warning to the test
   */
  addWarning(warning) {
    this.warnings.push({
      message: warning,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Set test data
   */
  setData(key, value) {
    this.data[key] = value;
  }

  /**
   * Get test data
   */
  getData(key) {
    return this.data[key];
  }

  /**
   * Add tags to the test
   */
  addTag(tag) {
    if (!this.tags.includes(tag)) {
      this.tags.push(tag);
    }
  }

  /**
   * Check if test has specific tag
   */
  hasTag(tag) {
    return this.tags.includes(tag);
  }

  /**
   * Get test execution time
   */
  getExecutionTime() {
    if (this.startTime && this.endTime) {
      return this.endTime - this.startTime;
    }
    return 0;
  }

  /**
   * Get test results summary
   */
  getResults() {
    const totalAssertions = this.results.length;
    const passedAssertions = this.results.filter(r => r.passed).length;
    const failedAssertions = totalAssertions - passedAssertions;

    return {
      name: this.name,
      description: this.description,
      status: this.status,
      executionTime: this.getExecutionTime(),
      totalAssertions,
      passedAssertions,
      failedAssertions,
      successRate: totalAssertions > 0 ? (passedAssertions / totalAssertions) * 100 : 0,
      errors: this.errors,
      warnings: this.warnings,
      results: this.results,
      data: this.data,
      tags: this.tags,
      startTime: this.startTime,
      endTime: this.endTime,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generate a simple test report
   */
  generateReport() {
    const results = this.getResults();
    
    console.log(`\n📊 Test Report: ${this.name}`);
    console.log(`Status: ${results.status}`);
    console.log(`Execution Time: ${results.executionTime}ms`);
    console.log(`Assertions: ${results.passedAssertions}/${results.totalAssertions} passed (${results.successRate.toFixed(1)}%)`);
    
    if (results.errors.length > 0) {
      console.log(`Errors: ${results.errors.length}`);
      results.errors.forEach(error => {
        console.log(`  ❌ ${error.message}`);
      });
    }
    
    if (results.warnings.length > 0) {
      console.log(`Warnings: ${results.warnings.length}`);
      results.warnings.forEach(warning => {
        console.log(`  ⚠️ ${warning.message}`);
      });
    }
    
    return results;
  }
}

module.exports = BaseTest;