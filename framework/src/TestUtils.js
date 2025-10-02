/**
 * Utility functions for API testing
 */

/**
 * Generate random test data
 */
class DataGenerator {
  static randomString(length = 10) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  static randomEmail() {
    return `${this.randomString(8)}@${this.randomString(5)}.com`;
  }

  static randomPhoneNumber() {
    return `+1${Math.floor(Math.random() * 900000000) + 100000000}`;
  }

  static randomDate(startYear = 2000, endYear = 2024) {
    const start = new Date(startYear, 0, 1);
    const end = new Date(endYear, 11, 31);
    return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
  }

  static randomNumber(min = 1, max = 100) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  static randomBoolean() {
    return Math.random() < 0.5;
  }

  static randomArrayElement(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  static generateUser() {
    return {
      id: this.randomNumber(1, 1000),
      name: `${this.randomString(5)} ${this.randomString(7)}`,
      username: this.randomString(8),
      email: this.randomEmail(),
      phone: this.randomPhoneNumber(),
      website: `${this.randomString(10)}.com`,
      address: {
        street: `${this.randomNumber(100, 9999)} ${this.randomString(8)} St`,
        suite: `Apt ${this.randomNumber(1, 999)}`,
        city: this.randomString(10),
        zipcode: `${this.randomNumber(10000, 99999)}`,
        geo: {
          lat: (Math.random() * 180 - 90).toFixed(6),
          lng: (Math.random() * 360 - 180).toFixed(6)
        }
      },
      company: {
        name: `${this.randomString(8)} Corp`,
        catchPhrase: `${this.randomString(10)} solutions`,
        bs: `${this.randomString(5)} ${this.randomString(8)}`
      }
    };
  }

  static generatePost() {
    return {
      userId: this.randomNumber(1, 10),
      id: this.randomNumber(1, 1000),
      title: this.randomString(20),
      body: this.randomString(100)
    };
  }

  static generateComment() {
    return {
      postId: this.randomNumber(1, 100),
      id: this.randomNumber(1, 1000),
      name: this.randomString(15),
      email: this.randomEmail(),
      body: this.randomString(80)
    };
  }
}

/**
 * Data validation utilities
 */
class Validator {
  static isEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static isUrl(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  static isPhoneNumber(phone) {
    const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/;
    return phoneRegex.test(phone);
  }

  static isValidDate(date) {
    return date instanceof Date && !isNaN(date);
  }

  static isValidId(id) {
    return Number.isInteger(id) && id > 0;
  }

  static hasRequiredFields(obj, requiredFields) {
    return requiredFields.every(field => obj.hasOwnProperty(field) && obj[field] !== null && obj[field] !== undefined);
  }

  static isValidUser(user) {
    const required = ['id', 'name', 'username', 'email'];
    return this.hasRequiredFields(user, required) && 
           this.isValidId(user.id) && 
           this.isEmail(user.email);
  }

  static isValidPost(post) {
    const required = ['userId', 'id', 'title', 'body'];
    return this.hasRequiredFields(post, required) && 
           this.isValidId(post.userId) && 
           this.isValidId(post.id);
  }

  static isValidComment(comment) {
    const required = ['postId', 'id', 'name', 'email', 'body'];
    return this.hasRequiredFields(comment, required) && 
           this.isValidId(comment.postId) && 
           this.isValidId(comment.id) && 
           this.isEmail(comment.email);
  }
}

/**
 * Performance measurement utilities
 */
class PerformanceMetrics {
  constructor() {
    this.metrics = {};
    this.timers = {};
  }

  startTimer(name) {
    this.timers[name] = Date.now();
  }

  endTimer(name) {
    if (this.timers[name]) {
      const duration = Date.now() - this.timers[name];
      this.addMetric(name, duration);
      delete this.timers[name];
      return duration;
    }
    return null;
  }

  addMetric(name, value) {
    if (!this.metrics[name]) {
      this.metrics[name] = [];
    }
    this.metrics[name].push(value);
  }

  getMetric(name) {
    return this.metrics[name] || [];
  }

  getAverageMetric(name) {
    const values = this.getMetric(name);
    return values.length > 0 ? values.reduce((a, b) => a + b, 0) / values.length : 0;
  }

  getMinMetric(name) {
    const values = this.getMetric(name);
    return values.length > 0 ? Math.min(...values) : 0;
  }

  getMaxMetric(name) {
    const values = this.getMetric(name);
    return values.length > 0 ? Math.max(...values) : 0;
  }

  getPercentile(name, percentile) {
    const values = this.getMetric(name).sort((a, b) => a - b);
    if (values.length === 0) return 0;
    
    const index = Math.ceil((percentile / 100) * values.length) - 1;
    return values[Math.max(0, index)];
  }

  getAllMetrics() {
    const result = {};
    
    Object.keys(this.metrics).forEach(name => {
      result[name] = {
        count: this.metrics[name].length,
        average: this.getAverageMetric(name),
        min: this.getMinMetric(name),
        max: this.getMaxMetric(name),
        p50: this.getPercentile(name, 50),
        p90: this.getPercentile(name, 90),
        p95: this.getPercentile(name, 95),
        p99: this.getPercentile(name, 99)
      };
    });
    
    return result;
  }

  clear() {
    this.metrics = {};
    this.timers = {};
  }
}

/**
 * HTTP response utilities
 */
class ResponseUtils {
  static isSuccessStatus(status) {
    return status >= 200 && status < 300;
  }

  static isClientError(status) {
    return status >= 400 && status < 500;
  }

  static isServerError(status) {
    return status >= 500 && status < 600;
  }

  static getStatusCategory(status) {
    if (this.isSuccessStatus(status)) return 'success';
    if (this.isClientError(status)) return 'client_error';
    if (this.isServerError(status)) return 'server_error';
    return 'unknown';
  }

  static extractHeaders(response) {
    return response.headers || {};
  }

  static hasHeader(response, headerName) {
    const headers = this.extractHeaders(response);
    return Object.keys(headers).some(key => key.toLowerCase() === headerName.toLowerCase());
  }

  static getHeader(response, headerName) {
    const headers = this.extractHeaders(response);
    const key = Object.keys(headers).find(k => k.toLowerCase() === headerName.toLowerCase());
    return key ? headers[key] : null;
  }

  static isJsonResponse(response) {
    const contentType = this.getHeader(response, 'content-type');
    return contentType && contentType.includes('application/json');
  }

  static getResponseSize(response) {
    const contentLength = this.getHeader(response, 'content-length');
    if (contentLength) {
      return parseInt(contentLength, 10);
    }
    
    if (response.data && typeof response.data === 'string') {
      return Buffer.byteLength(response.data, 'utf8');
    }
    
    if (response.data) {
      return Buffer.byteLength(JSON.stringify(response.data), 'utf8');
    }
    
    return 0;
  }
}

/**
 * Test data helpers
 */
class TestDataHelper {
  constructor() {
    this.testData = new Map();
  }

  store(key, value) {
    this.testData.set(key, value);
  }

  retrieve(key) {
    return this.testData.get(key);
  }

  has(key) {
    return this.testData.has(key);
  }

  clear() {
    this.testData.clear();
  }

  getAllKeys() {
    return Array.from(this.testData.keys());
  }

  remove(key) {
    return this.testData.delete(key);
  }

  generateUniqueId() {
    return `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Wait utilities
 */
class WaitUtils {
  static async wait(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
  }

  static async waitForCondition(condition, maxWaitTime = 10000, checkInterval = 100) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      if (await condition()) {
        return true;
      }
      await this.wait(checkInterval);
    }
    
    return false;
  }

  static async retry(operation, maxRetries = 3, delayMs = 1000) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries) {
          throw lastError;
        }
        
        await this.wait(delayMs * attempt); // Exponential backoff
      }
    }
  }
}

/**
 * Security test utilities
 */
class SecurityUtils {
  static getSqlInjectionPayloads() {
    return [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
      "1' OR '1'='1' --",
      "admin'--",
      "' OR 1=1#",
      "') OR ('1'='1",
      "1; DELETE FROM users WHERE 1=1 --"
    ];
  }

  static getXssPayloads() {
    return [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>",
      "';alert('XSS');//",
      "<iframe src=javascript:alert('XSS')></iframe>",
      "<body onload=alert('XSS')>",
      "<script>document.location='http://evil.com'</script>"
    ];
  }

  static getPathTraversalPayloads() {
    return [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
      "....//....//....//etc/passwd",
      "..%252f..%252f..%252fetc%252fpasswd"
    ];
  }

  static isSecureHeader(headerName, headerValue) {
    const securityHeaders = {
      'x-frame-options': ['DENY', 'SAMEORIGIN'],
      'x-content-type-options': ['nosniff'],
      'x-xss-protection': ['1; mode=block'],
      'strict-transport-security': null, // Just check if present
      'content-security-policy': null,   // Just check if present
      'referrer-policy': ['no-referrer', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade']
    };

    const normalizedName = headerName.toLowerCase();
    
    if (!securityHeaders.hasOwnProperty(normalizedName)) {
      return false;
    }

    const expectedValues = securityHeaders[normalizedName];
    
    if (expectedValues === null) {
      return true; // Just check if header is present
    }

    return expectedValues.some(value => 
      headerValue.toLowerCase().includes(value.toLowerCase())
    );
  }
}

/**
 * Logger utility
 */
class Logger {
  constructor(level = 'INFO') {
    this.level = level;
    this.levels = {
      DEBUG: 0,
      INFO: 1,
      WARN: 2,
      ERROR: 3
    };
  }

  log(level, message, data = null) {
    if (this.levels[level] >= this.levels[this.level]) {
      const timestamp = new Date().toISOString();
      const logMessage = `[${timestamp}] ${level}: ${message}`;
      
      console.log(logMessage);
      
      if (data) {
        console.log(JSON.stringify(data, null, 2));
      }
    }
  }

  debug(message, data = null) {
    this.log('DEBUG', message, data);
  }

  info(message, data = null) {
    this.log('INFO', message, data);
  }

  warn(message, data = null) {
    this.log('WARN', message, data);
  }

  error(message, data = null) {
    this.log('ERROR', message, data);
  }
}

module.exports = {
  DataGenerator,
  Validator,
  PerformanceMetrics,
  ResponseUtils,
  TestDataHelper,
  WaitUtils,
  SecurityUtils,
  Logger
};