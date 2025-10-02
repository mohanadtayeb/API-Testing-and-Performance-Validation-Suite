const axios = require('axios');
const https = require('https');

/**
 * Base API Client class providing common functionality for API testing
 */
class ApiClient {
  constructor(config = {}) {
    this.baseURL = config.baseURL || '';
    this.timeout = config.timeout || 10000;
    this.retryAttempts = config.retryAttempts || 3;
    this.retryDelay = config.retryDelay || 1000;
    this.defaultHeaders = config.headers || {};
    
    // Configure axios instance
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: this.timeout,
      headers: this.defaultHeaders,
      // Allow self-signed certificates for testing
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      })
    });

    // Setup interceptors
    this.setupInterceptors();
  }

  setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: Date.now() };
        console.log(`📤 ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        console.error('❌ Request Error:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        const endTime = Date.now();
        const duration = endTime - response.config.metadata.startTime;
        console.log(`📥 ${response.status} ${response.config.method?.toUpperCase()} ${response.config.url} (${duration}ms)`);
        
        // Add custom properties to response
        response.responseTime = duration;
        response.timestamp = new Date().toISOString();
        
        return response;
      },
      (error) => {
        const endTime = Date.now();
        const duration = error.config ? endTime - error.config.metadata?.startTime : 0;
        console.error(`❌ ${error.response?.status || 'ERROR'} ${error.config?.method?.toUpperCase()} ${error.config?.url} (${duration}ms)`);
        
        if (error.response) {
          error.response.responseTime = duration;
          error.response.timestamp = new Date().toISOString();
        }
        
        return Promise.reject(error);
      }
    );
  }

  /**
   * GET request with retry logic
   */
  async get(endpoint, config = {}) {
    return this.executeWithRetry('get', endpoint, null, config);
  }

  /**
   * POST request with retry logic
   */
  async post(endpoint, data = null, config = {}) {
    return this.executeWithRetry('post', endpoint, data, config);
  }

  /**
   * PUT request with retry logic
   */
  async put(endpoint, data = null, config = {}) {
    return this.executeWithRetry('put', endpoint, data, config);
  }

  /**
   * PATCH request with retry logic
   */
  async patch(endpoint, data = null, config = {}) {
    return this.executeWithRetry('patch', endpoint, data, config);
  }

  /**
   * DELETE request with retry logic
   */
  async delete(endpoint, config = {}) {
    return this.executeWithRetry('delete', endpoint, null, config);
  }

  /**
   * Execute request with retry logic
   */
  async executeWithRetry(method, endpoint, data = null, config = {}, attempt = 1) {
    try {
      let response;
      
      if (data) {
        response = await this.client[method](endpoint, data, config);
      } else {
        response = await this.client[method](endpoint, config);
      }
      
      return response;
    } catch (error) {
      if (attempt < this.retryAttempts && this.shouldRetry(error)) {
        console.log(`🔄 Retrying request (attempt ${attempt + 1}/${this.retryAttempts})`);
        await this.delay(this.retryDelay * attempt);
        return this.executeWithRetry(method, endpoint, data, config, attempt + 1);
      }
      
      throw error;
    }
  }

  /**
   * Determine if request should be retried
   */
  shouldRetry(error) {
    if (!error.response) {
      // Network errors should be retried
      return true;
    }
    
    // Retry on server errors (5xx) but not client errors (4xx)
    return error.response.status >= 500;
  }

  /**
   * Delay helper for retry logic
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Set authentication token
   */
  setAuthToken(token) {
    this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  /**
   * Remove authentication token
   */
  removeAuthToken() {
    delete this.client.defaults.headers.common['Authorization'];
  }

  /**
   * Set custom header
   */
  setHeader(name, value) {
    this.client.defaults.headers.common[name] = value;
  }

  /**
   * Remove custom header
   */
  removeHeader(name) {
    delete this.client.defaults.headers.common[name];
  }

  /**
   * Health check endpoint
   */
  async healthCheck() {
    try {
      const response = await this.get('/health');
      return {
        status: 'healthy',
        responseTime: response.responseTime,
        timestamp: response.timestamp
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Batch requests with concurrency control
   */
  async batchRequests(requests, concurrency = 5) {
    const results = [];
    const executing = [];

    for (const request of requests) {
      const promise = this.executeRequest(request);
      results.push(promise);

      if (requests.length >= concurrency) {
        executing.push(promise);

        if (executing.length >= concurrency) {
          await Promise.race(executing);
          executing.splice(executing.findIndex(p => p === promise), 1);
        }
      }
    }

    return Promise.allSettled(results);
  }

  /**
   * Execute a single request from batch
   */
  async executeRequest(request) {
    const { method, endpoint, data, config } = request;
    
    switch (method.toLowerCase()) {
      case 'get':
        return this.get(endpoint, config);
      case 'post':
        return this.post(endpoint, data, config);
      case 'put':
        return this.put(endpoint, data, config);
      case 'patch':
        return this.patch(endpoint, data, config);
      case 'delete':
        return this.delete(endpoint, config);
      default:
        throw new Error(`Unsupported HTTP method: ${method}`);
    }
  }

  /**
   * Upload file
   */
  async uploadFile(endpoint, filePath, fieldName = 'file', additionalData = {}) {
    const FormData = require('form-data');
    const fs = require('fs');
    
    const form = new FormData();
    form.append(fieldName, fs.createReadStream(filePath));
    
    // Add additional form data
    Object.keys(additionalData).forEach(key => {
      form.append(key, additionalData[key]);
    });

    return this.post(endpoint, form, {
      headers: {
        ...form.getHeaders(),
        'Content-Type': 'multipart/form-data'
      }
    });
  }

  /**
   * Download file
   */
  async downloadFile(endpoint, outputPath) {
    const response = await this.get(endpoint, {
      responseType: 'stream'
    });

    const fs = require('fs');
    const writer = fs.createWriteStream(outputPath);
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', resolve);
      writer.on('error', reject);
    });
  }

  /**
   * Performance test helper
   */
  async performanceTest(endpoint, options = {}) {
    const {
      method = 'GET',
      data = null,
      iterations = 10,
      concurrency = 1,
      warmupIterations = 2
    } = options;

    console.log(`🏃 Running performance test: ${iterations} iterations, concurrency: ${concurrency}`);

    // Warmup requests
    console.log('🔥 Warming up...');
    for (let i = 0; i < warmupIterations; i++) {
      await this.executeRequest({ method, endpoint, data });
    }

    // Actual test
    console.log('⏱️ Starting performance test...');
    const startTime = Date.now();
    const promises = [];

    for (let i = 0; i < iterations; i++) {
      if (concurrency === 1) {
        // Sequential execution
        const response = await this.executeRequest({ method, endpoint, data });
        promises.push(Promise.resolve(response));
      } else {
        // Concurrent execution
        promises.push(this.executeRequest({ method, endpoint, data }));
      }
    }

    const results = await Promise.allSettled(promises);
    const endTime = Date.now();

    // Calculate statistics
    const successful = results.filter(r => r.status === 'fulfilled');
    const failed = results.filter(r => r.status === 'rejected');
    const responseTimes = successful.map(r => r.value.responseTime);

    return {
      totalTime: endTime - startTime,
      totalRequests: iterations,
      successfulRequests: successful.length,
      failedRequests: failed.length,
      successRate: (successful.length / iterations) * 100,
      averageResponseTime: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length,
      minResponseTime: Math.min(...responseTimes),
      maxResponseTime: Math.max(...responseTimes),
      requestsPerSecond: (successful.length / (endTime - startTime)) * 1000,
      responseTimes: responseTimes
    };
  }
}

module.exports = ApiClient;