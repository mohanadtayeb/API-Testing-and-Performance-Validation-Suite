# Performance Testing Guide

## 📊 Overview

This guide provides comprehensive information about performance testing implementation using K6 for the API Testing & Performance Validation Suite. Our performance testing strategy ensures APIs can handle expected load and identify performance bottlenecks.

## 🎯 Performance Testing Objectives

### Primary Goals
- **Validate Response Times** - Ensure APIs respond within acceptable timeframes
- **Assess Throughput** - Measure maximum requests per second capacity
- **Identify Bottlenecks** - Pinpoint performance limitations
- **Verify Scalability** - Test system behavior under increasing load
- **Ensure Reliability** - Validate system stability under stress

### Key Performance Indicators (KPIs)
- **Response Time**: P95 < 500ms target
- **Throughput**: > 100 requests/second
- **Error Rate**: < 1% under normal load
- **Availability**: 99.9% uptime target

## 🛠️ Tool Stack

### K6 Performance Testing
- **Version**: Latest stable release
- **Language**: JavaScript ES6+
- **Reporting**: HTML, JSON, and console outputs
- **Metrics**: Built-in and custom metrics collection

### Installation & Setup
```bash
# Windows (Chocolatey)
choco install k6

# Windows (Direct download)
winget install k6

# Verify installation
k6 version
```

## 📋 Test Types Implementation

### 1. Load Testing
**Purpose**: Validate normal expected load performance

```javascript
// Configuration
export let options = {
  stages: [
    { duration: '2m', target: 20 },    // Ramp up
    { duration: '5m', target: 20 },    // Stay at 20 users
    { duration: '2m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.05'],
  },
};
```

**Execution**: `npm run performance:k6`

### 2. Stress Testing
**Purpose**: Test beyond normal capacity to find breaking point

```javascript
// Configuration
export let options = {
  stages: [
    { duration: '2m', target: 10 },    // Warm up
    { duration: '5m', target: 50 },    // High load
    { duration: '2m', target: 80 },    // Peak load
    { duration: '5m', target: 80 },    // Sustained peak
    { duration: '2m', target: 0 },     // Cool down
  ],
};
```

**Execution**: `npm run performance:k6-stress`

### 3. Spike Testing
**Purpose**: Test sudden traffic spikes and recovery

```javascript
// Configuration
export let options = {
  stages: [
    { duration: '1m', target: 10 },    // Normal load
    { duration: '30s', target: 100 },  // Spike!
    { duration: '1m', target: 10 },    // Recovery
    { duration: '30s', target: 200 },  // Bigger spike!
    { duration: '1m', target: 10 },    // Recovery
  ],
};
```

**Execution**: `npm run performance:k6-spike`

## 📊 Performance Metrics

### Core Metrics Collected

#### Response Time Metrics
- **http_req_duration**: Total request duration
- **http_req_connecting**: Connection establishment time
- **http_req_sending**: Request sending time
- **http_req_receiving**: Response receiving time

#### Throughput Metrics
- **http_reqs**: Total HTTP requests made
- **iterations**: Total test iterations completed
- **data_received**: Total data received
- **data_sent**: Total data sent

#### Error Metrics
- **http_req_failed**: Failed request rate
- **checks**: Custom validation checks
- **errors**: Custom error tracking

### Custom Metrics Implementation
```javascript
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
let apiErrors = new Counter('api_errors');
let apiSuccessRate = new Rate('api_success_rate');
let customResponseTime = new Trend('custom_response_time');

// Usage in tests
export default function () {
  let response = http.get('https://api.example.com/users');
  
  // Track custom metrics
  if (response.status !== 200) {
    apiErrors.add(1);
  }
  
  apiSuccessRate.add(response.status === 200);
  customResponseTime.add(response.timings.duration);
}
```

## 🎯 Test Scenarios

### Scenario 1: JSONPlaceholder API Testing
```javascript
export default function () {
  // Test different endpoints
  group('JSONPlaceholder API', function () {
    // Get all posts
    let posts = http.get('https://jsonplaceholder.typicode.com/posts');
    check(posts, {
      'status is 200': (r) => r.status === 200,
      'response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    // Get single post
    let post = http.get('https://jsonplaceholder.typicode.com/posts/1');
    check(post, {
      'post has title': (r) => JSON.parse(r.body).title !== undefined,
    });
    
    // Create new post
    let payload = JSON.stringify({
      title: 'Performance Test Post',
      body: 'Testing API performance',
      userId: 1,
    });
    
    let createResponse = http.post(
      'https://jsonplaceholder.typicode.com/posts',
      payload,
      { headers: { 'Content-Type': 'application/json' } }
    );
    
    check(createResponse, {
      'create status is 201': (r) => r.status === 201,
    });
  });
  
  sleep(1); // Think time between iterations
}
```

### Scenario 2: Multi-API Testing
```javascript
export default function () {
  // Test multiple APIs in sequence
  
  // JSONPlaceholder
  http.get('https://jsonplaceholder.typicode.com/users');
  
  // ReqRes API
  http.get('https://reqres.in/api/users?page=1');
  
  // Postman Echo
  http.get('https://postman-echo.com/get?foo=bar');
  
  sleep(Math.random() * 2); // Random think time
}
```

## 📈 Performance Thresholds

### Threshold Configuration
```javascript
export let options = {
  thresholds: {
    // Response time thresholds
    http_req_duration: [
      'p(95)<500',      // 95% of requests under 500ms
      'p(99)<1000',     // 99% of requests under 1000ms
      'max<5000'        // No request over 5 seconds
    ],
    
    // Error rate thresholds
    http_req_failed: ['rate<0.05'],    // Less than 5% failure rate
    
    // Custom thresholds
    'api_success_rate': ['rate>0.95'], // 95% success rate
    'api_errors': ['count<10'],        // Less than 10 errors total
    
    // Throughput thresholds
    http_reqs: ['rate>10'],            // At least 10 req/sec
  },
};
```

### Threshold Interpretation
- **Green**: All thresholds passed ✅
- **Red**: One or more thresholds failed ❌
- **Performance Score**: Based on threshold compliance

## 📊 Reporting and Analysis

### Report Formats

#### 1. Console Output
```bash
# Real-time metrics during test execution
✓ JSONPlaceholder - Get posts status is 200
✗ JSONPlaceholder - Get posts response time < 1000ms
```

#### 2. JSON Report
```javascript
// Structured data for integration
{
  "metrics": {
    "http_req_duration": {
      "avg": 345.67,
      "p95": 456.78,
      "max": 1234.56
    }
  }
}
```

#### 3. HTML Report
```javascript
// Visual dashboard with charts and graphs
export function handleSummary(data) {
  return {
    'reports/k6-performance-report.html': htmlReport(data),
    'reports/k6-performance-data.json': JSON.stringify(data),
  };
}
```

### Key Performance Insights

#### Response Time Analysis
- **Average Response Time**: Overall performance indicator
- **P95 Response Time**: 95th percentile (most users' experience)
- **P99 Response Time**: 99th percentile (worst-case scenarios)
- **Max Response Time**: Peak response time encountered

#### Throughput Analysis
- **Requests/Second**: System capacity measurement
- **Data Transfer Rate**: Network utilization
- **Concurrent Users**: Scalability assessment

#### Error Analysis
- **Error Rate**: System reliability indicator
- **Error Types**: Classification of failures
- **Error Patterns**: Time-based error distribution

## 🚀 Best Practices

### Test Design
1. **Realistic Load Patterns** - Mirror production traffic
2. **Gradual Load Increase** - Avoid system shock
3. **Proper Think Time** - Simulate user behavior
4. **Data Variation** - Use different test data sets

### Execution Guidelines
1. **Environment Isolation** - Dedicated test environment
2. **Resource Monitoring** - Track system resources
3. **Baseline Establishment** - Compare against benchmarks
4. **Regular Execution** - Continuous performance validation

### Analysis and Reporting
1. **Trend Analysis** - Track performance over time
2. **Comparative Analysis** - Before/after comparisons
3. **Root Cause Analysis** - Investigate performance issues
4. **Actionable Insights** - Provide improvement recommendations

## 🔧 Troubleshooting

### Common Issues

#### High Response Times
```javascript
// Check for:
- Network latency issues
- Server resource constraints
- Database performance problems
- External service dependencies
```

#### High Error Rates
```javascript
// Investigate:
- Rate limiting triggers
- Authentication failures
- Server capacity limits
- Invalid test data
```

#### Inconsistent Results
```javascript
// Consider:
- System resource availability
- Network stability
- Test environment consistency
- Concurrent test execution
```

### Performance Optimization Tips

1. **Connection Pooling** - Reuse HTTP connections
2. **Batch Requests** - Reduce individual request overhead
3. **Caching Strategy** - Implement appropriate caching
4. **Load Balancing** - Distribute traffic effectively

## 📝 Execution Commands

```bash
# Run all performance tests
npm run test:performance

# Individual test execution
npm run performance:k6        # Load test
npm run performance:k6-stress # Stress test
npm run performance:k6-spike  # Spike test

# Custom K6 execution
k6 run --vus 50 --duration 5m performance/k6/load-test.js

# Generate reports
k6 run --out json=reports/results.json performance/k6/load-test.js
```

## 📊 Performance Testing Results Summary

### Latest Test Results
- **Total Requests**: 16,596
- **Success Rate**: 77.8%
- **Average Response Time**: 649.55ms
- **P95 Response Time**: 1.38s
- **Throughput**: 17.26 req/sec
- **Test Duration**: 16 minutes

### Performance Score: **B+ (78%)**
*Areas for improvement: Response time optimization and error handling*

---

**Document Version:** 1.0  
**Last Updated:** October 2025  
**Next Review:** Monthly  
**Owner:** Performance Engineering Team