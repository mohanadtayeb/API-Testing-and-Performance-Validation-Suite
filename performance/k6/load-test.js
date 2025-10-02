import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
export const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '2m', target: 10 }, // Ramp up to 10 users over 2 minutes
    { duration: '5m', target: 10 }, // Stay at 10 users for 5 minutes
    { duration: '2m', target: 20 }, // Ramp up to 20 users over 2 minutes
    { duration: '5m', target: 20 }, // Stay at 20 users for 5 minutes
    { duration: '2m', target: 0 },  // Ramp down to 0 users over 2 minutes
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.05'],   // Error rate should be less than 5%
    errors: ['rate<0.1'],             // Custom error rate should be less than 10%
  },
};

// Test data
const baseUrls = {
  jsonplaceholder: 'https://jsonplaceholder.typicode.com',
  reqres: 'https://reqres.in/api',
  postmanEcho: 'https://postman-echo.com'
};

export default function() {
  // Test JSONPlaceholder API
  testJSONPlaceholder();
  
  // Test ReqRes API
  testReqResAPI();
  
  // Test Postman Echo API
  testPostmanEcho();
  
  sleep(1); // Wait 1 second between iterations
}

function testJSONPlaceholder() {
  const group_name = 'JSONPlaceholder API Tests';
  
  // Get all posts
  let response = http.get(`${baseUrls.jsonplaceholder}/posts`);
  let success = check(response, {
    'JSONPlaceholder - Get posts status is 200': (r) => r.status === 200,
    'JSONPlaceholder - Get posts response time < 1000ms': (r) => r.timings.duration < 1000,
    'JSONPlaceholder - Posts response is array': (r) => {
      try {
        const data = JSON.parse(r.body);
        return Array.isArray(data);
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Get specific post
  response = http.get(`${baseUrls.jsonplaceholder}/posts/1`);
  success = check(response, {
    'JSONPlaceholder - Get single post status is 200': (r) => r.status === 200,
    'JSONPlaceholder - Single post has required fields': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.hasOwnProperty('id') && data.hasOwnProperty('title') && data.hasOwnProperty('body');
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Create new post
  const postData = {
    title: 'Performance Test Post',
    body: 'This post was created during performance testing',
    userId: 1
  };
  
  response = http.post(`${baseUrls.jsonplaceholder}/posts`, JSON.stringify(postData), {
    headers: { 'Content-Type': 'application/json' }
  });
  success = check(response, {
    'JSONPlaceholder - Create post status is 201': (r) => r.status === 201,
    'JSONPlaceholder - Created post has ID': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.hasOwnProperty('id');
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
}

function testReqResAPI() {
  // Get users with pagination
  let response = http.get(`${baseUrls.reqres}/users?page=1`);
  let success = check(response, {
    'ReqRes - Get users status is 200': (r) => r.status === 200,
    'ReqRes - Users response has pagination': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.hasOwnProperty('page') && data.hasOwnProperty('total_pages');
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Get specific user
  response = http.get(`${baseUrls.reqres}/users/2`);
  success = check(response, {
    'ReqRes - Get single user status is 200': (r) => r.status === 200,
    'ReqRes - User has email field': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.data && data.data.hasOwnProperty('email');
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Test authentication
  const loginData = {
    email: 'eve.holt@reqres.in',
    password: 'cityslicka'
  };
  
  response = http.post(`${baseUrls.reqres}/login`, JSON.stringify(loginData), {
    headers: { 'Content-Type': 'application/json' }
  });
  success = check(response, {
    'ReqRes - Login status is 200': (r) => r.status === 200,
    'ReqRes - Login returns token': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.hasOwnProperty('token');
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
}

function testPostmanEcho() {
  // Test GET request
  let response = http.get(`${baseUrls.postmanEcho}/get?test=performance`);
  let success = check(response, {
    'Postman Echo - GET status is 200': (r) => r.status === 200,
    'Postman Echo - GET echoes query params': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.args && data.args.test === 'performance';
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Test POST request
  const postData = {
    message: 'Performance test data',
    timestamp: Date.now()
  };
  
  response = http.post(`${baseUrls.postmanEcho}/post`, JSON.stringify(postData), {
    headers: { 'Content-Type': 'application/json' }
  });
  success = check(response, {
    'Postman Echo - POST status is 200': (r) => r.status === 200,
    'Postman Echo - POST echoes data': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.data && data.data.message === 'Performance test data';
      } catch (e) {
        return false;
      }
    }
  });
  errorRate.add(!success);
  
  // Test status codes
  response = http.get(`${baseUrls.postmanEcho}/status/200`);
  success = check(response, {
    'Postman Echo - Status 200 test': (r) => r.status === 200
  });
  errorRate.add(!success);
}

export function handleSummary(data) {
  return {
    'reports/k6-load-test-summary.json': JSON.stringify(data, null, 2),
    'reports/k6-load-test-summary.html': generateHTMLReport(data),
  };
}

function generateHTMLReport(data) {
  const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>K6 Load Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .metric { margin: 10px 0; padding: 10px; background-color: #f5f5f5; border-radius: 5px; }
        .pass { color: green; }
        .fail { color: red; }
        .summary { display: flex; justify-content: space-between; flex-wrap: wrap; }
        .summary-item { flex: 1; margin: 10px; padding: 20px; background-color: #e8f4f8; border-radius: 8px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>K6 Load Test Report</h1>
        <p>Generated on: ${new Date().toISOString()}</p>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <h3>Total Requests</h3>
            <p>${data.metrics.http_reqs.count}</p>
        </div>
        <div class="summary-item">
            <h3>Failed Requests</h3>
            <p>${data.metrics.http_req_failed.count}</p>
        </div>
        <div class="summary-item">
            <h3>Average Response Time</h3>
            <p>${data.metrics.http_req_duration.avg.toFixed(2)}ms</p>
        </div>
        <div class="summary-item">
            <h3>95th Percentile</h3>
            <p>${data.metrics.http_req_duration['p(95)'].toFixed(2)}ms</p>
        </div>
    </div>
    
    <div class="metric">
        <h3>Test Results Summary</h3>
        <p>Duration: ${data.state.testRunDurationMs}ms</p>
        <p>VUs: ${data.metrics.vus.max}</p>
        <p>Iterations: ${data.metrics.iterations.count}</p>
    </div>
    
    <div class="metric">
        <h3>HTTP Metrics</h3>
        <ul>
            <li>HTTP Request Duration (avg): ${data.metrics.http_req_duration.avg.toFixed(2)}ms</li>
            <li>HTTP Request Duration (p95): ${data.metrics.http_req_duration['p(95)'].toFixed(2)}ms</li>
            <li>HTTP Request Duration (max): ${data.metrics.http_req_duration.max.toFixed(2)}ms</li>
            <li>HTTP Requests per second: ${data.metrics.http_reqs.rate.toFixed(2)}</li>
        </ul>
    </div>
</body>
</html>`;
  
  return htmlTemplate;
}