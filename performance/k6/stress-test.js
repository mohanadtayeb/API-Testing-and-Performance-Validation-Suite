import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
export const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '2m', target: 50 },  // Ramp up to 50 users over 2 minutes
    { duration: '5m', target: 50 },  // Stay at 50 users for 5 minutes
    { duration: '2m', target: 100 }, // Ramp up to 100 users over 2 minutes
    { duration: '5m', target: 100 }, // Stay at 100 users for 5 minutes
    { duration: '2m', target: 150 }, // Ramp up to 150 users over 2 minutes
    { duration: '5m', target: 150 }, // Stay at 150 users for 5 minutes
    { duration: '5m', target: 0 },   // Ramp down to 0 users over 5 minutes
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000'], // 95% of requests should be below 1000ms (more lenient for stress test)
    http_req_failed: ['rate<0.1'],     // Error rate should be less than 10%
    errors: ['rate<0.15'],             // Custom error rate should be less than 15%
  },
};

const baseUrls = {
  jsonplaceholder: 'https://jsonplaceholder.typicode.com',
  reqres: 'https://reqres.in/api',
  postmanEcho: 'https://postman-echo.com'
};

export default function() {
  // Randomly choose which API to stress test
  const apiChoice = Math.floor(Math.random() * 3);
  
  switch(apiChoice) {
    case 0:
      stressTestJSONPlaceholder();
      break;
    case 1:
      stressTestReqRes();
      break;
    case 2:
      stressTestPostmanEcho();
      break;
  }
  
  sleep(Math.random() * 2); // Random sleep between 0-2 seconds
}

function stressTestJSONPlaceholder() {
  // Stress test with multiple rapid requests
  for (let i = 0; i < 5; i++) {
    const postId = Math.floor(Math.random() * 100) + 1;
    
    let response = http.get(`${baseUrls.jsonplaceholder}/posts/${postId}`);
    let success = check(response, {
      'JSONPlaceholder Stress - Status is 200': (r) => r.status === 200,
      'JSONPlaceholder Stress - Response time acceptable': (r) => r.timings.duration < 2000,
    });
    errorRate.add(!success);
    
    // Attempt to create multiple posts rapidly
    if (i % 2 === 0) {
      const postData = {
        title: `Stress Test Post ${Date.now()}`,
        body: `Stress test content created at ${new Date().toISOString()}`,
        userId: Math.floor(Math.random() * 10) + 1
      };
      
      response = http.post(`${baseUrls.jsonplaceholder}/posts`, JSON.stringify(postData), {
        headers: { 'Content-Type': 'application/json' }
      });
      success = check(response, {
        'JSONPlaceholder Stress - Create post successful': (r) => r.status === 201,
      });
      errorRate.add(!success);
    }
  }
}

function stressTestReqRes() {
  // Stress test user operations
  for (let i = 0; i < 3; i++) {
    const userId = Math.floor(Math.random() * 12) + 1;
    const page = Math.floor(Math.random() * 3) + 1;
    
    // Get users with pagination
    let response = http.get(`${baseUrls.reqres}/users?page=${page}`);
    let success = check(response, {
      'ReqRes Stress - Get users successful': (r) => r.status === 200,
      'ReqRes Stress - Response time acceptable': (r) => r.timings.duration < 2000,
    });
    errorRate.add(!success);
    
    // Get specific user
    response = http.get(`${baseUrls.reqres}/users/${userId}`);
    success = check(response, {
      'ReqRes Stress - Get user response correct': (r) => r.status === 200 || r.status === 404,
    });
    errorRate.add(!success);
    
    // Create user
    if (i === 0) {
      const userData = {
        name: `Stress User ${Date.now()}`,
        job: `Tester ${Math.random()}`
      };
      
      response = http.post(`${baseUrls.reqres}/users`, JSON.stringify(userData), {
        headers: { 'Content-Type': 'application/json' }
      });
      success = check(response, {
        'ReqRes Stress - Create user successful': (r) => r.status === 201,
      });
      errorRate.add(!success);
    }
  }
}

function stressTestPostmanEcho() {
  // Stress test various endpoints
  for (let i = 0; i < 4; i++) {
    const testData = {
      iteration: i,
      timestamp: Date.now(),
      randomData: Math.random().toString(36).substring(7)
    };
    
    // Test POST endpoint
    let response = http.post(`${baseUrls.postmanEcho}/post`, JSON.stringify(testData), {
      headers: { 'Content-Type': 'application/json' }
    });
    let success = check(response, {
      'Postman Echo Stress - POST successful': (r) => r.status === 200,
      'Postman Echo Stress - POST response time acceptable': (r) => r.timings.duration < 2000,
    });
    errorRate.add(!success);
    
    // Test GET with query parameters
    response = http.get(`${baseUrls.postmanEcho}/get?stress=test&iteration=${i}&data=${testData.randomData}`);
    success = check(response, {
      'Postman Echo Stress - GET successful': (r) => r.status === 200,
    });
    errorRate.add(!success);
    
    // Test different status codes
    const statusCode = [200, 201, 400, 404, 500][Math.floor(Math.random() * 5)];
    response = http.get(`${baseUrls.postmanEcho}/status/${statusCode}`);
    success = check(response, {
      'Postman Echo Stress - Status code test': (r) => r.status === statusCode,
    });
    errorRate.add(!success);
  }
}

export function handleSummary(data) {
  return {
    'reports/k6-stress-test-summary.json': JSON.stringify(data, null, 2),
    'reports/k6-stress-test-summary.html': generateHTMLReport(data),
  };
}

function generateHTMLReport(data) {
  const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>K6 Stress Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; }
        .header { color: #dc3545; border-bottom: 3px solid #dc3545; padding-bottom: 15px; margin-bottom: 30px; }
        .metric { margin: 15px 0; padding: 15px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .pass { color: #28a745; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-item { padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; text-align: center; }
        .summary-item h3 { margin: 0 0 10px 0; font-size: 14px; opacity: 0.9; }
        .summary-item p { margin: 0; font-size: 24px; font-weight: bold; }
        .threshold { padding: 10px; margin: 5px 0; border-radius: 5px; }
        .threshold.pass { background-color: #d4edda; color: #155724; }
        .threshold.fail { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 K6 Stress Test Report</h1>
        <p>High-load performance testing results</p>
        <p>Generated on: ${new Date().toISOString()}</p>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <h3>Total Requests</h3>
            <p>${data.metrics.http_reqs ? data.metrics.http_reqs.count : 'N/A'}</p>
        </div>
        <div class="summary-item">
            <h3>Failed Requests</h3>
            <p>${data.metrics.http_req_failed ? data.metrics.http_req_failed.count : 'N/A'}</p>
        </div>
        <div class="summary-item">
            <h3>Error Rate</h3>
            <p>${data.metrics.http_req_failed ? (data.metrics.http_req_failed.rate * 100).toFixed(2) : 'N/A'}%</p>
        </div>
        <div class="summary-item">
            <h3>Max VUs</h3>
            <p>${data.metrics.vus ? data.metrics.vus.max : 'N/A'}</p>
        </div>
        <div class="summary-item">
            <h3>Avg Response Time</h3>
            <p>${data.metrics.http_req_duration ? data.metrics.http_req_duration.avg.toFixed(2) : 'N/A'}ms</p>
        </div>
        <div class="summary-item">
            <h3>95th Percentile</h3>
            <p>${data.metrics.http_req_duration ? data.metrics.http_req_duration['p(95)'].toFixed(2) : 'N/A'}ms</p>
        </div>
    </div>
    
    <div class="metric">
        <h3>🎯 Threshold Results</h3>
        ${Object.entries(data.thresholds || {}).map(([key, threshold]) => `
            <div class="threshold ${threshold.ok ? 'pass' : 'fail'}">
                <strong>${key}:</strong> ${threshold.ok ? '✅ PASSED' : '❌ FAILED'}
            </div>
        `).join('')}
    </div>
    
    <div class="metric">
        <h3>📊 Detailed Metrics</h3>
        <ul>
            <li><strong>Total Test Duration:</strong> ${(data.state.testRunDurationMs / 1000).toFixed(2)} seconds</li>
            <li><strong>Total Iterations:</strong> ${data.metrics.iterations ? data.metrics.iterations.count : 'N/A'}</li>
            <li><strong>Requests per Second:</strong> ${data.metrics.http_reqs ? data.metrics.http_reqs.rate.toFixed(2) : 'N/A'}</li>
            <li><strong>Average Response Time:</strong> ${data.metrics.http_req_duration ? data.metrics.http_req_duration.avg.toFixed(2) : 'N/A'}ms</li>
            <li><strong>Median Response Time:</strong> ${data.metrics.http_req_duration ? data.metrics.http_req_duration.med.toFixed(2) : 'N/A'}ms</li>
            <li><strong>Max Response Time:</strong> ${data.metrics.http_req_duration ? data.metrics.http_req_duration.max.toFixed(2) : 'N/A'}ms</li>
        </ul>
    </div>
    
    <div class="metric">
        <h3>💡 Performance Analysis</h3>
        <p><strong>System Behavior Under Stress:</strong></p>
        <ul>
            <li>Peak concurrent users: ${data.metrics.vus ? data.metrics.vus.max : 'N/A'}</li>
            <li>Error rate: ${data.metrics.http_req_failed ? (data.metrics.http_req_failed.rate * 100).toFixed(2) : 'N/A'}% 
                ${data.metrics.http_req_failed && data.metrics.http_req_failed.rate > 0.1 ? '<span class="fail">(High)</span>' : '<span class="pass">(Acceptable)</span>'}
            </li>
            <li>Response time degradation: 
                ${data.metrics.http_req_duration && data.metrics.http_req_duration['p(95)'] > 1000 ? '<span class="fail">Significant</span>' : '<span class="pass">Minimal</span>'}
            </li>
        </ul>
    </div>
</body>
</html>`;
  
  return htmlTemplate;
}