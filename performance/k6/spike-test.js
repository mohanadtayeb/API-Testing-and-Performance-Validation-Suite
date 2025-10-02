import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
export const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Normal load
    { duration: '30s', target: 10 },  // Stay at normal load
    { duration: '20s', target: 100 }, // Spike to 100 users in 20 seconds
    { duration: '30s', target: 100 }, // Stay at spike load
    { duration: '20s', target: 10 },  // Return to normal load
    { duration: '1m', target: 10 },   // Stay at normal load
    { duration: '20s', target: 200 }, // Even bigger spike
    { duration: '30s', target: 200 }, // Stay at high spike
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // More lenient for spike testing
    http_req_failed: ['rate<0.15'],    // Allow higher error rate during spikes
    errors: ['rate<0.2'],              // Custom error rate threshold
  },
};

const baseUrls = {
  jsonplaceholder: 'https://jsonplaceholder.typicode.com',
  reqres: 'https://reqres.in/api',
  postmanEcho: 'https://postman-echo.com'
};

// Simulate realistic user behavior patterns
const userBehaviors = [
  'browse_posts',
  'user_management',
  'api_testing',
  'mixed_operations'
];

export default function() {
  const behavior = userBehaviors[Math.floor(Math.random() * userBehaviors.length)];
  
  switch(behavior) {
    case 'browse_posts':
      browsePosts();
      break;
    case 'user_management':
      manageUsers();
      break;
    case 'api_testing':
      testApiEndpoints();
      break;
    case 'mixed_operations':
      performMixedOperations();
      break;
  }
  
  sleep(Math.random() * 3); // Random think time
}

function browsePosts() {
  // Simulate a user browsing through posts
  let response = http.get(`${baseUrls.jsonplaceholder}/posts`);
  let success = check(response, {
    'Spike Test - Browse all posts': (r) => r.status === 200,
    'Spike Test - Browse posts response time': (r) => r.timings.duration < 3000,
  });
  errorRate.add(!success);
  
  // Read a few random posts
  for (let i = 0; i < 3; i++) {
    const postId = Math.floor(Math.random() * 100) + 1;
    response = http.get(`${baseUrls.jsonplaceholder}/posts/${postId}`);
    success = check(response, {
      'Spike Test - Read individual post': (r) => r.status === 200,
    });
    errorRate.add(!success);
    
    // Sometimes read comments
    if (Math.random() > 0.5) {
      response = http.get(`${baseUrls.jsonplaceholder}/posts/${postId}/comments`);
      success = check(response, {
        'Spike Test - Read post comments': (r) => r.status === 200,
      });
      errorRate.add(!success);
    }
    
    sleep(0.5); // Brief pause between reads
  }
}

function manageUsers() {
  // Simulate user management operations
  let response = http.get(`${baseUrls.reqres}/users?page=1`);
  let success = check(response, {
    'Spike Test - List users': (r) => r.status === 200,
  });
  errorRate.add(!success);
  
  // View user details
  const userId = Math.floor(Math.random() * 12) + 1;
  response = http.get(`${baseUrls.reqres}/users/${userId}`);
  success = check(response, {
    'Spike Test - View user details': (r) => r.status === 200 || r.status === 404,
  });
  errorRate.add(!success);
  
  // Create a new user occasionally
  if (Math.random() > 0.7) {
    const userData = {
      name: `Spike User ${Date.now()}`,
      job: `Position ${Math.floor(Math.random() * 100)}`
    };
    
    response = http.post(`${baseUrls.reqres}/users`, JSON.stringify(userData), {
      headers: { 'Content-Type': 'application/json' }
    });
    success = check(response, {
      'Spike Test - Create user': (r) => r.status === 201,
    });
    errorRate.add(!success);
  }
  
  // Test authentication
  if (Math.random() > 0.8) {
    const loginData = {
      email: 'eve.holt@reqres.in',
      password: 'cityslicka'
    };
    
    response = http.post(`${baseUrls.reqres}/login`, JSON.stringify(loginData), {
      headers: { 'Content-Type': 'application/json' }
    });
    success = check(response, {
      'Spike Test - User login': (r) => r.status === 200,
    });
    errorRate.add(!success);
  }
}

function testApiEndpoints() {
  // Simulate API testing activities
  const endpoints = [
    { method: 'GET', url: `${baseUrls.postmanEcho}/get?test=spike` },
    { method: 'POST', url: `${baseUrls.postmanEcho}/post`, data: { spike: true, timestamp: Date.now() } },
    { method: 'PUT', url: `${baseUrls.postmanEcho}/put`, data: { updated: true } },
    { method: 'DELETE', url: `${baseUrls.postmanEcho}/delete` }
  ];
  
  endpoints.forEach(endpoint => {
    let response;
    if (endpoint.method === 'GET' || endpoint.method === 'DELETE') {
      response = http.request(endpoint.method, endpoint.url);
    } else {
      response = http.request(endpoint.method, endpoint.url, JSON.stringify(endpoint.data), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const success = check(response, {
      [`Spike Test - ${endpoint.method} request`]: (r) => r.status === 200,
    });
    errorRate.add(!success);
    
    sleep(0.2); // Small delay between requests
  });
  
  // Test various status codes
  const statusCodes = [200, 201, 400, 404, 500];
  const randomStatus = statusCodes[Math.floor(Math.random() * statusCodes.length)];
  
  const response = http.get(`${baseUrls.postmanEcho}/status/${randomStatus}`);
  const success = check(response, {
    'Spike Test - Status code test': (r) => r.status === randomStatus,
  });
  errorRate.add(!success);
}

function performMixedOperations() {
  // Mix of all operations to simulate real-world usage
  
  // 1. Check API status
  let response = http.get(`${baseUrls.postmanEcho}/status/200`);
  let success = check(response, {
    'Spike Test - API health check': (r) => r.status === 200,
  });
  errorRate.add(!success);
  
  // 2. Browse some content
  response = http.get(`${baseUrls.jsonplaceholder}/posts?_limit=5`);
  success = check(response, {
    'Spike Test - Limited posts fetch': (r) => r.status === 200,
  });
  errorRate.add(!success);
  
  // 3. User operation
  response = http.get(`${baseUrls.reqres}/users?page=${Math.floor(Math.random() * 3) + 1}`);
  success = check(response, {
    'Spike Test - Random page users': (r) => r.status === 200,
  });
  errorRate.add(!success);
  
  // 4. Create some data
  if (Math.random() > 0.6) {
    const postData = {
      title: `Spike Test ${Date.now()}`,
      body: `Generated during spike testing at ${new Date().toISOString()}`,
      userId: Math.floor(Math.random() * 10) + 1
    };
    
    response = http.post(`${baseUrls.jsonplaceholder}/posts`, JSON.stringify(postData), {
      headers: { 'Content-Type': 'application/json' }
    });
    success = check(response, {
      'Spike Test - Create content': (r) => r.status === 201,
    });
    errorRate.add(!success);
  }
  
  // 5. Test echo service
  response = http.get(`${baseUrls.postmanEcho}/time/now`);
  success = check(response, {
    'Spike Test - Time service': (r) => r.status === 200,
  });
  errorRate.add(!success);
}

export function handleSummary(data) {
  return {
    'reports/k6-spike-test-summary.json': JSON.stringify(data, null, 2),
    'reports/k6-spike-test-summary.html': generateHTMLReport(data),
  };
}

function generateHTMLReport(data) {
  const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>K6 Spike Test Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .container { background: white; color: #333; border-radius: 15px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .header { text-align: center; border-bottom: 3px solid #ff6b6b; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; color: #ff6b6b; }
        .metric { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 10px; border-left: 5px solid #ff6b6b; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-item { padding: 25px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; border-radius: 15px; text-align: center; box-shadow: 0 5px 15px rgba(255,107,107,0.3); }
        .summary-item h3 { margin: 0 0 15px 0; font-size: 16px; opacity: 0.9; }
        .summary-item p { margin: 0; font-size: 28px; font-weight: bold; }
        .spike-indicator { background: linear-gradient(90deg, #4CAF50, #FF9800, #F44336); height: 10px; border-radius: 5px; margin: 20px 0; }
        .threshold { padding: 15px; margin: 10px 0; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        .threshold.pass { background: linear-gradient(135deg, #4CAF50, #8BC34A); color: white; }
        .threshold.fail { background: linear-gradient(135deg, #F44336, #E91E63); color: white; }
        .performance-chart { height: 60px; background: linear-gradient(90deg, #2ecc71 0%, #f39c12 50%, #e74c3c 100%); border-radius: 30px; margin: 20px 0; position: relative; }
        .performance-chart::after { content: 'Load Progression: Normal → Spike → Normal → Major Spike'; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: white; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ K6 Spike Test Report</h1>
            <p>Sudden Load Surge Performance Analysis</p>
            <p>Generated on: ${new Date().toISOString()}</p>
            <div class="spike-indicator"></div>
        </div>
        
        <div class="performance-chart"></div>
        
        <div class="summary">
            <div class="summary-item">
                <h3>Total Requests</h3>
                <p>${data.metrics.http_reqs ? data.metrics.http_reqs.count : 'N/A'}</p>
            </div>
            <div class="summary-item">
                <h3>Peak Virtual Users</h3>
                <p>${data.metrics.vus ? data.metrics.vus.max : 'N/A'}</p>
            </div>
            <div class="summary-item">
                <h3>Error Rate</h3>
                <p>${data.metrics.http_req_failed ? (data.metrics.http_req_failed.rate * 100).toFixed(2) : 'N/A'}%</p>
            </div>
            <div class="summary-item">
                <h3>Peak Response Time</h3>
                <p>${data.metrics.http_req_duration ? data.metrics.http_req_duration.max.toFixed(2) : 'N/A'}ms</p>
            </div>
            <div class="summary-item">
                <h3>Avg During Spikes</h3>
                <p>${data.metrics.http_req_duration ? data.metrics.http_req_duration['p(90)'].toFixed(2) : 'N/A'}ms</p>
            </div>
            <div class="summary-item">
                <h3>Recovery Time</h3>
                <p>${data.metrics.http_req_duration ? (data.metrics.http_req_duration['p(95)'] - data.metrics.http_req_duration.med).toFixed(2) : 'N/A'}ms</p>
            </div>
        </div>
        
        <div class="metric">
            <h3>🎯 Spike Test Thresholds</h3>
            ${Object.entries(data.thresholds || {}).map(([key, threshold]) => `
                <div class="threshold ${threshold.ok ? 'pass' : 'fail'}">
                    <span><strong>${key}</strong></span>
                    <span>${threshold.ok ? '✅ PASSED' : '❌ FAILED'}</span>
                </div>
            `).join('')}
        </div>
        
        <div class="metric">
            <h3>📈 Spike Performance Analysis</h3>
            <ul>
                <li><strong>System Resilience:</strong> 
                    ${data.metrics.http_req_failed && data.metrics.http_req_failed.rate < 0.1 ? 
                      '<span style="color: #4CAF50;">Excellent - System handled spikes well</span>' : 
                      '<span style="color: #F44336;">Needs Improvement - High error rate during spikes</span>'}
                </li>
                <li><strong>Response Time Impact:</strong> 
                    ${data.metrics.http_req_duration && data.metrics.http_req_duration['p(95)'] < 2000 ? 
                      '<span style="color: #4CAF50;">Acceptable degradation</span>' : 
                      '<span style="color: #FF9800;">Significant slowdown detected</span>'}
                </li>
                <li><strong>Recovery Speed:</strong> 
                    ${data.metrics.http_req_duration && (data.metrics.http_req_duration['p(95)'] - data.metrics.http_req_duration.med) < 500 ? 
                      '<span style="color: #4CAF50;">Fast recovery</span>' : 
                      '<span style="color: #FF9800;">Slow recovery</span>'}
                </li>
                <li><strong>Peak Throughput:</strong> ${data.metrics.http_reqs ? data.metrics.http_reqs.rate.toFixed(2) : 'N/A'} req/s</li>
                <li><strong>Total Test Duration:</strong> ${(data.state.testRunDurationMs / 1000 / 60).toFixed(2)} minutes</li>
            </ul>
        </div>
        
        <div class="metric">
            <h3>🔍 Detailed Performance Metrics</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4>Response Time Distribution</h4>
                    <ul>
                        <li>Average: ${data.metrics.http_req_duration ? data.metrics.http_req_duration.avg.toFixed(2) : 'N/A'}ms</li>
                        <li>Median: ${data.metrics.http_req_duration ? data.metrics.http_req_duration.med.toFixed(2) : 'N/A'}ms</li>
                        <li>90th Percentile: ${data.metrics.http_req_duration ? data.metrics.http_req_duration['p(90)'].toFixed(2) : 'N/A'}ms</li>
                        <li>95th Percentile: ${data.metrics.http_req_duration ? data.metrics.http_req_duration['p(95)'].toFixed(2) : 'N/A'}ms</li>
                        <li>Maximum: ${data.metrics.http_req_duration ? data.metrics.http_req_duration.max.toFixed(2) : 'N/A'}ms</li>
                    </ul>
                </div>
                <div>
                    <h4>Load Characteristics</h4>
                    <ul>
                        <li>Total Iterations: ${data.metrics.iterations ? data.metrics.iterations.count : 'N/A'}</li>
                        <li>Failed Requests: ${data.metrics.http_req_failed ? data.metrics.http_req_failed.count : 'N/A'}</li>
                        <li>Data Received: ${data.metrics.data_received ? (data.metrics.data_received.count / 1024 / 1024).toFixed(2) : 'N/A'} MB</li>
                        <li>Data Sent: ${data.metrics.data_sent ? (data.metrics.data_sent.count / 1024).toFixed(2) : 'N/A'} KB</li>
                        <li>Average VUs: ${data.metrics.vus ? data.metrics.vus.avg.toFixed(2) : 'N/A'}</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="metric">
            <h3>💡 Recommendations</h3>
            <ul>
                <li><strong>Auto-scaling:</strong> ${data.metrics.http_req_failed && data.metrics.http_req_failed.rate > 0.1 ? 'Consider implementing auto-scaling to handle sudden load spikes' : 'Current scaling appears adequate for spike loads'}</li>
                <li><strong>Caching:</strong> ${data.metrics.http_req_duration && data.metrics.http_req_duration['p(95)'] > 1000 ? 'Implement caching strategies to improve response times during high load' : 'Response times are acceptable during spikes'}</li>
                <li><strong>Monitoring:</strong> Set up alerts for response times exceeding ${data.metrics.http_req_duration ? Math.ceil(data.metrics.http_req_duration['p(95)'] * 1.2) : 2000}ms</li>
                <li><strong>Load Balancing:</strong> ${data.metrics.http_req_failed && data.metrics.http_req_failed.rate > 0.05 ? 'Review load balancing strategy to better distribute spike traffic' : 'Load distribution handling spike traffic effectively'}</li>
            </ul>
        </div>
    </div>
</body>
</html>`;
  
  return htmlTemplate;
}