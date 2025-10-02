#!/usr/bin/env node

const TestRunner = require('./src/TestRunner');
const JsonPlaceholderTests = require('./tests/JsonPlaceholderTests');
const ReqResTests = require('./tests/ReqResTests');
const { getInstance: getConfig } = require('./src/ConfigManager');

/**
 * Main test execution script
 */
async function main() {
  const args = process.argv.slice(2);
  const config = getConfig();
  
  // Parse command line arguments
  const options = parseArguments(args);
  
  // Set environment if specified
  if (options.env) {
    config.setEnvironment(options.env);
  }
  
  console.log(`🌍 Environment: ${config.getEnvironment()}`);
  
  const runner = new TestRunner();
  
  try {
    // Add tests based on options
    if (options.tests.length === 0 || options.tests.includes('all')) {
      addAllTests(runner);
    } else {
      addSpecificTests(runner, options.tests);
    }
    
    // Run the tests
    const results = await runner.runTests({
      tags: options.tags,
      parallel: options.parallel,
      maxConcurrency: options.concurrency,
      generateReports: !options.noReports,
      stopOnFailure: options.stopOnFailure
    });
    
    // Print summary
    runner.printSummary();
    
    // Exit with appropriate code
    const exitCode = (results.failedTests > 0 || results.errorTests > 0) ? 1 : 0;
    process.exit(exitCode);
    
  } catch (error) {
    console.error('❌ Test execution failed:', error.message);
    process.exit(1);
  }
}

/**
 * Parse command line arguments
 */
function parseArguments(args) {
  const options = {
    tests: [],
    tags: [],
    env: null,
    parallel: false,
    concurrency: 5,
    noReports: false,
    stopOnFailure: false,
    help: false
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--help':
      case '-h':
        options.help = true;
        break;
        
      case '--tests':
      case '-t':
        if (args[i + 1]) {
          options.tests = args[i + 1].split(',');
          i++;
        }
        break;
        
      case '--tags':
        if (args[i + 1]) {
          options.tags = args[i + 1].split(',');
          i++;
        }
        break;
        
      case '--env':
      case '-e':
        if (args[i + 1]) {
          options.env = args[i + 1];
          i++;
        }
        break;
        
      case '--parallel':
      case '-p':
        options.parallel = true;
        break;
        
      case '--concurrency':
      case '-c':
        if (args[i + 1]) {
          options.concurrency = parseInt(args[i + 1], 10);
          i++;
        }
        break;
        
      case '--no-reports':
        options.noReports = true;
        break;
        
      case '--stop-on-failure':
        options.stopOnFailure = true;
        break;
        
      default:
        if (arg.startsWith('--')) {
          console.warn(`Unknown option: ${arg}`);
        }
    }
  }
  
  if (options.help) {
    showHelp();
    process.exit(0);
  }
  
  return options;
}

/**
 * Show help information
 */
function showHelp() {
  console.log(`
🧪 API Testing Framework - Test Runner

Usage: node run-tests.js [options]

Options:
  -h, --help              Show this help message
  -t, --tests <tests>     Comma-separated list of test suites to run
                          Available: jsonplaceholder, reqres, all (default: all)
  --tags <tags>           Comma-separated list of tags to filter tests
  -e, --env <env>         Environment to run tests against (dev, staging, prod)
  -p, --parallel          Run tests in parallel
  -c, --concurrency <n>   Maximum number of concurrent tests (default: 5)
  --no-reports            Skip generating test reports
  --stop-on-failure       Stop execution when a test fails

Examples:
  node run-tests.js                                    # Run all tests
  node run-tests.js --tests jsonplaceholder           # Run only JSONPlaceholder tests
  node run-tests.js --tags api,smoke                  # Run tests with 'api' or 'smoke' tags
  node run-tests.js --env staging --parallel          # Run tests in staging environment with parallel execution
  node run-tests.js --tests reqres --stop-on-failure  # Run ReqRes tests and stop on first failure

Test Suites:
  jsonplaceholder    - Tests for JSONPlaceholder API (posts, users, comments)
  reqres            - Tests for ReqRes API (authentication, users, resources)
  all               - Run all available test suites
`);
}

/**
 * Add all available tests to the runner
 */
function addAllTests(runner) {
  console.log('📋 Adding all test suites...');
  runner.addTest(JsonPlaceholderTests);
  runner.addTest(ReqResTests);
}

/**
 * Add specific tests to the runner
 */
function addSpecificTests(runner, testNames) {
  console.log(`📋 Adding specific test suites: ${testNames.join(', ')}`);
  
  testNames.forEach(testName => {
    switch (testName.toLowerCase()) {
      case 'jsonplaceholder':
        runner.addTest(JsonPlaceholderTests);
        break;
        
      case 'reqres':
        runner.addTest(ReqResTests);
        break;
        
      default:
        console.warn(`⚠️  Unknown test suite: ${testName}`);
    }
  });
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

// Run the main function if this script is executed directly
if (require.main === module) {
  main();
}

module.exports = { main, parseArguments, addAllTests, addSpecificTests };