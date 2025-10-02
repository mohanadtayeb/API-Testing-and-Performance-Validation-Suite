/**
 * Configuration Manager for API Testing Framework
 * Handles environment-specific configurations and settings
 */
class ConfigManager {
  constructor() {
    this.config = {};
    this.environment = process.env.NODE_ENV || 'development';
    this.loadConfig();
  }

  /**
   * Load configuration based on environment
   */
  loadConfig() {
    // Default configuration
    this.config = {
      // API Endpoints
      apis: {
        jsonplaceholder: {
          baseURL: 'https://jsonplaceholder.typicode.com',
          timeout: 10000,
          retryAttempts: 3,
          retryDelay: 1000
        },
        reqres: {
          baseURL: 'https://reqres.in/api',
          timeout: 10000,
          retryAttempts: 3,
          retryDelay: 1000
        },
        postmanEcho: {
          baseURL: 'https://postman-echo.com',
          timeout: 10000,
          retryAttempts: 3,
          retryDelay: 1000
        },
        localApi: {
          baseURL: 'http://localhost:3000/api',
          timeout: 15000,
          retryAttempts: 2,
          retryDelay: 2000
        }
      },

      // Test Configuration
      test: {
        defaultTimeout: 30000,
        maxConcurrentTests: 10,
        generateReports: true,
        reportFormat: ['json', 'html'],
        reportDir: './reports',
        screenshotOnFailure: false,
        logLevel: 'info', // debug, info, warn, error
        tags: {
          smoke: ['basic', 'health'],
          regression: ['crud', 'auth', 'validation'],
          performance: ['load', 'stress', 'spike'],
          security: ['injection', 'auth-bypass', 'headers']
        }
      },

      // Performance Testing
      performance: {
        load: {
          virtualUsers: 10,
          duration: 300, // 5 minutes
          rampUpTime: 60  // 1 minute
        },
        stress: {
          virtualUsers: 100,
          duration: 600, // 10 minutes
          rampUpTime: 300 // 5 minutes
        },
        spike: {
          normalLoad: 10,
          spikeLoad: 100,
          spikeDuration: 60,
          totalDuration: 600
        },
        thresholds: {
          responseTime: {
            excellent: 200,
            good: 500,
            acceptable: 1000,
            poor: 2000
          },
          errorRate: {
            excellent: 0.1,
            good: 1,
            acceptable: 5,
            poor: 10
          },
          throughput: {
            minimum: 10, // requests per second
            target: 50,
            maximum: 100
          }
        }
      },

      // Security Testing
      security: {
        enabled: true,
        testTypes: [
          'sql-injection',
          'xss',
          'auth-bypass',
          'rate-limiting',
          'security-headers',
          'http-methods',
          'input-validation'
        ],
        payloadSets: {
          basic: true,
          advanced: false,
          custom: []
        },
        maxPayloadsPerTest: 10,
        skipKnownSafe: false
      },

      // Database Configuration (for local API testing)
      database: {
        host: 'localhost',
        port: 5432,
        name: 'test_db',
        username: 'test_user',
        password: 'test_password',
        dialect: 'postgresql',
        pool: {
          max: 5,
          min: 0,
          acquire: 30000,
          idle: 10000
        }
      },

      // Authentication
      auth: {
        defaultStrategy: 'bearer',
        tokenStorage: 'memory', // memory, file, redis
        tokenRefreshBuffer: 300, // 5 minutes before expiry
        credentials: {
          testUser: {
            username: 'test@example.com',
            password: 'testpassword123'
          },
          adminUser: {
            username: 'admin@example.com',
            password: 'adminpassword123'
          }
        }
      },

      // Notification Settings
      notifications: {
        enabled: false,
        channels: {
          email: {
            enabled: false,
            smtp: {
              host: 'smtp.gmail.com',
              port: 587,
              secure: false,
              auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
              }
            },
            recipients: ['team@example.com']
          },
          slack: {
            enabled: false,
            webhookUrl: process.env.SLACK_WEBHOOK_URL,
            channel: '#testing'
          },
          teams: {
            enabled: false,
            webhookUrl: process.env.TEAMS_WEBHOOK_URL
          }
        },
        triggers: {
          testFailure: true,
          testSuccess: false,
          performanceThreshold: true,
          securityIssue: true
        }
      },

      // Monitoring and Observability
      monitoring: {
        enabled: false,
        metrics: {
          prometheus: {
            enabled: false,
            endpoint: 'http://localhost:9090'
          },
          grafana: {
            enabled: false,
            endpoint: 'http://localhost:3000'
          }
        },
        tracing: {
          jaeger: {
            enabled: false,
            endpoint: 'http://localhost:14268/api/traces'
          }
        },
        logging: {
          level: 'info',
          format: 'json',
          destination: 'console', // console, file, elasticsearch
          elasticsearch: {
            host: 'localhost',
            port: 9200,
            index: 'api-testing-logs'
          }
        }
      }
    };

    // Load environment-specific overrides
    this.loadEnvironmentConfig();
    
    // Load from environment variables
    this.loadEnvironmentVariables();
  }

  /**
   * Load environment-specific configuration
   */
  loadEnvironmentConfig() {
    const environmentConfigs = {
      development: {
        test: {
          logLevel: 'debug',
          generateReports: true
        },
        security: {
          testTypes: ['sql-injection', 'xss'] // Limited for faster dev testing
        }
      },
      testing: {
        test: {
          logLevel: 'info',
          maxConcurrentTests: 5
        },
        performance: {
          load: {
            virtualUsers: 5,
            duration: 60
          }
        }
      },
      staging: {
        test: {
          logLevel: 'warn',
          generateReports: true
        },
        notifications: {
          enabled: true,
          channels: {
            slack: { enabled: true }
          }
        }
      },
      production: {
        test: {
          logLevel: 'error'
        },
        security: {
          enabled: false // Don't run security tests in production
        },
        notifications: {
          enabled: true
        }
      }
    };

    const envConfig = environmentConfigs[this.environment];
    if (envConfig) {
      this.mergeConfig(envConfig);
    }
  }

  /**
   * Load configuration from environment variables
   */
  loadEnvironmentVariables() {
    const envMappings = {
      'API_TIMEOUT': 'test.defaultTimeout',
      'MAX_CONCURRENT_TESTS': 'test.maxConcurrentTests',
      'LOG_LEVEL': 'test.logLevel',
      'REPORT_DIR': 'test.reportDir',
      
      'JSONPLACEHOLDER_BASE_URL': 'apis.jsonplaceholder.baseURL',
      'REQRES_BASE_URL': 'apis.reqres.baseURL',
      'POSTMAN_ECHO_BASE_URL': 'apis.postmanEcho.baseURL',
      'LOCAL_API_BASE_URL': 'apis.localApi.baseURL',
      
      'LOAD_TEST_USERS': 'performance.load.virtualUsers',
      'LOAD_TEST_DURATION': 'performance.load.duration',
      'STRESS_TEST_USERS': 'performance.stress.virtualUsers',
      
      'SECURITY_TESTS_ENABLED': 'security.enabled',
      'MAX_SECURITY_PAYLOADS': 'security.maxPayloadsPerTest',
      
      'DB_HOST': 'database.host',
      'DB_PORT': 'database.port',
      'DB_NAME': 'database.name',
      'DB_USER': 'database.username',
      'DB_PASSWORD': 'database.password',
      
      'NOTIFICATIONS_ENABLED': 'notifications.enabled',
      'SLACK_WEBHOOK_URL': 'notifications.channels.slack.webhookUrl',
      'EMAIL_USER': 'notifications.channels.email.smtp.auth.user',
      'EMAIL_PASS': 'notifications.channels.email.smtp.auth.pass'
    };

    Object.entries(envMappings).forEach(([envVar, configPath]) => {
      const value = process.env[envVar];
      if (value !== undefined) {
        this.setNestedConfig(configPath, this.parseValue(value));
      }
    });
  }

  /**
   * Parse environment variable value to appropriate type
   */
  parseValue(value) {
    // Boolean
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
    
    // Number
    if (!isNaN(value) && !isNaN(parseFloat(value))) {
      return parseFloat(value);
    }
    
    // JSON
    if (value.startsWith('{') || value.startsWith('[')) {
      try {
        return JSON.parse(value);
      } catch (e) {
        // Return as string if JSON parsing fails
      }
    }
    
    return value;
  }

  /**
   * Set nested configuration value
   */
  setNestedConfig(path, value) {
    const keys = path.split('.');
    let current = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
  }

  /**
   * Get nested configuration value
   */
  getNestedConfig(path) {
    const keys = path.split('.');
    let current = this.config;
    
    for (const key of keys) {
      if (current[key] === undefined) {
        return undefined;
      }
      current = current[key];
    }
    
    return current;
  }

  /**
   * Merge configuration objects
   */
  mergeConfig(newConfig) {
    this.config = this.deepMerge(this.config, newConfig);
  }

  /**
   * Deep merge two objects
   */
  deepMerge(target, source) {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }

  /**
   * Get configuration for specific API
   */
  getApiConfig(apiName) {
    return this.config.apis[apiName];
  }

  /**
   * Get test configuration
   */
  getTestConfig() {
    return this.config.test;
  }

  /**
   * Get performance testing configuration
   */
  getPerformanceConfig() {
    return this.config.performance;
  }

  /**
   * Get security testing configuration
   */
  getSecurityConfig() {
    return this.config.security;
  }

  /**
   * Get database configuration
   */
  getDatabaseConfig() {
    return this.config.database;
  }

  /**
   * Get authentication configuration
   */
  getAuthConfig() {
    return this.config.auth;
  }

  /**
   * Get notification configuration
   */
  getNotificationConfig() {
    return this.config.notifications;
  }

  /**
   * Get monitoring configuration
   */
  getMonitoringConfig() {
    return this.config.monitoring;
  }

  /**
   * Get current environment
   */
  getEnvironment() {
    return this.environment;
  }

  /**
   * Check if running in development environment
   */
  isDevelopment() {
    return this.environment === 'development';
  }

  /**
   * Check if running in production environment
   */
  isProduction() {
    return this.environment === 'production';
  }

  /**
   * Get full configuration
   */
  getAll() {
    return this.config;
  }

  /**
   * Validate configuration
   */
  validate() {
    const errors = [];

    // Validate required API configurations
    Object.entries(this.config.apis).forEach(([name, config]) => {
      if (!config.baseURL) {
        errors.push(`Missing baseURL for API: ${name}`);
      }
    });

    // Validate performance thresholds
    const perfConfig = this.config.performance;
    if (perfConfig.load.virtualUsers <= 0) {
      errors.push('Load test virtual users must be greater than 0');
    }

    // Validate notification configuration
    if (this.config.notifications.enabled) {
      const channels = this.config.notifications.channels;
      if (channels.slack.enabled && !channels.slack.webhookUrl) {
        errors.push('Slack webhook URL is required when Slack notifications are enabled');
      }
      if (channels.email.enabled && (!channels.email.smtp.auth.user || !channels.email.smtp.auth.pass)) {
        errors.push('Email credentials are required when email notifications are enabled');
      }
    }

    if (errors.length > 0) {
      throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }

    return true;
  }

  /**
   * Print configuration summary
   */
  printSummary() {
    console.log('\n📋 Configuration Summary');
    console.log(`Environment: ${this.environment}`);
    console.log(`APIs configured: ${Object.keys(this.config.apis).join(', ')}`);
    console.log(`Report directory: ${this.config.test.reportDir}`);
    console.log(`Log level: ${this.config.test.logLevel}`);
    console.log(`Security tests: ${this.config.security.enabled ? 'enabled' : 'disabled'}`);
    console.log(`Notifications: ${this.config.notifications.enabled ? 'enabled' : 'disabled'}`);
  }
}

// Singleton instance
let instance = null;

module.exports = {
  getInstance: () => {
    if (!instance) {
      instance = new ConfigManager();
    }
    return instance;
  },
  ConfigManager
};