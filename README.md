# API Testing & Performance Validation Suite

A comprehensive testing suite for API validation, performance testing, and automation framework.

## Project Overview

This project demonstrates professional API testing capabilities including:
- Functional API testing with Postman
- Automated test execution with Newman
- Performance testing with K6
- Security testing fundamentals
- Test automation framework development
- Comprehensive reporting and documentation

## Project Structure

```
API-Testing-and-Performance-Validation-Suite/
├── postman/                    # Postman collections and environments
│   ├── collections/
│   ├── environments/
│   └── data/
├── newman/                     # Newman automation scripts
├── performance/                # Performance testing scripts
│   └── k6/
├── security/                   # Security testing scripts
├── framework/                  # Test automation framework
│   ├── src/
│   ├── tests/
│   └── utils/
├── reports/                    # Test execution reports
├── docs/                       # Documentation
└── config/                     # Configuration files
```

## Target APIs

We'll be testing multiple APIs to demonstrate different testing scenarios:

1. **JSONPlaceholder** - https://jsonplaceholder.typicode.com/
2. **ReqRes API** - https://reqres.in/
3. **Postman Echo** - https://postman-echo.com/
4. **Custom Node.js API** - Local REST API for advanced testing

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- Python (v3.8 or higher)
- Postman Desktop App
- Newman CLI
- K6

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd API-Testing-and-Performance-Validation-Suite
```

2. Install dependencies:
```bash
npm install
pip install -r requirements.txt
```

3. Set up tools:
```bash
# Install Newman globally
npm install -g newman

# Install K6 (Windows)
choco install k6

```

## Usage

### Running Postman Collections
```bash
# Run collection with Newman
newman run postman/collections/jsonplaceholder-api.json -e postman/environments/test.json

# Run with data file
newman run postman/collections/data-driven-tests.json -d postman/data/test-data.csv
```

### Performance Testing
```bash
# Run K6 tests
k6 run performance/k6/load-test.js

### Framework Tests
```bash
# Run JavaScript framework tests
npm test

# Run Python framework tests
python -m pytest framework/tests/ -v --html=reports/pytest-report.html
```

## Features

### ✅ Functional Testing
- CRUD operations validation
- Data validation and schema testing
- Error handling and edge cases
- Authentication and authorization

### ✅ Performance Testing
- Load testing scenarios
- Stress and spike testing
- Endurance testing
- Response time analysis

### ✅ Security Testing
- Basic security vulnerability checks
- Authentication bypass attempts
- Input validation testing
- Rate limiting validation

### ✅ Automation Framework
- Reusable test components
- Data-driven testing
- Configuration management
- Comprehensive reporting

## Documentation

- [API Documentation Analysis](docs/api-analysis.md)
- [Test Strategy](docs/test-strategy.md)
- [Performance Testing Guide](docs/performance-testing.md)
- [Security Testing Guide](docs/security-testing.md)
- [Framework Documentation](docs/framework.md)

## Reports

Test execution reports are generated in the `reports/` directory:
- Newman HTML reports
- K6 performance summaries
- Framework test reports
- Executive summary dashboards

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact & Connect

**Project Author**: Mohanad Tayeb  
**Purpose**: Software Testing & QA Skills Demonstration  
**LinkedIn**: [Connect with me](https://linkedin.com/in/your-profile)  
**Portfolio**: [View more projects](https://mohanad-tayeb.netlify.app/)
