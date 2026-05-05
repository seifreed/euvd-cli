# EUVD Python CLI

A Python command-line interface for querying the ENISA EU Vulnerability Database (EUVD) API. This tool provides both interactive and direct command-line access to vulnerability data with advanced search capabilities.

## Features

- **Multiple Access Methods**: Interactive menu and direct CLI commands
- **Comprehensive API Coverage**: Access to all major EUVD endpoints
- **Advanced Search**: Flexible filtering with text search and exploitation status
- **Rich Output**: Colored JSON formatting for better readability
- **Rate Limiting**: Built-in request throttling (1 request per 6 seconds)
- **Type Safety**: Pydantic models for data validation
- **Self-Testing**: Automated endpoint validation
- **Modular Architecture**: Clean, extensible codebase

## Installation

### Prerequisites

- Python 3.13 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/seifreed/euvd-cli
cd euvd-cli
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the package in development mode:
```bash
pip install -e .
```

## Usage

### Interactive Mode

Launch the interactive menu:
```bash
python euvd-cli.py
```

The menu provides the following options:
1. Show Latest Vulnerabilities
2. Show Exploited Vulnerabilities
3. Show Critical Vulnerabilities
4. Search by ENISA ID
5. Search by Advisory ID
6. Advanced Search with Filters
7. Show Vulnerability Statistics
8. Run Self-Test
9. Exit

### Direct Commands

#### Basic Vulnerability Queries

```bash
# Get latest vulnerabilities
python euvd-cli.py latest

# Get critical vulnerabilities
python euvd-cli.py critical

# Get exploited vulnerabilities
python euvd-cli.py exploited
```

#### Search Operations

```bash
# Search by ENISA ID
python euvd-cli.py search-enisa EUVD-2025-4893

# Search by Advisory ID
python euvd-cli.py search-advisory oxas-adv-2024-0002

# Advanced search with text filter
python euvd-cli.py search --text "Windows" --size 10

# Search for exploited vulnerabilities
python euvd-cli.py search --exploited true --size 5

# Combined search
python euvd-cli.py search --text "Linux" --exploited true --size 3
```

#### Utility Commands

```bash
# Show vulnerability statistics
python euvd-cli.py stats

# Run self-test suite
python euvd-cli.py selftest

# Show help
python euvd-cli.py --help
```

### Advanced Search Parameters

The advanced search command supports the following parameters:

**Working Parameters:**
- `--text`: Text search keywords
- `--exploited`: Filter by exploitation status (true/false)
- `--size`: Number of results (default: 10, max: 100)

**Note**: Some parameters like vendor, product, CVSS scores may return 403 errors due to API limitations.

## API Endpoints

The tool interfaces with the following EUVD API endpoints:

| Endpoint | Description | Status |
|----------|-------------|---------|
| `/lastvulnerabilities` | Latest vulnerabilities | Working |
| `/criticalvulnerabilities` | Critical vulnerabilities | Working |
| `/exploitedvulnerabilities` | Exploited vulnerabilities | Working |
| `/enisaid?id=` | Search by ENISA ID | Working |
| `/advisory?id=` | Search by Advisory ID | Working |
| `/search` | Advanced search with filters | Partial |

## Project Structure

```
euvd_python/
├── __init__.py          # Package initialization
├── api_client.py        # HTTP client with rate limiting
├── cli.py              # Command-line interface
├── main.py             # Entry point
├── models.py           # Pydantic data models
└── self_test.py        # Automated testing suite

euvd-cli.py             # Main executable script
requirements.txt        # Python dependencies
README.md              # This file
```

## Dependencies

- **requests**: HTTP client library
- **click**: Command-line interface framework
- **pydantic**: Data validation and parsing
- **rich**: Rich text and beautiful formatting
- **urllib3**: HTTP client utilities

## Configuration

The tool uses the following default settings:

- **API Base URL**: `https://euvdservices.enisa.europa.eu/api`
- **Request Timeout**: 10 seconds
- **Rate Limit**: 1 request per 6 seconds
- **Default Page Size**: 10 results
- **Maximum Page Size**: 100 results

## Error Handling

The application includes comprehensive error handling for:

- Network connectivity issues
- API rate limiting
- Invalid response formats
- Authentication errors (403 Forbidden)
- Data validation failures

## Testing

Run the built-in self-test suite to verify all endpoints:

```bash
python euvd-cli.py selftest
```

The self-test validates:
- All major API endpoints
- Search functionality
- Data parsing and validation
- Error handling

## Development

### Adding New Features

1. **API Methods**: Add new methods to `api_client.py`
2. **Data Models**: Define Pydantic models in `models.py`
3. **CLI Commands**: Implement commands in `cli.py`
4. **Tests**: Add validation to `self_test.py`

### Code Style

The project follows Python best practices:
- Type hints for all functions
- Comprehensive docstrings
- Error handling with logging
- Modular, testable code structure

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided as-is for educational and research purposes. Please respect the EUVD API terms of service.

## Acknowledgments

- **ENISA**: For providing the EU Vulnerability Database API
- **Original Go Implementation**: This Python version is inspired by the original Go-based EUVD tool

## Support

For issues, questions, or contributions, please use the repository's issue tracker.

---

**Author**: Marc Rivero | @seifreed  
**Repository**: https://github.com/seifreed/euvd-cli  
**API Documentation**: https://euvd.enisa.europa.eu/apidoc


