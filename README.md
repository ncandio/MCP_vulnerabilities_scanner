# Security Scanner MCP

This is an experimental client application that interfaces with external vulnerability scanning tools to test applications for security issues. It is designed as a proof of concept for integrating with services like VirusTotal, OWASP ZAP, and dependency scanners.

## Purpose

This application provides a GUI interface to scan:
- Files for malware and vulnerabilities using VirusTotal
- Web applications for security issues using OWASP ZAP
- Software dependencies for known vulnerabilities

## Features

- **Multi-Scanner Integration**: Connect to multiple security scanners with a single interface
- **File Scanning**: Analyze executables, libraries, and other files for malware and vulnerabilities
- **Web Application Scanning**: Test websites for common security issues like SQL injection and XSS
- **Dependency Analysis**: Check software dependencies for known vulnerabilities
- **Report Generation**: Create and save detailed scan reports in JSON format
- **Configurable Settings**: Customize API keys and scan options

## Usage

1. Configure API keys in the Configuration tab
2. Select files or URLs to scan
3. Choose scanning options
4. View and export results
5. Review historical scans in the Results tab

## Note

This is a demonstration project and not for production use. The scanner currently simulates API calls to external services for demonstration purposes.

## Requirements

- Python 3.11+
- Tkinter (included with Python)

## Setup

```
# Create and activate virtual environment
python3 -m venv MCP_SCAN
source MCP_SCAN/bin/activate

# Run the application
python mcp_scanner.py
```

## Security Considerations

- API keys are stored locally in config.ini
- No data is sent to external servers in this demo version
- In a real implementation, secure API key storage would be recommended