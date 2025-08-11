# DMARC Security Analyzer

A comprehensive and fast DMARC security analysis tool that detects vulnerabilities in email authentication configurations.

<img width="1000" height="500" alt="image" src="https://github.com/user-attachments/assets/578b613f-2291-4ce0-a24c-e8f80c26c778" />

## 🚀 Features

- **Fast DNS Resolution**: Optimized DNS resolver with caching and concurrent lookups
- **Comprehensive Analysis**: Checks DMARC, SPF, DKIM, and MX records
- **Security Vulnerability Detection**: Identifies common security misconfigurations
- **Colored Output**: Beautiful terminal interface with color-coded results
- **JSON Reporting**: Generate detailed JSON reports for automation
- **Performance Optimized**: Fast analysis with intelligent caching
- **Cross-platform**: Works on Windows, macOS, and Linux

## 📋 Requirements

- Python 3.7+
- Internet connection for DNS lookups

## 🔧 Installation

1. Clone or download the project
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Basic Usage
```bash
python dmarc_analyzer.py domain.com
```

### Advanced Options
```bash
# Verbose output with detailed information
python dmarc_analyzer.py --verbose example.com

# Generate JSON report
python dmarc_analyzer.py --output report.json example.com

# Show only discovered records
python dmarc_analyzer.py --records-only example.com

# Disable colored output
python dmarc_analyzer.py --no-color example.com
```

### Command Line Options
- `domain`: Target domain to analyze (required)
- `-o, --output`: Save JSON report to file
- `-v, --verbose`: Enable verbose output
- `-r, --records-only`: Show only discovered DNS records
- `--no-color`: Disable colored terminal output

## 📊 Output Examples

### Console Output
The tool provides color-coded output:
- 🔴 **CRITICAL**: Immediate action required
- 🟠 **HIGH**: Important security issues
- 🟡 **MEDIUM**: Security concerns
- 🔵 **LOW**: Minor issues
- 🟢 **INFO**: Informational messages

### JSON Report
Detailed JSON report with structured data:
```json
{
  "domain": "example.com",
  "timestamp": "2024-01-15T10:30:00",
  "issues": [...],
  "summary": {
    "total_issues": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```

## 🔍 Security Checks

### DMARC Analysis
- **Record Existence**: Checks for DMARC record presence
- **Policy Analysis**: Evaluates policy settings (none/quarantine/reject)
- **Reporting Configuration**: Validates rua/ruf parameters
- **Subdomain Policy**: Checks subdomain policy settings
- **Percentage Settings**: Analyzes pct parameter usage

### SPF Analysis
- **Record Validation**: Verifies SPF record format
- **Mechanism Analysis**: Checks for insecure mechanisms
- **Include Optimization**: Identifies excessive DNS lookups
- **Policy Strength**: Evaluates all mechanism usage
- **Third-party Services**: Detects unsecured third-party includes

### DKIM Analysis
- **Record Discovery**: Finds DKIM records across common selectors
- **Key Strength**: Analyzes RSA key lengths
- **Syntax Validation**: Checks DKIM record format
- **Selector Optimization**: Identifies multiple DKIM configurations

### MX Record Analysis
- **Mail Server Discovery**: Finds and validates MX records
- **Server Connectivity**: Tests mail server availability
- **Priority Analysis**: Evaluates MX record priorities

### Additional Security Checks
- **MTA-STS**: Checks for Mail Transfer Agent Strict Transport Security
- **TLS-RPT**: Validates TLS reporting configuration
- **STARTTLS**: Tests for secure mail transport

## 🚨 Security Levels

- **🔴 CRITICAL**: Missing DMARC record, major security vulnerabilities
- **🟠 HIGH**: Weak policies, insecure configurations
- **🟡 MEDIUM**: Suboptimal settings, improvement opportunities
- **🔵 LOW**: Minor issues, optimization suggestions
- **🟢 INFO**: Informational findings, best practices

## 📁 Exit Codes

- `0`: Success (no issues found)
- `1`: General issues detected
- `2`: High severity issues found
- `3`: Critical issues requiring immediate attention
- `130`: Analysis interrupted by user

## 🛠️ Technical Details

### DNS Resolution
- **Multiple DNS Servers**: Uses Google (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1, 1.0.0.1)
- **Caching**: Intelligent DNS result caching for performance
- **Timeout Handling**: Robust timeout and retry mechanisms
- **Concurrent Lookups**: Parallel DNS queries for speed

### Performance Features
- **Smart Caching**: Avoids redundant DNS queries
- **Concurrent Processing**: Parallel analysis of different record types
- **Optimized Timeouts**: Balanced speed and reliability
- **Memory Efficient**: Minimal memory footprint

### Error Handling
- **Graceful Degradation**: Continues analysis even if some checks fail
- **Detailed Logging**: Comprehensive error reporting
- **User-friendly Messages**: Clear, actionable error descriptions
- **Recovery Mechanisms**: Automatic retry with alternative DNS servers

## 📚 Examples

### Basic Analysis
```bash
$ python dmarc_analyzer.py google.com
[INFO] Starting DMARC analysis for google.com
[SUCCESS] DMARC record found
[WARNING] Policy set to monitoring only (p=none)
[INFO] Analysis completed in 2.34 seconds
```

### Verbose Analysis
```bash
$ python dmarc_analyzer.py --verbose example.com
[INFO] Starting DMARC analysis for example.com
[INFO] Checking DMARC record...
[INFO] Checking SPF record...
[INFO] Checking DKIM records...
[WARNING] No DMARC record found
[CRITICAL] Missing DMARC record - high security risk
```

### JSON Report Generation
```bash
$ python dmarc_analyzer.py --output security_report.json example.com
[INFO] Analysis completed
[SUCCESS] JSON report saved to security_report.json
```

## 🔧 Development

### Project Structure
```
DMARC/
├── dmarc_analyzer.py    # Main analyzer script
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

### Key Classes
- **DMARCAnalyzer**: Main analysis engine
- **DNSResolver**: Optimized DNS resolution with caching
- **SecurityIssue**: Data structure for security findings
- **Logger**: Colored logging utility

### Adding New Checks
```python
def check_new_security_feature(self):
    """Add new security check"""
    try:
        # Your check logic here
        if issue_found:
            self._add_issue(
                severity="MEDIUM",
                category="NEW_CHECK",
                title="Issue Title",
                description="Issue description",
                solution="How to fix it"
            )
    except Exception as e:
        if self.verbose:
            Logger.error(f"Check failed: {e}")
```

## 📚 Resources

- [DMARC RFC 7489](https://tools.ietf.org/html/rfc7489)
- [SPF RFC 7208](https://tools.ietf.org/html/rfc7208)
- [DKIM RFC 6376](https://tools.ietf.org/html/rfc6376)
- [MTA-STS RFC 8461](https://tools.ietf.org/html/rfc8461)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is designed for educational and security testing purposes. Always ensure you have proper authorization before testing domains you don't own. The authors are not responsible for any misuse of this tool.

## 🆘 Troubleshooting

### Common Issues

**DNS Timeout Errors**
- Check your internet connection
- Try using different DNS servers
- Increase timeout values if needed

**Permission Errors**
- Ensure you have write permissions for output files
- Run with appropriate user privileges

**Import Errors**
- Verify all dependencies are installed: `pip install -r requirements.txt`
- Check Python version compatibility

### Performance Tips

- Use `--records-only` for quick record discovery
- Disable colors with `--no-color` for automation
- Use JSON output for programmatic analysis 
