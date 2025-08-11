#!/usr/bin/env python3
"""
DMARC Security Analyzer - Enhanced Version
Analyzes DMARC records and detects security vulnerabilities.
"""

import dns.resolver
import dns.exception
import re
import sys
import argparse
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colors
colorama.init(autoreset=True)

# DNS Configuration
DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']

@dataclass
class SecurityIssue:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    solution: str
    impact: str

class Logger:
    """Simple colored logging utility"""
    
    @staticmethod
    def info(msg: str):
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg: str):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg: str):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg: str):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def critical(msg: str):
        print(f"{Fore.RED}{Back.WHITE}[CRITICAL]{Style.RESET_ALL} {msg}")

class DNSResolver:
    """Fast DNS resolver with caching and concurrent lookups"""
    
    def __init__(self):
        self.cache = {}
        self.timeout = 3.0
        self.lifetime = 10.0
    
    def get_record(self, domain: str, record_type: str) -> List[str]:
        """Get DNS record with caching"""
        cache_key = f"{domain}:{record_type}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = DNS_SERVERS
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime
        
        try:
            answers = resolver.resolve(domain, record_type)
            result = [str(rdata) for rdata in answers]
            self.cache[cache_key] = result
            return result
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, Exception):
            self.cache[cache_key] = []
            return []

class DMARCAnalyzer:
    """Enhanced DMARC Security Analyzer"""
    
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain.lower().strip()
        self.verbose = verbose
        self.dns = DNSResolver()
        self.issues: List[SecurityIssue] = []
        self.records = {
            'dmarc': None,
            'spf': None,
            'dkim': [],
            'mx': []
        }
        self.start_time = time.time()
    
    def _add_issue(self, severity: str, category: str, title: str, 
                   description: str, solution: str, impact: str = "Unknown"):
        """Add security issue to list"""
        self.issues.append(SecurityIssue(
            severity=severity,
            category=category,
            title=title,
            description=description,
            solution=solution,
            impact=impact
        ))
    
    def _log_progress(self, message: str):
        """Log progress if verbose mode is enabled"""
        if self.verbose:
            elapsed = time.time() - self.start_time
            Logger.info(f"[{elapsed:.1f}s] {message}")
    
    def check_dmarc_record(self) -> bool:
        """Check DMARC record"""
        self._log_progress(f"Checking DMARC record for {self.domain}")
        
        try:
            records = self.dns.get_record(f"_dmarc.{self.domain}", "TXT")
            
            dmarc_record = None
            for record in records:
                if record.startswith("v=DMARC1"):
                    dmarc_record = record
                    break
            
            if not dmarc_record:
                self._add_issue(
                    "CRITICAL", "DMARC", "Missing DMARC Record",
                    f"No DMARC record found for domain {self.domain}",
                    f"Add DMARC record: _dmarc.{self.domain} TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{self.domain}\"",
                    "High - No email authentication"
                )
                return False
            
            self.records['dmarc'] = dmarc_record
            self._analyze_dmarc_policy(dmarc_record)
            return True
            
        except Exception as e:
            self._add_issue(
                "HIGH", "DMARC", "DMARC Check Failed",
                f"Failed to check DMARC record: {str(e)}",
                "Check DNS configuration and try again",
                "High"
            )
            return False
    
    def _analyze_dmarc_policy(self, record: str):
        """Analyze DMARC policy for vulnerabilities"""
        tags = {}
        
        # Parse DMARC tags
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip()] = value.strip()
        
        policy = tags.get('p', 'none').lower()
        
        # Policy analysis
        if policy == 'none':
            self._add_issue(
                "MEDIUM", "DMARC", "Weak DMARC Policy",
                "DMARC policy is set to 'none', providing no protection against spoofing",
                "Gradually change policy to 'quarantine' then 'reject'",
                "Medium"
            )
        
        # Percentage check
        if policy in ['quarantine', 'reject']:
            pct = tags.get('pct', '100')
            if pct != '100':
                self._add_issue(
                    "LOW", "DMARC", "Partial Policy Enforcement",
                    f"DMARC policy only applies to {pct}% of emails",
                    "Set pct=100 after testing phase",
                    "Low"
                )
        
        # Alignment checks
        if 'adkim' not in tags:
            self._add_issue(
                "INFO", "DMARC", "DKIM Alignment Not Specified",
                "DKIM alignment mode not explicitly set (defaults to relaxed)",
                "Consider setting adkim=s for strict alignment",
                "Low"
            )
        
        if 'aspf' not in tags:
            self._add_issue(
                "INFO", "DMARC", "SPF Alignment Not Specified",
                "SPF alignment mode not explicitly set (defaults to relaxed)",
                "Consider setting aspf=s for strict alignment",
                "Low"
            )
        
        # Reporting URIs
        if 'rua' not in tags:
            self._add_issue(
                "MEDIUM", "DMARC", "No Aggregate Reports",
                "No aggregate reporting URI specified",
                f"Add rua=mailto:dmarc@{self.domain}",
                "Medium"
            )
    
    def check_spf_record(self) -> bool:
        """Check SPF record"""
        self._log_progress("Checking SPF record")
        
        try:
            records = self.dns.get_record(self.domain, "TXT")
            
            spf_record = None
            for record in records:
                if record.startswith("v=spf1"):
                    spf_record = record
                    break
            
            if not spf_record:
                self._add_issue(
                    "HIGH", "SPF", "Missing SPF Record",
                    f"No SPF record found for domain {self.domain}",
                    f"Add SPF record: {self.domain} TXT \"v=spf1 -all\"",
                    "High"
                )
                return False
            
            self.records['spf'] = spf_record
            self._analyze_spf_record(spf_record)
            return True
            
        except Exception as e:
            self._add_issue(
                "MEDIUM", "SPF", "SPF Check Failed",
                f"Failed to check SPF record: {str(e)}",
                "Check DNS configuration",
                "Medium"
            )
            return False
    
    def _analyze_spf_record(self, record: str):
        """Analyze SPF record for vulnerabilities"""
        record_lower = record.lower()
        
        # Check for overly permissive policy
        if "+all" in record_lower:
            self._add_issue(
                "HIGH", "SPF", "Overly Permissive SPF",
                "SPF record allows all senders (+all)",
                "Change +all to -all for strict policy",
                "High"
            )
        elif "~all" in record_lower:
            self._add_issue(
                "LOW", "SPF", "Soft SPF Policy",
                "SPF record uses soft fail (~all) instead of hard fail",
                "Consider changing ~all to -all for stricter policy",
                "Low"
            )
        elif "-all" not in record_lower:
            self._add_issue(
                "MEDIUM", "SPF", "No SPF Policy Defined",
                "SPF record doesn't specify a policy for unlisted senders",
                "Add -all at the end of SPF record",
                "Medium"
            )
        
        # Check for excessive includes
        include_count = record_lower.count("include:")
        if include_count > 10:
            self._add_issue(
                "MEDIUM", "SPF", "Too Many SPF Includes",
                f"SPF record has {include_count} includes (max recommended: 10)",
                "Reduce number of includes or flatten SPF record",
                "Medium"
            )
        
        # Check for insecure mechanisms
        if "ptr" in record_lower:
            self._add_issue(
                "HIGH", "SPF", "Insecure PTR Mechanism",
                "SPF record uses deprecated PTR mechanism",
                "Remove PTR mechanism and use IP addresses or includes",
                "High"
            )
    
    def check_dkim_records(self) -> bool:
        """Check DKIM records"""
        self._log_progress("Checking DKIM records")
        
        selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim']
        found_records = []
        
        # Use ThreadPoolExecutor for concurrent DKIM checks
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_selector = {
                executor.submit(self._check_dkim_selector, selector): selector
                for selector in selectors
            }
            
            for future in as_completed(future_to_selector):
                selector = future_to_selector[future]
                try:
                    record = future.result()
                    if record:
                        found_records.append((selector, record))
                except Exception as e:
                    if self.verbose:
                        Logger.error(f"Failed to check DKIM selector {selector}: {e}")
        
        if not found_records:
            self._add_issue(
                "MEDIUM", "DKIM", "No DKIM Records Found",
                "No DKIM records found with common selectors",
                "Configure DKIM signing with your email provider",
                "Medium"
            )
            return False
        
        self.records['dkim'] = found_records
        
        for selector, record in found_records:
            self._analyze_dkim_record(selector, record)
        
        return True
    
    def _check_dkim_selector(self, selector: str) -> Optional[str]:
        """Check a specific DKIM selector"""
        try:
            records = self.dns.get_record(f"{selector}._domainkey.{self.domain}", "TXT")
            
            for record in records:
                if "v=DKIM1" in record or "k=" in record or "p=" in record:
                    return record
            return None
        except:
            return None
    
    def _analyze_dkim_record(self, selector: str, record: str):
        """Analyze DKIM record for vulnerabilities"""
        record_lower = record.lower()
        
        # Check if record is properly formatted
        if not record_lower.startswith("v=dkim1"):
            self._add_issue(
                "MEDIUM", "DKIM", f"Invalid DKIM Format ({selector})",
                f"DKIM record for selector '{selector}' doesn't start with v=DKIM1",
                "Fix DKIM record format",
                "Medium"
            )
        
        # Check for public key
        if "p=" not in record_lower:
            self._add_issue(
                "HIGH", "DKIM", f"Missing DKIM Public Key ({selector})",
                f"DKIM record for selector '{selector}' is missing public key",
                "Add public key to DKIM record",
                "High"
            )
        elif record_lower.count("p=") > 1 or "p= " in record_lower:
            self._add_issue(
                "HIGH", "DKIM", f"Invalid DKIM Public Key ({selector})",
                f"DKIM record for selector '{selector}' has invalid public key format",
                "Fix public key in DKIM record",
                "High"
            )
        
        # Check key length (estimate based on base64 length)
        if "p=" in record:
            try:
                key_part = record.split("p=")[1].split(";")[0].strip()
                if len(key_part) < 200:  # Rough estimate for < 1024-bit key
                    self._add_issue(
                        "MEDIUM", "DKIM", f"Weak DKIM Key ({selector})",
                        f"DKIM key for selector '{selector}' appears to be weak",
                        "Use at least 2048-bit RSA key",
                        "Medium"
                    )
            except:
                pass
    
    def check_mx_records(self) -> bool:
        """Check MX records"""
        self._log_progress("Checking MX records")
        
        try:
            mx_records = self.dns.get_record(self.domain, "MX")
            
            if not mx_records:
                self._add_issue(
                    "CRITICAL", "MX", "No MX Records",
                    f"No MX records found for domain {self.domain}",
                    "Add MX records to enable email delivery",
                    "Critical"
                )
                return False
            
            self.records['mx'] = mx_records
            
            # Check for common MX issues
            for mx_record in mx_records:
                if mx_record.endswith('.'):
                    continue  # Properly formatted
                self._add_issue(
                    "LOW", "MX", "MX Record Format",
                    f"MX record '{mx_record}' should end with a dot",
                    "Ensure MX records are properly formatted",
                    "Low"
                )
            
            return True
            
        except Exception as e:
            self._add_issue(
                "MEDIUM", "MX", "MX Check Failed",
                f"Failed to check MX records: {str(e)}",
                "Check DNS configuration",
                "Medium"
            )
            return False
    
    def check_additional_security(self):
        """Check additional security features"""
        self._log_progress("Checking additional security features")
        
        # Check MTA-STS
        try:
            mta_sts_records = self.dns.get_record(f"_mta-sts.{self.domain}", "TXT")
            if not mta_sts_records:
                self._add_issue(
                    "INFO", "Security", "MTA-STS Not Configured",
                    "MTA-STS policy not found",
                    "Consider implementing MTA-STS for enhanced transport security",
                    "Low"
                )
        except:
            pass
        
        # Check TLS-RPT
        try:
            tls_rpt_records = self.dns.get_record(f"_smtp._tls.{self.domain}", "TXT")
            if not tls_rpt_records:
                self._add_issue(
                    "INFO", "Security", "TLS-RPT Not Configured",
                    "TLS reporting policy not found",
                    "Consider implementing TLS-RPT for monitoring transport security",
                    "Low"
                )
        except:
            pass
    
    def run_analysis(self) -> bool:
        """Run complete analysis"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}DMARC Security Analysis")
        print(f"{Fore.CYAN}Domain: {Fore.WHITE}{self.domain}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        success = True
        
        # Run all checks
        checks = [
            ("DMARC Record", self.check_dmarc_record),
            ("SPF Record", self.check_spf_record),
            ("DKIM Records", self.check_dkim_records),
            ("MX Records", self.check_mx_records),
        ]
        
        for check_name, check_func in checks:
            try:
                if check_func():
                    Logger.success(f"{check_name}: OK")
                else:
                    Logger.warning(f"{check_name}: Issues found")
                    success = False
            except Exception as e:
                Logger.error(f"{check_name}: Failed ({e})")
                success = False
        
        # Additional security checks
        self.check_additional_security()
        
        return success
    
    def print_summary(self):
        """Print analysis summary"""
        if not self.issues:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}🎉 ANALYSIS COMPLETE - NO ISSUES FOUND!")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
            return
        
        # Count issues by severity
        severity_counts = {}
        for issue in self.issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}📊 ANALYSIS SUMMARY")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = severity_colors[severity]
                print(f"{color}  {severity:8}: {count:2} issues{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
    
    def print_detailed_results(self):
        """Print detailed analysis results"""
        if not self.issues:
            return
        
        # Group issues by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        issues_by_severity = {}
        
        for issue in self.issues:
            if issue.severity not in issues_by_severity:
                issues_by_severity[issue.severity] = []
            issues_by_severity[issue.severity].append(issue)
        
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }
        
        severity_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }
        
        for severity in severity_order:
            if severity not in issues_by_severity:
                continue
            
            color = severity_colors[severity]
            icon = severity_icons[severity]
            
            print(f"\n{color}{'─'*60}")
            print(f"{color}{icon} {severity} ISSUES ({len(issues_by_severity[severity])})")
            print(f"{color}{'─'*60}{Style.RESET_ALL}")
            
            for i, issue in enumerate(issues_by_severity[severity], 1):
                print(f"\n{color}[{i}] {issue.title}")
                print(f"{Fore.WHITE}    Category: {issue.category}")
                print(f"{Fore.WHITE}    Impact: {issue.impact}")
                print(f"{Fore.WHITE}    Issue: {issue.description}")
                print(f"{Fore.GREEN}    Solution: {issue.solution}{Style.RESET_ALL}")
    
    def print_records_info(self):
        """Print found records information"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}📋 DISCOVERED RECORDS")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.records['dmarc']:
            print(f"\n{Fore.GREEN}DMARC Record:{Style.RESET_ALL}")
            print(f"  {self.records['dmarc']}")
        
        if self.records['spf']:
            print(f"\n{Fore.GREEN}SPF Record:{Style.RESET_ALL}")
            print(f"  {self.records['spf']}")
        
        if self.records['dkim']:
            print(f"\n{Fore.GREEN}DKIM Records:{Style.RESET_ALL}")
            for selector, record in self.records['dkim']:
                print(f"  Selector '{selector}': {record[:80]}...")
        
        if self.records['mx']:
            print(f"\n{Fore.GREEN}MX Records:{Style.RESET_ALL}")
            for mx_record in self.records['mx']:
                print(f"  {mx_record}")
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "analysis_time": f"{time.time() - self.start_time:.2f}s",
            "records": self.records,
            "issues": [
                {
                    "severity": issue.severity,
                    "category": issue.category,
                    "title": issue.title,
                    "description": issue.description,
                    "solution": issue.solution,
                    "impact": issue.impact
                }
                for issue in self.issues
            ],
            "summary": {
                "total_issues": len(self.issues),
                "critical": len([i for i in self.issues if i.severity == "CRITICAL"]),
                "high": len([i for i in self.issues if i.severity == "HIGH"]),
                "medium": len([i for i in self.issues if i.severity == "MEDIUM"]),
                "low": len([i for i in self.issues if i.severity == "LOW"]),
                "info": len([i for i in self.issues if i.severity == "INFO"])
            }
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)

def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced DMARC Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s --output report.json --verbose example.com
  %(prog)s --records-only example.com
        """
    )
    
    parser.add_argument("domain", help="Domain to analyze")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-r", "--records-only", action="store_true", help="Show only discovered records")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        colorama.deinit()
    
    # Validate domain
    if not validate_domain(args.domain):
        Logger.error("Invalid domain format")
        sys.exit(1)
    
    try:
        # Create analyzer and run analysis
        analyzer = DMARCAnalyzer(args.domain, args.verbose)
        success = analyzer.run_analysis()
        
        # Print results
        analyzer.print_summary()
        
        if args.records_only:
            analyzer.print_records_info()
        else:
            analyzer.print_detailed_results()
            analyzer.print_records_info()
        
        # Save JSON report
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(analyzer.generate_json_report())
                Logger.success(f"JSON report saved to {args.output}")
            except Exception as e:
                Logger.error(f"Failed to save report: {e}")
        
        # Execution time
        elapsed = time.time() - analyzer.start_time
        print(f"\n{Fore.CYAN}Analysis completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
        
        # Exit codes
        critical_issues = len([i for i in analyzer.issues if i.severity == "CRITICAL"])
        high_issues = len([i for i in analyzer.issues if i.severity == "HIGH"])
        
        if critical_issues > 0:
            sys.exit(3)  # Critical issues
        elif high_issues > 0:
            sys.exit(2)  # High severity issues
        elif not success or analyzer.issues:
            sys.exit(1)  # General issues
        else:
            sys.exit(0)  # Success
            
    except KeyboardInterrupt:
        Logger.error("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        Logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()