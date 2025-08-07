#!/usr/bin/env python3
"""
Reconborne – Enhanced AI-driven reconnaissance tool
Features: Tech Stack Detection, Certificate Analysis, Advanced Reporting
Usage: python3 reconborne.py <IP-or-domain> [options]
"""
import click
import json
import subprocess
import xml.etree.ElementTree as ET
import requests
import socket
import ssl
import re
import google.generativeai as genai
import os
import tempfile
import pandas as pd
import hashlib
import threading
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import yaml
import time

# Rich console imports
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text

# Additional imports for enhanced features
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pyfiglet import Figlet
from colorama import init, Fore

# ========== CONFIGURATION ==========
class Config:
    def __init__(self):
        self.load_config()

    def load_config(self):
        """Load configuration from file or use defaults"""
        config_file = Path("reconborne_config.yaml")
        default_config = {
            'timeouts': {
                'http_request': 10,
                'ssl_connection': 10,
                'subprocess': 60,
                'dns_lookup': 5
            },
            'scan_options': {
                'max_threads': 10,
                'nmap_timing': 'T4',
                'enable_passive_scan': True,
                'passive_duration': 30
            },
            'api_keys': {
                'gemini_api_key': os.getenv("GEMINI_API_KEY"),
                'shodan_api_key': os.getenv("SHODAN_API_KEY"),
                'virustotal_api_key': os.getenv("VIRUSTOTAL_API_KEY")
            },
            'output': {
                'save_raw_data': True,
                'generate_pdf': False,
                'include_screenshots': False
            }
        }
        if config_file.exists():
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                self.config = {**default_config, **user_config}
        else:
            self.config = default_config
            # Save default config
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)

    def get(self, key_path, default=None):
        """Get nested config value"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value


# Initialize global objects
config = Config()
console = Console()

# AI Configuration
if config.get('api_keys.gemini_api_key'):
    genai.configure(api_key=config.get('api_keys.gemini_api_key'))
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None
    console.print("[yellow]Warning: GEMINI_API_KEY not set. AI reporting disabled.[/yellow]")

# ========== BANNER ==========
init(autoreset=True)
banner_text = Figlet(font="slant").renderText("Reconborne")
console.print(Panel(f"[bold cyan]{banner_text}[/bold cyan]\n"
                   "[italic]Enhanced AI-Driven Reconnaissance Tool[/italic]",
                   title="--Developed by Vylarion--", border_style="cyan"))

# ========== TECHNOLOGY STACK DETECTOR ==========
class TechStackDetector:
    def __init__(self):
        self.wappalyzer = None
        if WAPPALYZER_AVAILABLE:
            try:
                self.wappalyzer = Wappalyzer.latest()
            except Exception as e:
                console.print(f"[yellow]Wappalyzer initialization failed: {e}[/yellow]")
        # Comprehensive technology fingerprints
        self.tech_patterns = {
            'cms': {
                'wordpress': [r'wp-content', r'wp-includes', r'/wp-admin', r'wp_nonce', r'WordPress'],
                'drupal': [r'Drupal\.settings', r'sites/default/files', r'/node/', r'drupal'],
                'joomla': [r'/administrator/', r'joomla', r'/components/', r'JFactory'],
                'magento': [r'/skin/frontend/', r'Mage\.Cookies', r'/js/mage/', r'magento'],
                'shopify': [r'cdn\.shopify\.com', r'shopify-digital-wallet', r'Shopify'],
                'typo3': [r'typo3', r'TYPO3', r'/typo3/'],
                'prestashop': [r'prestashop', r'PrestaShop'],
                'opencart': [r'opencart', r'OpenCart']
            },
            'frameworks': {
                'react': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'React\.createElement'],
                'angular': [r'angular', r'ng-version', r'AngularJS'],
                'vue': [r'vue\.js', r'__vue__', r'Vue\.js'],
                'jquery': [r'jquery', r'\$\(document\)\.ready', r'jQuery'],
                'bootstrap': [r'bootstrap', r'col-md-', r'col-lg-', r'Bootstrap'],
                'ember': [r'ember', r'Ember\.js'],
                'backbone': [r'backbone', r'Backbone\.js'],
                'knockout': [r'knockout', r'ko\.observable']
            },
            'servers': {
                'apache': [r'Apache/[\d\.]+', r'Server:\s*Apache'],
                'nginx': [r'nginx/[\d\.]+', r'Server:\s*nginx'],
                'iis': [r'Server:\s*Microsoft-IIS', r'X-Powered-By:\s*ASP\.NET'],
                'cloudflare': [r'cf-ray', r'cloudflare', r'CF-RAY'],
                'lighttpd': [r'lighttpd', r'Server:\s*lighttpd'],
                'caddy': [r'Server:\s*Caddy']
            },
            'languages': {
                'php': [r'\.php', r'X-Powered-By:\s*PHP', r'PHPSESSID'],
                'asp.net': [r'\.aspx', r'X-Powered-By:\s*ASP\.NET', r'__VIEWSTATE'],
                'java': [r'\.jsp', r'jsessionid', r'X-Powered-By:\s*Servlet'],
                'python': [r'django', r'flask', r'\.py', r'Django'],
                'ruby': [r'ruby', r'rails', r'\.rb', r'Ruby on Rails'],
                'node.js': [r'node\.js', r'express', r'X-Powered-By:\s*Express'],
                'go': [r'golang', r'go-', r'/go/'],
                'rust': [r'actix', r'rocket', r'warp']
            },
            'databases': {
                'mysql': [r'mysql', r'MySQL'],
                'postgresql': [r'postgresql', r'postgres'],
                'mongodb': [r'mongodb', r'mongo'],
                'redis': [r'redis'],
                'elasticsearch': [r'elasticsearch', r'elastic']
            },
            'security': {
                'cloudflare': [r'cf-ray', r'cloudflare'],
                'fail2ban': [r'fail2ban'],
                'modsecurity': [r'mod_security', r'modsec']
            }
        }

    def detect_from_response(self, url, response_text, headers):
        """Enhanced technology detection from HTTP response"""
        detected = {
            'cms': [], 'frameworks': [], 'servers': [], 'languages': [],
            'databases': [], 'security': [], 'other': []
        }
        full_content = f"{response_text} {' '.join(headers.values())}"

        for category, techs in self.tech_patterns.items():
            for tech, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, full_content, re.IGNORECASE):
                        if tech not in detected[category]:
                            detected[category].append(tech)
                        break

        if self.wappalyzer:
            try:
                webpage = WebPage.new_from_url(url)
                wapp_results = self.wappalyzer.analyze(webpage)
                for tech in wapp_results:
                    if tech.lower() not in [item.lower() for sublist in detected.values() for item in sublist]:
                        detected['other'].append(tech.lower())
            except Exception as e:
                console.print(f"[yellow]Wappalyzer error: {e}[/yellow]")

        if BUILTWITH_AVAILABLE:
            try:
                bw_results = builtwith.parse(url)
                for category, items in bw_results.items():
                    if items:
                        for item in items:
                            if item.lower() not in [tech.lower() for sublist in detected.values() for tech in sublist]:
                                detected['other'].append(item.lower())
            except Exception as e:
                console.print(f"[yellow]BuiltWith error: {e}[/yellow]")

        for key in detected:
            detected[key] = list(set(detected[key]))
        return detected

    def analyze_javascript_libraries(self, response_text):
        """Detect JavaScript libraries with version information"""
        js_libs = {}
        patterns = {
            'jquery': [r'jQuery\s+v?(\d+\.\d+[\.\d]*)', r'jquery-(\d+\.\d+[\.\d]*)'],
            'react': [r'React\s+(\d+\.\d+[\.\d]*)', r'react@(\d+\.\d+[\.\d]*)'],
            'angular': [r'Angular\s+(\d+\.\d+[\.\d]*)', r'@angular/core@(\d+\.\d+[\.\d]*)'],
            'vue': [r'Vue\.js\s+v(\d+\.\d+[\.\d]*)', r'vue@(\d+\.\d+[\.\d]*)'],
            'bootstrap': [r'Bootstrap\s+v?(\d+\.\d+[\.\d]*)', r'bootstrap@(\d+\.\d+[\.\d]*)'],
            'd3': [r'd3\.js\s+v(\d+\.\d+[\.\d]*)', r'd3@(\d+\.\d+[\.\d]*)'],
            'lodash': [r'lodash@(\d+\.\d+[\.\d]*)'],
            'moment': [r'moment@(\d+\.\d+[\.\d]*)', r'moment\.js\s+(\d+\.\d+[\.\d]*)']
        }
        for lib, lib_patterns in patterns.items():
            for pattern in lib_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    js_libs[lib] = match.group(1)
                    break
        return js_libs

    def detect_cdn_usage(self, url):
        """Detect CDN usage through various methods"""
        cdns = []
        if not DNS_AVAILABLE:
            return cdns
        try:
            domain = urlparse(url).netloc.split(':')[0]
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).lower()
                    if 'cloudflare' in cname:
                        cdns.append('Cloudflare')
                    elif 'amazonaws' in cname or 'cloudfront' in cname:
                        cdns.append('AWS CloudFront')
                    elif 'azureedge' in cname:
                        cdns.append('Azure CDN')
                    elif 'fastly' in cname:
                        cdns.append('Fastly')
                    elif 'akamai' in cname:
                        cdns.append('Akamai')
                    elif 'maxcdn' in cname:
                        cdns.append('MaxCDN')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if ip.startswith(('104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.')):
                        if 'Cloudflare' not in cdns:
                            cdns.append('Cloudflare')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
        except Exception as e:
            console.print(f"[yellow]CDN detection error: {e}[/yellow]")
        return list(set(cdns))


# ========== CERTIFICATE ANALYZER ==========
class CertificateAnalyzer:
    def __init__(self):
        self.vulnerability_checks = {
            'weak_signature': ['md5', 'sha1'],
            'weak_key_size': 1024,
            'expiry_warning_days': 30,
        }
        self.ca_trust_levels = {
            'digicert': 'high', 'comodo': 'high', 'godaddy': 'medium', 'sectigo': 'high',
            'globalsign': 'high', 'entrust': 'high', 'thawte': 'medium', 'geotrust': 'medium',
            'rapidssl': 'medium', 'self-signed': 'low'
        }

    def analyze_certificate(self, hostname, port=443):
        cert_info = {
            'basic_info': {}, 'security_analysis': {}, 'vulnerabilities': [],
            'recommendations': [], 'trust_analysis': {}, 'extensions': {}, 'chain_info': {}
        }
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=config.get('timeouts.ssl_connection', 10)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    cert_info['basic_info'] = self._extract_basic_info(cert, cert_der)
                    cert_info['security_analysis'] = self._analyze_security(protocol, cipher)
                    self._check_vulnerabilities(cert_info, cert)
                    cert_info['trust_analysis'] = self._analyze_trust(cert)
                    cert_info['extensions'] = self._analyze_extensions(cert)
                    cert_info.update(self._perform_additional_checks(hostname, port))
        except Exception as e:
            cert_info['error'] = str(e)
        return cert_info

    def _extract_basic_info(self, cert, cert_der):
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        return {
            'subject': subject,
            'issuer': issuer,
            'common_name': subject.get('commonName', 'Unknown'),
            'organization': subject.get('organizationName', 'Unknown'),
            'country': subject.get('countryName', 'Unknown'),
            'version': cert.get('version', 'Unknown'),
            'serial_number': cert.get('serialNumber', 'Unknown'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
            'san': [name[1] for name in cert.get('subjectAltName', [])],
            'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest().upper(),
            'fingerprint_sha1': hashlib.sha1(cert_der).hexdigest().upper(),
        }

    def _analyze_security(self, protocol, cipher):
        return {
            'tls_version': protocol,
            'cipher_suite': cipher[0] if cipher else 'Unknown',
            'key_exchange': cipher[1] if cipher else 'Unknown',
            'encryption': cipher[2] if cipher else 'Unknown',
            'mac': cipher[3] if cipher and len(cipher) > 3 else 'Unknown',
            'cipher_strength': self._evaluate_cipher_strength(cipher[0] if cipher else '')
        }

    def _evaluate_cipher_strength(self, cipher_suite):
        if not cipher_suite:
            return 'unknown'
        cipher_lower = cipher_suite.lower()
        if any(weak in cipher_lower for weak in ['rc4', 'des', 'null', 'anon', 'export']):
            return 'weak'
        elif any(medium in cipher_lower for medium in ['3des', 'aes128']):
            return 'medium'
        elif any(strong in cipher_lower for strong in ['aes256', 'chacha20']):
            return 'strong'
        else:
            return 'medium'

    def _check_vulnerabilities(self, cert_info, cert):
        vulnerabilities = []
        recommendations = []
        sig_algo = cert_info['basic_info']['signature_algorithm'].lower()
        for weak_algo in self.vulnerability_checks['weak_signature']:
            if weak_algo in sig_algo:
                severity = 'CRITICAL' if 'md5' in sig_algo else 'HIGH'
                vulnerabilities.append({
                    'type': 'weak_signature_algorithm',
                    'severity': severity,
                    'description': f'Weak signature algorithm detected: {sig_algo}',
                    'impact': 'Certificate could be forged or tampered with',
                    'cve': 'CVE-2020-1967' if 'sha1' in sig_algo else None
                })
                recommendations.append('Upgrade to SHA-256 or stronger signature algorithm')

        try:
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            if days_until_expiry < 0:
                vulnerabilities.append({
                    'type': 'expired_certificate',
                    'severity': 'CRITICAL',
                    'description': f'Certificate expired {abs(days_until_expiry)} days ago',
                    'impact': 'Service interruption, MITM risk'
                })
                recommendations.append('Renew certificate immediately')
            elif days_until_expiry < self.vulnerability_checks['expiry_warning_days']:
                vulnerabilities.append({
                    'type': 'expiring_certificate',
                    'severity': 'MEDIUM',
                    'description': f'Certificate expires in {days_until_expiry} days',
                    'impact': 'Service interruption if not renewed'
                })
                recommendations.append('Schedule certificate renewal')
        except ValueError:
            vulnerabilities.append({
                'type': 'invalid_date_format',
                'severity': 'LOW',
                'description': 'Unable to parse certificate expiry date'
            })

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        if subject == issuer:
            vulnerabilities.append({
                'type': 'self_signed_certificate',
                'severity': 'HIGH',
                'description': 'Self-signed certificate detected',
                'impact': 'Untrusted by clients, no third-party validation'
            })
            recommendations.append('Obtain certificate from trusted CA')

        cert_info['vulnerabilities'] = vulnerabilities
        cert_info['recommendations'] = recommendations

    def _analyze_trust(self, cert):
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issuer_name = issuer.get('commonName', '').lower()
        trust_level = 'unknown'
        for ca, level in self.ca_trust_levels.items():
            if ca in issuer_name:
                trust_level = level
                break
        return {
            'issuer_name': issuer.get('commonName', 'Unknown'),
            'trust_level': trust_level,
            'is_ev_cert': bool(cert.get('subject', {}).get('businessCategory')),
            'is_dv_cert': not (cert.get('subject', {}).get('organizationName')),
            'is_wildcard': any(name.startswith('*.') for name in cert.get('subjectAltName', []))
        }

    def _analyze_extensions(self, cert):
        return {
            'subject_alt_names': [name[1] for name in cert.get('subjectAltName', [])],
            'key_usage': 'Not implemented - requires full cert parsing'
        }

    def _perform_additional_checks(self, hostname, port):
        return {
            'supported_protocols': self._check_supported_protocols(hostname, port),
            'hsts': self._check_hsts(hostname, port)
        }

    def _check_supported_protocols(self, hostname, port):
        protocols = {}
        test_protocols = [
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', getattr(ssl, 'PROTOCOL_TLS', ssl.PROTOCOL_TLSv1_2))
        ]
        for name, proto in test_protocols:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[name] = {'supported': True, 'version': ssock.version()}
            except Exception:
                protocols[name] = {'supported': False}
        return protocols

    def _check_hsts(self, hostname, port):
        try:
            resp = requests.get(f'https://{hostname}:{port}', timeout=10, verify=False)
            hsts = resp.headers.get('Strict-Transport-Security')
            return {
                'enabled': bool(hsts),
                'header': hsts,
                'max_age': re.search(r'max-age=(\d+)', hsts).group(1) if hsts else None
            } if hsts else {'enabled': False}
        except Exception as e:
            return {'error': str(e)}


# ========== ENHANCED HELPERS ==========
def grab_http_banner_enhanced(host, port=80, use_https=False):
    protocol = 'https' if use_https or port == 443 else 'http'
    url = f"{protocol}://{host}:{port}"
    try:
        headers = {
            'User-Agent': 'Reconborne-Enhanced/2.0',
            'Accept': '*/*',
            'Connection': 'close'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        title = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.I | re.S)
        tech_detector = TechStackDetector()
        tech_stack = tech_detector.detect_from_response(url, response.text, response.headers)
        js_libs = tech_detector.analyze_javascript_libraries(response.text)
        cdn_usage = tech_detector.detect_cdn_usage(url)
        return {
            'status_code': response.status_code,
            'server': response.headers.get('Server', 'Unknown'),
            'title': title.group(1).strip() if title else "",
            'tech_stack': tech_stack,
            'javascript_libraries': js_libs,
            'cdn_usage': cdn_usage,
            'security_headers': {
                'x-frame-options': response.headers.get('X-Frame-Options'),
                'content-security-policy': response.headers.get('Content-Security-Policy'),
                'strict-transport-security': response.headers.get('Strict-Transport-Security'),
            },
            'response_analysis': {
                'size': len(response.text),
                'load_time': response.elapsed.total_seconds()
            }
        }
    except Exception as e:
        return {'error': str(e)}

def grab_ssh_banner(host, port=22):
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            banner = s.recv(1024).decode(errors="ignore").strip()
            impl = 'OpenSSH' if 'openssh' in banner.lower() else 'Unknown'
            return {'banner': banner, 'version': banner.split(' ')[0], 'implementation': impl}
    except Exception as e:
        return {'error': str(e)}

def recon_subdomains(domain):
    subdomains = set()
    common_subdomains = ['www', 'mail', 'admin', 'api', 'dev', 'test', 'blog', 'shop']
    if DNS_AVAILABLE:
        for sub in common_subdomains:
            try:
                full = f"{sub}.{domain}"
                dns.resolver.resolve(full, 'A')
                subdomains.add(full)
            except Exception:
                continue
    return list(subdomains)

def passive_network_analysis(duration=30):
    try:
        cmd = ["tshark", "-a", f"duration:{duration}", "-q", "-z", "io,phs"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=duration + 10)
        return {'summary': [line for line in output.splitlines() if '%' in line]}
    except Exception as e:
        return {'error': str(e)}

def vulnerability_correlation(tech_stack, open_ports):
    vulnerabilities = []
    tech_vulns = {
        'wordpress': {'severity': 'Medium', 'common_vulns': ['Plugin vulns', 'Outdated core']},
        'apache': {'severity': 'Low', 'common_vulns': ['Module vulns', 'DoS']},
        'php': {'severity': 'Medium', 'common_vulns': ['Code injection', 'File inclusion']}
    }
    port_vulns = {
        21: {'service': 'FTP', 'severity': 'Medium', 'common_vulns': ['Brute force']},
        22: {'service': 'SSH', 'severity': 'Low', 'common_vulns': ['Brute force']},
        23: {'service': 'Telnet', 'severity': 'High', 'common_vulns': ['Unencrypted']},
        80: {'service': 'HTTP', 'severity': 'Medium', 'common_vulns': ['Web attacks']},
        443: {'service': 'HTTPS', 'severity': 'Low', 'common_vulns': ['Misconfigurations']},
        445: {'service': 'SMB', 'severity': 'High', 'common_vulns': ['EternalBlue']},
    }
    for tech, info in tech_vulns.items():
        if any(tech in cat for cat in tech_stack.values()):
            vulnerabilities.append({'technology': tech, **info})
    for port in open_ports:
        p = port.get('port')
        if p in port_vulns:
            vulnerabilities.append({'port': p, **port_vulns[p]})
    return vulnerabilities

def generate_enhanced_nmap_scan(target):
    try:
        cmd = ["nmap", "-sV", "-sC", "-O", "-T4", "-p-", "-oX", "-", target]
        xml_output = subprocess.check_output(cmd, text=True, timeout=300)
        root = ET.fromstring(xml_output)
        result = {"ports": [], "os_detection": {}}
        for host in root.findall("host"):
            for os in host.findall(".//osmatch"):
                result["os_detection"] = {"name": os.get("name"), "accuracy": os.get("accuracy")}
            for port in host.findall("./ports/port"):
                if port.find("state").get("state") == "open":
                    service = port.find("service")
                    result["ports"].append({
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "service": service.get("name") if service is not None else "",
                        "version": service.get("version") if service is not None else "",
                        "scripts": {s.get("id"): s.get("output") for s in port.findall(".//script")}
                    })
        return result
    except Exception as e:
        return {"error": str(e), "ports": []}

def generate_comprehensive_report(enriched_data, target):
    if model:
        try:
            prompt = f"Generate a detailed markdown security report for {target}:\n\n```json\n{json.dumps(enriched_data, indent=2)}\n```"
            response = model.generate_content(prompt)
            return response.text.strip() or generate_fallback_report(enriched_data, target)
        except Exception as e:
            console.print(f"[red]AI report failed: {e}[/red]")
    return generate_fallback_report(enriched_data, target)

def generate_fallback_report(data, target):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""# Reconnaissance Report: {target}
**Generated:** {timestamp}

## 🔍 Open Ports
{chr(10).join(f"- {p['port']}/{p['protocol']}: {p['service']} {p['version']}" for p in data.get('nmap', {}).get('ports', []))}

## 🛠️ Technologies
{chr(10).join(f"- {cat}: {', '.join(techs)}" for cat, techs in data.get('http_enhanced', {}).get('tech_stack', {}).items() if techs)}

## 🚨 Vulnerabilities
{chr(10).join(f"- {v.get('technology') or v.get('port')}: {', '.join(v.get('common_vulns', []))}" for v in data.get('vulnerabilities', []))}

---
*Generated by Reconborne v2.0*"""


# ========== MAIN SCAN FUNCTION ==========
@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument("target", required=False)
@click.option("--output", "-o", default=None, type=str,
              help="Output file (default: <target>-report.md)")
@click.option("--timeout", "-t", default=None, type=int,
              help="Scan timeout in seconds")
@click.option("--threads", default=None, type=int,
              help="Number of threads for concurrent operations")
@click.option("--no-passive", is_flag=True,
              help="Skip passive network analysis")
@click.option("--quick", "-q", is_flag=True,
              help="Quick scan mode (faster, less thorough)")
@click.option("--verbose", "-v", is_flag=True,
              help="Enable verbose output")
def scan(target, output, timeout, threads, no_passive, quick, verbose):
    """
    Enhanced AI-driven reconnaissance tool.

    TARGET: IP address or domain name to scan (e.g., example.com, 192.168.1.1)

    Examples:
      python3 reconborne.py example.com
      python3 reconborne.py example.com --quick -o report.md
      python3 reconborne.py 192.168.1.1 --no-passive --threads 5
    """
    if not target:
        console.print("[red][!] Target is required. Use: reconborne.py <target>[/red]")
        console.print("[dim]Run 'python3 reconborne.py --help' for usage details.[/dim]")
        return

    # Configure based on options
    if quick:
        config.config['timeouts'] = {k: min(v, 5) for k, v in config.config['timeouts'].items()}
        config.config['scan_options']['passive_duration'] = 10
    if timeout:
        config.config['timeouts']['subprocess'] = int(timeout)
    if threads:
        config.config['scan_options']['max_threads'] = int(threads)

    console.print(f"[bold blue]🎯 Starting reconnaissance on {target}[/bold blue]")
    if verbose:
        console.print(f"[dim]Config: Threads={config.get('scan_options.max_threads')}, "
                     f"Timeout={config.get('timeouts.subprocess')}s, Quick={quick}[/dim]")

    start_time = time.time()
    enriched_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scan_config": {
            "quick_mode": quick,
            "passive_analysis": not no_passive,
            "threads": config.get('scan_options.max_threads'),
            "timeout": config.get('timeouts.subprocess'),
            "verbose": verbose
        }
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:

        # Task 1: Port Scanning
        task1 = progress.add_task("🔍 Running port scan...", total=None)
        enriched_data["nmap"] = generate_enhanced_nmap_scan(target)
        progress.update(task1, completed=1)

        # Task 2: HTTP Analysis
        task2 = progress.add_task("🌐 Analyzing web services...", total=None)
        http_result = grab_http_banner_enhanced(target, 80, False)
        open_ports = [p.get('port', 0) for p in enriched_data["nmap"].get("ports", [])]
        https_result = {}
        if 443 in open_ports:
            https_result = grab_http_banner_enhanced(target, 443, True)
        enriched_data["http"] = http_result
        enriched_data["https"] = https_result
        enriched_data["http_enhanced"] = https_result if https_result else http_result
        progress.update(task2, completed=1)

        # Task 3: Certificate Analysis
        task3 = progress.add_task("🔒 Analyzing SSL/TLS certificate...", total=None)
        if 443 in open_ports:
            cert_analyzer = CertificateAnalyzer()
            enriched_data["certificate"] = cert_analyzer.analyze_certificate(target, 443)
        else:
            enriched_data["certificate"] = {"note": "HTTPS not available"}
        progress.update(task3, completed=1)

        # Task 4: SSH Analysis
        task4 = progress.add_task("🔑 Analyzing SSH service...", total=None)
        enriched_data["ssh"] = grab_ssh_banner(target, 22)
        progress.update(task4, completed=1)

        # Task 5: Subdomain Enumeration
        task5 = progress.add_task("🌐 Enumerating subdomains...", total=None)
        enriched_data["subdomains"] = recon_subdomains(target)
        progress.update(task5, completed=1)

        # Task 6: Passive Analysis
        if not no_passive and config.get('scan_options.enable_passive_scan'):
            duration = config.get('scan_options.passive_duration', 30)
            task6 = progress.add_task(f"📡 Passive analysis ({duration}s)...", total=None)
            enriched_data["passive"] = passive_network_analysis(duration)
            progress.update(task6, completed=1)
        else:
            enriched_data["passive"] = {"skipped": True}

        # Task 7: Vulnerability Correlation
        task7 = progress.add_task("🚨 Correlating vulnerabilities...", total=None)
        tech_stack = enriched_data["http_enhanced"].get("tech_stack", {})
        open_ports_list = enriched_data["nmap"].get("ports", [])
        enriched_data["vulnerabilities"] = vulnerability_correlation(tech_stack, open_ports_list)
        progress.update(task7, completed=1)

    # Generate Report
    report = generate_comprehensive_report(enriched_data, target)
    output_file = output or f"{target}-report.md"
    with open(output_file, "w") as f:
        f.write(report)

    elapsed = time.time() - start_time
    console.print(f"[green]✅ Scan complete! Report saved to:[/green] {output_file}")
    console.print(f"[dim]⏱️  Total time: {elapsed:.2f} seconds[/dim]")


if __name__ == "__main__":
    scan()
