from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import requests
from bs4 import BeautifulSoup
import ssl
import socket
from typing import Dict, List, Optional, Tuple, Any
import urllib3
from urllib.parse import urlparse
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL.SSL
from OpenSSL.SSL import Context, Connection
import idna
import re
import html
import certifi
import dns.resolver

app = FastAPI(
    title="ShieldCheck API",
    description="API for checking website security parameters",
    version="1.0.0"
)

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:3000",    # For React default port
    "http://localhost:8000",    # For local development
    "http://localhost:8001",    # For local development alternate port
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
    "http://127.0.0.1:3000",
    # Add your production domains here
    # "https://yourdomain.com",
    # "https://api.yourdomain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],        # Allows all methods
    allow_headers=["*"],        # Allows all headers
    expose_headers=["*"],       # Expose all headers
    max_age=600,               # Cache preflight requests for 10 minutes
)

class WebsiteRequest(BaseModel):
    url: HttpUrl

class SecurityResponse(BaseModel):
    is_safe: bool
    overall_score: float
    security_headers: Dict[str, str]
    ssl_info: Dict[str, str]
    recommendations: List[str]
    phishing_check: Dict[str, Any]
    malware_check: Dict[str, Any]
    xss_check: Dict[str, Any]
    csrf_check: Dict[str, Any]
    ct_check: Dict[str, Any]

def get_certificate_info(hostname: str) -> Dict[str, str]:
    try:
        # Create SSL context with system certificates
        context = ssl.create_default_context()
        
        # Create connection
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    return {"error": "No certificate found"}
                
                # Convert subject and issuer to string format
                subject_dict = dict(x[0] for x in cert['subject'])
                issuer_dict = dict(x[0] for x in cert['issuer'])
                
                subject_str = ", ".join(f"{k}={v}" for k, v in subject_dict.items())
                issuer_str = ", ".join(f"{k}={v}" for k, v in issuer_dict.items())
                
                cert_info = {
                    "subject": subject_str,
                    "issuer": issuer_str,
                    "version": str(cert.get('version', 'unknown')),
                    "serial_number": cert.get('serialNumber', 'unknown'),
                    "not_before": cert.get('notBefore', 'unknown'),
                    "not_after": cert.get('notAfter', 'unknown'),
                    "protocol_version": ssock.version(),
                    "cipher": ssock.cipher()[0],
                    "bits": str(ssock.cipher()[2])
                }
                
                return cert_info
                
    except ssl.SSLError as e:
        return {"error": f"SSL verification failed: {str(e)}"}
    except socket.gaierror as e:
        return {"error": f"DNS lookup failed: {str(e)}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except Exception as e:
        return {"error": f"Connection failed: {str(e)}"}

def check_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    # Convert headers to lowercase for case-insensitive comparison
    headers = {k.lower(): v for k, v in headers.items()}
    
    header_checks = {
        'strict-transport-security': {
            'key': 'Strict-Transport-Security',
            'missing': 'Missing HSTS header',
            'check': lambda v: 'max-age=' in v.lower()
        },
        'content-security-policy': {
            'key': 'Content-Security-Policy',
            'missing': 'Missing CSP',
            'check': lambda v: any(d in v.lower() for d in ['default-src', 'script-src'])
        },
        'x-frame-options': {
            'key': 'X-Frame-Options',
            'missing': 'Missing X-Frame-Options',
            'check': lambda v: v.upper() in ['DENY', 'SAMEORIGIN']
        },
        'x-content-type-options': {
            'key': 'X-Content-Type-Options',
            'missing': 'Missing X-Content-Type-Options',
            'check': lambda v: v.lower() == 'nosniff'
        },
        'x-xss-protection': {
            'key': 'X-XSS-Protection',
            'missing': 'Missing XSS Protection',
            'check': lambda v: v in ['1', '1; mode=block']
        },
        'referrer-policy': {
            'key': 'Referrer-Policy',
            'missing': 'Missing Referrer Policy',
            'check': lambda v: any(p in v.lower() for p in ['no-referrer', 'strict-origin', 'same-origin'])
        },
        'permissions-policy': {
            'key': 'Permissions-Policy',
            'missing': 'Missing Permissions Policy',
            'check': lambda v: len(v) > 0
        },
        'cross-origin-opener-policy': {
            'key': 'Cross-Origin-Opener-Policy',
            'missing': 'Missing COOP',
            'check': lambda v: v.lower() in ['same-origin', 'same-origin-allow-popups']
        },
        'cross-origin-embedder-policy': {
            'key': 'Cross-Origin-Embedder-Policy',
            'missing': 'Missing COEP',
            'check': lambda v: v.lower() == 'require-corp'
        },
        'cross-origin-resource-policy': {
            'key': 'Cross-Origin-Resource-Policy',
            'missing': 'Missing CORP',
            'check': lambda v: v.lower() in ['same-site', 'same-origin', 'cross-origin']
        }
    }
    
    results = {}
    for header_key, check_info in header_checks.items():
        value = headers.get(header_key)
        if not value:
            results[check_info['key']] = check_info['missing']
        else:
            if check_info['check'](value):
                results[check_info['key']] = value
            else:
                results[check_info['key']] = f"Invalid value: {value}"
    
    return results

def calculate_safety_score(ssl_info: Dict[str, str], security_headers: Dict[str, str]) -> float:
    score = 0.0
    
    # SSL scoring (40% of total)
    if not ssl_info.get('error'):
        score += 20  # Basic SSL present
        
        # Check protocol version (up to 10%)
        protocol = ssl_info.get('protocol_version', '').upper()
        if 'TLSV1.3' in protocol:
            score += 10
        elif 'TLSV1.2' in protocol:
            score += 7
        elif 'TLSV1.1' in protocol:
            score += 3
        
        # Check certificate validity (up to 10%)
        try:
            not_after = datetime.strptime(ssl_info['not_after'], '%b %d %H:%M:%S %Y GMT')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry > 90:  # More than 90 days
                score += 10
            elif days_until_expiry > 30:  # More than 30 days
                score += 7
            elif days_until_expiry > 0:  # Valid but expiring soon
                score += 3
        except:
            pass
    
    # Security headers scoring (60% of total)
    header_scores = {
        'Strict-Transport-Security': 8,
        'Content-Security-Policy': 8,
        'X-Frame-Options': 6,
        'X-Content-Type-Options': 6,
        'X-XSS-Protection': 6,
        'Referrer-Policy': 6,
        'Permissions-Policy': 5,
        'Cross-Origin-Opener-Policy': 5,
        'Cross-Origin-Embedder-Policy': 5,
        'Cross-Origin-Resource-Policy': 5
    }
    
    for header, value in security_headers.items():
        if not value.startswith(('Missing', 'Invalid')):
            score += header_scores.get(header, 0)
    
    return min(100, round(score, 2))  # Cap at 100%

def generate_recommendations(ssl_info: Dict[str, str], security_headers: Dict[str, str]) -> List[str]:
    recommendations = []
    
    # SSL recommendations
    if ssl_info.get('error'):
        recommendations.append("Implement proper SSL/TLS configuration")
    else:
        protocol = ssl_info.get('protocol_version', '').upper()
        if 'TLS1.3' not in protocol:
            recommendations.append("Upgrade to TLS 1.3 for better security")
        
        try:
            not_after = datetime.strptime(ssl_info['not_after'], '%Y%m%d%H%M%SZ')
            if datetime.now() > not_after:
                recommendations.append("SSL certificate has expired")
        except:
            pass
    
    # Security header recommendations
    for header, value in security_headers.items():
        if value.startswith('Missing'):
            recommendations.append(f"Add {header} header for improved security")
    
    return recommendations

def check_certificate_transparency(domain: str) -> Dict[str, Any]:
    try:
        # Query Certificate Transparency logs via crt.sh API
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        if response.status_code == 200:
            certs = response.json()
            return {
                "ct_status": "Monitored",
                "cert_count": len(certs),
                "latest_cert": certs[0] if certs else None
            }
        return {"ct_status": "Not found in CT logs"}
    except Exception as e:
        return {"ct_status": f"Error checking CT logs: {str(e)}"}

def check_phishing_indicators(url: str, html_content: str) -> Dict[str, Any]:
    indicators = {
        "suspicious_patterns": [],
        "risk_level": "low"
    }
    
    # Check for suspicious URL patterns
    suspicious_patterns = [
        r'paypal.*\.com',
        r'bank.*\.com',
        r'secure.*\.com',
        r'account.*\.com',
        r'login.*\.com',
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.I):
            indicators["suspicious_patterns"].append(f"Suspicious URL pattern: {pattern}")
    
    # Check for login forms
    if re.search(r'<form.*?password.*?</form>', html_content, re.I | re.S):
        indicators["suspicious_patterns"].append("Contains login form")
    
    # Set risk level based on findings
    if len(indicators["suspicious_patterns"]) > 2:
        indicators["risk_level"] = "high"
    elif len(indicators["suspicious_patterns"]) > 0:
        indicators["risk_level"] = "medium"
    
    return indicators

def check_xss_vulnerabilities(html_content: str) -> Dict[str, Any]:
    vulnerabilities = {
        "issues": [],
        "risk_level": "low"
    }
    
    # Check for common XSS vectors
    xss_patterns = [
        r'<script.*?>',
        r'javascript:',
        r'onerror=',
        r'onload=',
        r'onclick=',
        r'eval\(',
    ]
    
    for pattern in xss_patterns:
        matches = re.findall(pattern, html_content, re.I)
        if matches:
            vulnerabilities["issues"].append(f"Potential XSS vector found: {pattern}")
    
    # Set risk level based on findings
    if len(vulnerabilities["issues"]) > 2:
        vulnerabilities["risk_level"] = "high"
    elif len(vulnerabilities["issues"]) > 0:
        vulnerabilities["risk_level"] = "medium"
    
    return vulnerabilities

def check_csrf_protection(headers: Dict[str, str], html_content: str) -> Dict[str, Any]:
    csrf_check = {
        "has_protection": False,
        "issues": [],
        "recommendations": []
    }
    
    # Check for CSRF tokens in forms
    forms = re.findall(r'<form.*?</form>', html_content, re.I | re.S)
    for form in forms:
        if not re.search(r'csrf|token', form, re.I):
            csrf_check["issues"].append("Form found without CSRF token")
    
    # Check for CSRF headers
    csrf_headers = ['x-csrf-token', 'csrf-token', 'x-xsrf-token']
    if not any(header in headers.keys() for header in csrf_headers):
        csrf_check["issues"].append("No CSRF protection headers found")
        csrf_check["recommendations"].append("Implement CSRF tokens in headers")
    
    csrf_check["has_protection"] = len(csrf_check["issues"]) == 0
    return csrf_check

def check_malware_indicators(url: str, html_content: str) -> Dict[str, Any]:
    indicators = {
        "suspicious_patterns": [],
        "risk_level": "low"
    }
    
    # Check for suspicious patterns
    malware_patterns = [
        r'eval\(unescape\(',
        r'document\.write\(unescape\(',
        r'\.exe',
        r'\.dll',
        r'\\x[0-9a-fA-F]{2}',
        r'fromCharCode',
        r'<iframe.*?hidden',
    ]
    
    for pattern in malware_patterns:
        if re.search(pattern, html_content, re.I):
            indicators["suspicious_patterns"].append(f"Suspicious pattern found: {pattern}")
    
    # Check for suspicious external domains
    external_domains = re.findall(r'https?://([^\s/$.?#].[^\s]*)', html_content)
    for domain in external_domains:
        if re.search(r'(\.ru|\.cn|\.tk|\.top)$', domain, re.I):
            indicators["suspicious_patterns"].append(f"Suspicious domain: {domain}")
    
    # Set risk level based on findings
    if len(indicators["suspicious_patterns"]) > 2:
        indicators["risk_level"] = "high"
    elif len(indicators["suspicious_patterns"]) > 0:
        indicators["risk_level"] = "medium"
    
    return indicators

@app.post("/check-website", response_model=SecurityResponse)
async def check_website(request: WebsiteRequest):
    try:
        # Parse domain from URL
        parsed_url = urlparse(str(request.url))
        domain = parsed_url.netloc
        
        # Make request to the website
        response = requests.get(
            str(request.url),
            headers={'User-Agent': 'ShieldCheck Security Scanner/1.0'},
            verify=True,
            timeout=10
        )
        
        # Get HTML content
        html_content = response.text
        
        # Check SSL
        ssl_info = get_certificate_info(domain)
        
        # Check security headers
        security_headers = check_security_headers(dict(response.headers))
        
        # New security checks
        phishing_check = check_phishing_indicators(str(request.url), html_content)
        malware_check = check_malware_indicators(str(request.url), html_content)
        xss_check = check_xss_vulnerabilities(html_content)
        csrf_check = check_csrf_protection(dict(response.headers), html_content)
        ct_check = check_certificate_transparency(domain)
        
        # Calculate safety score (updated to include new checks)
        base_score = calculate_safety_score(ssl_info, security_headers)
        
        # Additional scoring based on new checks
        additional_score = 0
        if phishing_check["risk_level"] == "low":
            additional_score += 5
        if malware_check["risk_level"] == "low":
            additional_score += 5
        if xss_check["risk_level"] == "low":
            additional_score += 5
        if csrf_check["has_protection"]:
            additional_score += 5
        if ct_check.get("ct_status") == "Monitored":
            additional_score += 5
        
        final_score = min(100, base_score + additional_score)
        
        # Generate recommendations (including new checks)
        recommendations = generate_recommendations(ssl_info, security_headers)
        
        # Add recommendations from new checks
        if phishing_check["risk_level"] != "low":
            recommendations.append("Potential phishing indicators detected")
        if malware_check["risk_level"] != "low":
            recommendations.append("Potential malware indicators detected")
        if xss_check["risk_level"] != "low":
            recommendations.extend([f"Fix XSS vulnerability: {issue}" for issue in xss_check["issues"]])
        if not csrf_check["has_protection"]:
            recommendations.extend(csrf_check["recommendations"])
        if ct_check.get("ct_status") != "Monitored":
            recommendations.append("Certificate not found in CT logs")
        
        return SecurityResponse(
            is_safe=final_score >= 70,  # Consider safe if score is 70% or higher
            overall_score=final_score,
            security_headers=security_headers,
            ssl_info=ssl_info,
            recommendations=recommendations,
            phishing_check=phishing_check,
            malware_check=malware_check,
            xss_check=xss_check,
            csrf_check=csrf_check,
            ct_check=ct_check
        )
        
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Error checking website: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Welcome to ShieldCheck API",
        "docs": "/docs",
        "redoc": "/redoc"
    } 