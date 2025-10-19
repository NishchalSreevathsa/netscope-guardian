"""
NetScope Guardian Backend
AI-powered threat intelligence API using Google Gemini Flash 2.0
"""

import os
import re
import asyncio
import hashlib
import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import logging

import httpx
import google.generativeai as genai
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
print("Loaded API Key:", api_key)  # For debugging only
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="NetScope Guardian API",
    description="AI-powered browser threat contextualizer",
    version="1.0.0"
)

# CORS configuration for Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://localhost:*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini AI
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'your-gemini-api-key-here')
genai.configure(api_key=GEMINI_API_KEY)

# Initialize Gemini model
try:
    model = genai.GenerativeModel('gemini-2.0-flash-exp')  # Using Gemini Flash 2.0
    logger.info("Gemini Flash 2.0 model initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Gemini model: {e}")
    model = None

# Request/Response Models
class ThreatAnalysisRequest(BaseModel):
    indicator: str
    
    @validator('indicator')
    def validate_indicator(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Indicator cannot be empty')
        if len(v) > 500:  # Reasonable limit
            raise ValueError('Indicator too long')
        return v.strip()

class SecurityHeadersRequest(BaseModel):
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError('Invalid URL format')
            return v
        except Exception:
            raise ValueError('Invalid URL format')

class NetworkAuditRequest(BaseModel):
    requests: List[Dict[str, Any]]
    suspicious_activity: List[Dict[str, Any]]

class ThreatAnalysisResponse(BaseModel):
    indicator: str
    type: str
    threat_score: str
    gemini_analysis: str
    reputation_data: Dict[str, Any]
    recommendations: List[str]
    timestamp: str
    sources: List[str]

class SecurityHeadersResponse(BaseModel):
    url: str
    headers: Dict[str, str]
    missing_headers: List[str]
    security_score: int
    gemini_analysis: str
    recommendations: List[str]
    timestamp: str

# Utility Classes
class IndicatorAnalyzer:
    """Analyzes different types of security indicators"""
    
    @staticmethod
    def detect_type(indicator: str) -> str:
        """Detect the type of indicator"""
        patterns = {
            'IP': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
            'DOMAIN': re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'),
            'URL': re.compile(r'^https?://.*'),
            'HASH_MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
            'HASH_SHA1': re.compile(r'^[a-fA-F0-9]{40}$'),
            'HASH_SHA256': re.compile(r'^[a-fA-F0-9]{64}$'),
            'EMAIL': re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
        }
        
        for ioc_type, pattern in patterns.items():
            if pattern.match(indicator):
                if ioc_type.startswith('HASH_'):
                    return 'HASH'
                return ioc_type
        
        return 'UNKNOWN'
    
    @staticmethod
    async def get_reputation_data(indicator: str, ioc_type: str) -> Dict[str, Any]:
        """Get reputation data from various sources"""
        reputation = {}
        
        try:
            if ioc_type == 'IP':
                reputation.update(await IndicatorAnalyzer._analyze_ip(indicator))
            elif ioc_type == 'DOMAIN':
                reputation.update(await IndicatorAnalyzer._analyze_domain(indicator))
            elif ioc_type == 'URL':
                reputation.update(await IndicatorAnalyzer._analyze_url(indicator))
            elif ioc_type == 'HASH':
                reputation.update(await IndicatorAnalyzer._analyze_hash(indicator))
        except Exception as e:
            logger.error(f"Error getting reputation data: {e}")
            reputation['error'] = str(e)
        
        return reputation
    
    @staticmethod
    async def _analyze_ip(ip: str) -> Dict[str, Any]:
        """Analyze IP address"""
        data = {}
        
        # Check if IP is private/reserved
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            data['is_private'] = ip_obj.is_private
            data['is_reserved'] = ip_obj.is_reserved
            data['is_multicast'] = ip_obj.is_multicast
            data['is_loopback'] = ip_obj.is_loopback
        except Exception:
            data['is_private'] = False
        
        # Basic geolocation (simplified)
        try:
            # In production, you would use a proper geolocation service
            data['location'] = 'Location lookup not implemented'
        except Exception:
            data['location'] = 'Unknown'
        
        # Check common malicious patterns
        suspicious_patterns = [
            '192.168.',  # Private networks in public contexts
            '10.',       # Private networks
            '172.16.',   # Private networks
        ]
        
        data['suspicious_patterns'] = any(ip.startswith(pattern) for pattern in suspicious_patterns)
        
        return data
    
    @staticmethod
    async def _analyze_domain(domain: str) -> Dict[str, Any]:
        """Analyze domain"""
        data = {}
        
        try:
            # DNS resolution check
            import socket
            ip = socket.gethostbyname(domain)
            data['resolved_ip'] = ip
            data['dns_resolves'] = True
        except Exception:
            data['dns_resolves'] = False
            data['resolved_ip'] = None
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.bit']
        data['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Domain age estimation (simplified)
        data['estimated_age'] = 'Unknown'
        
        # Entropy analysis (domains with high entropy might be DGA)
        import math
        entropy = -sum((domain.count(c)/len(domain)) * math.log2(domain.count(c)/len(domain)) 
                      for c in set(domain))
        data['entropy'] = round(entropy, 2)
        data['high_entropy'] = entropy > 4.0  # Threshold for suspicious entropy
        
        return data
    
    @staticmethod
    async def _analyze_url(url: str) -> Dict[str, Any]:
        """Analyze URL"""
        data = {}
        
        try:
            parsed = urlparse(url)
            data['scheme'] = parsed.scheme
            data['domain'] = parsed.netloc
            data['path'] = parsed.path
            data['query'] = parsed.query
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                'bit.ly', 'tinyurl.com', 'goo.gl',  # URL shorteners
                'login', 'signin', 'verify',        # Phishing keywords
                'secure', 'account', 'update',      # Common phishing terms
                'base64', 'eval', 'unescape'        # Potential malicious scripts
            ]
            
            data['suspicious_patterns'] = [p for p in suspicious_patterns if p in url.lower()]
            data['has_suspicious_patterns'] = len(data['suspicious_patterns']) > 0
            
            # URL length analysis
            data['url_length'] = len(url)
            data['long_url'] = len(url) > 200  # Threshold for long URLs
            
            # Check for obfuscation
            data['encoded_content'] = 'base64' in url.lower() or '%' in url
            
        except Exception as e:
            data['parse_error'] = str(e)
        
        return data
    
    @staticmethod
    async def _analyze_hash(hash_value: str) -> Dict[str, Any]:
        """Analyze file hash"""
        data = {}
        
        # Determine hash type
        if len(hash_value) == 32:
            data['hash_type'] = 'MD5'
        elif len(hash_value) == 40:
            data['hash_type'] = 'SHA1'
        elif len(hash_value) == 64:
            data['hash_type'] = 'SHA256'
        else:
            data['hash_type'] = 'Unknown'
        
        # In production, you would check against malware databases
        data['known_malware'] = False
        data['detection_ratio'] = '0/0'
        data['first_seen'] = 'Unknown'
        data['last_seen'] = 'Unknown'
        
        return data

class SecurityHeadersAnalyzer:
    """Analyzes HTTP security headers"""
    
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'description': 'Prevents XSS and data injection attacks',
            'severity': 'HIGH'
        },
        'Strict-Transport-Security': {
            'description': 'Enforces secure HTTPS connections',
            'severity': 'HIGH'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'severity': 'MEDIUM'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME type sniffing',
            'severity': 'MEDIUM'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'severity': 'LOW'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features and APIs',
            'severity': 'MEDIUM'
        }
    }
    
    @staticmethod
    async def analyze_headers(url: str) -> Dict[str, Any]:
        """Analyze security headers for a given URL"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.head(url, follow_redirects=True)
                headers = dict(response.headers)
        except Exception as e:
            logger.error(f"Failed to fetch headers for {url}: {e}")
            return {
                'error': f'Failed to fetch headers: {str(e)}',
                'headers': {},
                'missing_headers': list(SecurityHeadersAnalyzer.SECURITY_HEADERS.keys())
            }
        
        # Analyze present and missing headers
        present_headers = {}
        missing_headers = []
        
        for header_name, header_info in SecurityHeadersAnalyzer.SECURITY_HEADERS.items():
            header_key = header_name.lower()
            if header_key in {k.lower() for k in headers.keys()}:
                # Find the actual header with case-insensitive match
                actual_key = next(k for k in headers.keys() if k.lower() == header_key)
                present_headers[header_name] = headers[actual_key]
            else:
                missing_headers.append(header_name)
        
        # Calculate security score
        total_headers = len(SecurityHeadersAnalyzer.SECURITY_HEADERS)
        present_count = len(present_headers)
        score = int((present_count / total_headers) * 100)
        
        return {
            'headers': present_headers,
            'missing_headers': missing_headers,
            'security_score': score,
            'all_headers': headers
        }

class GeminiAnalyzer:
    """Handles AI analysis using Google Gemini"""
    
    @staticmethod
    async def analyze_threat(indicator: str, ioc_type: str, reputation_data: Dict[str, Any]) -> str:
        """Generate AI analysis for threat indicators"""
        if not model:
            return "AI analysis unavailable - Gemini model not initialized"
        
        try:
            prompt = f"""
            Analyze this cybersecurity indicator and provide a clear, professional assessment:
            
            Indicator: {indicator}
            Type: {ioc_type}
            Reputation Data: {reputation_data}
            
            Please provide:
            1. A threat assessment explaining WHY this indicator might be risky
            2. Context about similar threats or attack patterns
            3. Potential impact if this is malicious
            4. Plain English explanation suitable for both beginners and experts
            
            Keep the response concise but informative, focusing on actionable insights.
            If the indicator appears benign, explain why. If it's suspicious, explain the specific risks.
            """
            
            response = model.generate_content(prompt)
            return response.text if response.text else "Unable to generate analysis"
            
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return f"AI analysis failed: {str(e)}"
    
    @staticmethod
    async def analyze_security_headers(url: str, headers_analysis: Dict[str, Any]) -> str:
        """Generate AI analysis for security headers"""
        if not model:
            return "AI analysis unavailable - Gemini model not initialized"
        
        try:
            prompt = f"""
            Analyze the security posture of this website based on its HTTP headers:
            
            URL: {url}
            Present Headers: {headers_analysis.get('headers', {})}
            Missing Headers: {headers_analysis.get('missing_headers', [])}
            Security Score: {headers_analysis.get('security_score', 0)}/100
            
            Explain in plain English:
            1. What these security headers do and why they matter
            2. Which missing headers are most critical and why
            3. Specific risks the website faces without proper headers
            4. Overall security assessment and recommendations
            
            Make it educational - explain concepts clearly for users learning about web security.
            """
            
            response = model.generate_content(prompt)
            return response.text if response.text else "Unable to generate security analysis"
            
        except Exception as e:
            logger.error(f"Security headers analysis failed: {e}")
            return f"Security analysis failed: {str(e)}"

# API Routes
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "NetScope Guardian API",
        "version": "1.0.0",
        "status": "operational",
        "gemini_available": model is not None
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "gemini_available": model is not None
    }

@app.post("/threat-summary", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """Analyze threat indicators with AI-powered insights"""
    try:
        indicator = request.indicator
        
        # Detect indicator type
        ioc_type = IndicatorAnalyzer.detect_type(indicator)
        
        # Get reputation data
        reputation_data = await IndicatorAnalyzer.get_reputation_data(indicator, ioc_type)
        
        # Determine threat score based on reputation data
        threat_score = await _calculate_threat_score(reputation_data, ioc_type)
        
        # Get AI analysis
        gemini_analysis = await GeminiAnalyzer.analyze_threat(indicator, ioc_type, reputation_data)
        
        # Generate recommendations
        recommendations = _generate_recommendations(ioc_type, threat_score, reputation_data)
        
        # Generate sources list
        sources = _generate_sources(ioc_type)
        
        return ThreatAnalysisResponse(
            indicator=indicator,
            type=ioc_type,
            threat_score=threat_score,
            gemini_analysis=gemini_analysis,
            reputation_data=reputation_data,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat(),
            sources=sources
        )
        
    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/headers", response_model=SecurityHeadersResponse)
async def analyze_security_headers(request: SecurityHeadersRequest):
    """Analyze security headers with AI-powered assessment"""
    try:
        url = request.url
        
        # Analyze headers
        headers_analysis = await SecurityHeadersAnalyzer.analyze_headers(url)
        
        # Get AI analysis
        gemini_analysis = await GeminiAnalyzer.analyze_security_headers(url, headers_analysis)
        
        # Generate recommendations
        recommendations = _generate_header_recommendations(headers_analysis.get('missing_headers', []))
        
        return SecurityHeadersResponse(
            url=url,
            headers=headers_analysis.get('headers', {}),
            missing_headers=headers_analysis.get('missing_headers', []),
            security_score=headers_analysis.get('security_score', 0),
            gemini_analysis=gemini_analysis,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Headers analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Headers analysis failed: {str(e)}")

@app.post("/network-audit")
async def audit_network_activity(request: NetworkAuditRequest):
    """Audit network activity for suspicious patterns"""
    try:
        # Analyze network requests
        analysis = {
            'total_requests': len(request.requests),
            'suspicious_count': len(request.suspicious_activity),
            'risk_level': _calculate_network_risk(request.suspicious_activity),
            'patterns_detected': _analyze_network_patterns(request.requests),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Get AI analysis for suspicious activity
        if request.suspicious_activity:
            gemini_prompt = f"""
            Analyze this suspicious network activity for security threats:
            
            Suspicious Requests: {request.suspicious_activity[:5]}  # Limit for prompt size
            
            Explain:
            1. What makes these requests suspicious
            2. Potential security implications
            3. Recommended actions
            """
            
            if model:
                try:
                    response = model.generate_content(gemini_prompt)
                    analysis['ai_assessment'] = response.text
                except Exception as e:
                    analysis['ai_assessment'] = f"AI analysis failed: {str(e)}"
            else:
                analysis['ai_assessment'] = "AI analysis unavailable"
        
        return analysis
        
    except Exception as e:
        logger.error(f"Network audit failed: {e}")
        raise HTTPException(status_code=500, detail=f"Network audit failed: {str(e)}")

# Helper Functions
async def _calculate_threat_score(reputation_data: Dict[str, Any], ioc_type: str) -> str:
    """Calculate threat score based on reputation data"""
    score = 0
    
    try:
        if ioc_type == 'IP':
            if reputation_data.get('is_private', False):
                score += 1  # Private IPs in public context can be suspicious
            if reputation_data.get('suspicious_patterns', False):
                score += 2
        
        elif ioc_type == 'DOMAIN':
            if reputation_data.get('suspicious_tld', False):
                score += 3
            if reputation_data.get('high_entropy', False):
                score += 2
            if not reputation_data.get('dns_resolves', True):
                score += 1
        
        elif ioc_type == 'URL':
            if reputation_data.get('has_suspicious_patterns', False):
                score += len(reputation_data.get('suspicious_patterns', []))
            if reputation_data.get('long_url', False):
                score += 1
            if reputation_data.get('encoded_content', False):
                score += 2
        
        elif ioc_type == 'HASH':
            if reputation_data.get('known_malware', False):
                score += 5
        
        # Convert score to category
        if score >= 4:
            return 'CRITICAL'
        elif score >= 3:
            return 'HIGH'
        elif score >= 2:
            return 'MEDIUM'
        elif score >= 1:
            return 'LOW'
        else:
            return 'CLEAN'
    
    except Exception as e:
        logger.error(f"Error calculating threat score: {e}")
        return 'UNKNOWN'

def _generate_recommendations(ioc_type: str, threat_score: str, reputation_data: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    if threat_score in ['CRITICAL', 'HIGH']:
        recommendations.extend([
            "Block this indicator immediately",
            "Check logs for related connections",
            "Investigate potential compromise",
            "Consider threat hunting activities"
        ])
    elif threat_score == 'MEDIUM':
        recommendations.extend([
            "Monitor this indicator closely",
            "Review related network traffic",
            "Consider adding to watchlist"
        ])
    elif threat_score == 'LOW':
        recommendations.extend([
            "Monitor for changes in reputation",
            "Document for future reference"
        ])
    else:
        recommendations.extend([
            "Continue normal monitoring",
            "No immediate action required"
        ])
    
    # Add type-specific recommendations
    if ioc_type == 'DOMAIN':
        if reputation_data.get('high_entropy'):
            recommendations.append("Investigate for possible DGA (Domain Generation Algorithm)")
        if reputation_data.get('suspicious_tld'):
            recommendations.append("Be cautious of suspicious top-level domain")
    
    elif ioc_type == 'URL':
        if reputation_data.get('encoded_content'):
            recommendations.append("Analyze encoded content for malicious payload")
        if reputation_data.get('has_suspicious_patterns'):
            recommendations.append("Review for phishing or social engineering indicators")
    
    return recommendations

def _generate_sources(ioc_type: str) -> List[str]:
    """Generate list of recommended sources for further investigation"""
    base_sources = ["Internal logs", "SIEM alerts", "Network monitoring"]
    
    if ioc_type in ['IP', 'DOMAIN', 'URL']:
        base_sources.extend([
            "VirusTotal",
            "AbuseIPDB",
            "Hybrid Analysis",
            "URLVoid"
        ])
    
    if ioc_type == 'HASH':
        base_sources.extend([
            "VirusTotal",
            "Malware Bazaar",
            "Hybrid Analysis"
        ])
    
    return base_sources

def _generate_header_recommendations(missing_headers: List[str]) -> List[str]:
    """Generate recommendations for missing security headers"""
    recommendations = []
    
    header_recommendations = {
        'Content-Security-Policy': "Implement CSP to prevent XSS and data injection attacks",
        'Strict-Transport-Security': "Enable HSTS to enforce secure connections",
        'X-Frame-Options': "Add X-Frame-Options to prevent clickjacking",
        'X-Content-Type-Options': "Set X-Content-Type-Options to prevent MIME sniffing",
        'Referrer-Policy': "Configure Referrer-Policy to control information leakage",
        'Permissions-Policy': "Use Permissions-Policy to restrict browser features"
    }
    
    for header in missing_headers:
        if header in header_recommendations:
            recommendations.append(header_recommendations[header])
    
    if not recommendations:
        recommendations.append("All critical security headers are present")
    
    recommendations.append("Regularly review and update security headers")
    recommendations.append("Test header configuration with security tools")
    
    return recommendations

def _calculate_network_risk(suspicious_activity: List[Dict[str, Any]]) -> str:
    """Calculate overall network risk level"""
    if not suspicious_activity:
        return 'LOW'
    
    critical_count = sum(1 for activity in suspicious_activity 
                        if activity.get('severity') == 'CRITICAL')
    high_count = sum(1 for activity in suspicious_activity 
                    if activity.get('severity') == 'HIGH')
    
    if critical_count > 0:
        return 'CRITICAL'
    elif high_count > 2:
        return 'HIGH'
    elif len(suspicious_activity) > 5:
        return 'MEDIUM'
    else:
        return 'LOW'

def _analyze_network_patterns(requests: List[Dict[str, Any]]) -> List[str]:
    """Analyze network requests for suspicious patterns"""
    patterns = []
    
    # Group requests by domain
    domain_counts = {}
    for request in requests:
        try:
            domain = urlparse(request.get('url', '')).netloc
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except:
            continue
    
    # Check for excessive requests to single domain
    for domain, count in domain_counts.items():
        if count > 20:  # Threshold for suspicious activity
            patterns.append(f"High request volume to {domain} ({count} requests)")
    
    # Check for suspicious timing patterns
    timestamps = [req.get('timestamp', 0) for req in requests if req.get('timestamp')]
    if timestamps:
        timestamps.sort()
        # Check for rapid-fire requests (possible bot activity)
        rapid_requests = sum(1 for i in range(1, len(timestamps)) 
                           if timestamps[i] - timestamps[i-1] < 100)  # 100ms threshold
        
        if rapid_requests > 10:
            patterns.append(f"Rapid request pattern detected ({rapid_requests} rapid requests)")
    
    return patterns

# Error Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )

# Main execution
if __name__ == "__main__":
    # Environment configuration
    PORT = int(os.getenv('PORT', 8000))
    HOST = os.getenv('HOST', '127.0.0.1')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"""
    🛡️  NetScope Guardian Backend Starting
    
    🚀 Server: http://{HOST}:{PORT}
    🤖 Gemini AI: {'✅ Connected' if model else '❌ Not Available'}
    🔧 Debug Mode: {'✅ Enabled' if DEBUG else '❌ Disabled'}
    
    📚 API Documentation: http://{HOST}:{PORT}/docs
    🔍 Health Check: http://{HOST}:{PORT}/health
    """)
    
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=DEBUG,
        log_level="info" if not DEBUG else "debug"
    )
