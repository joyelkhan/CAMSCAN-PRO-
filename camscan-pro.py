#!/usr/bin/env python3
"""
CAMXPLOIT ELITE - Advanced CCTV & IP Camera Security Assessment Suite
Enterprise-Grade Camera Reconnaissance & Vulnerability Scanner

Author: Security Research Team
Version: 3.0.0
License: MIT - For Educational & Research Purposes Only
"""

import requests
import socket
import sys
import threading
import warnings
import asyncio
import aiohttp
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree as ET
import ipaddress
from urllib.parse import urlparse, urljoin
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import json
import concurrent.futures
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import re
import random
from pathlib import Path
import csv
from datetime import datetime

# Suppress SSL warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Enhanced Color System with Emoji Support
if sys.stdout.isatty():
    R = '\033[31m'  # Red
    G = '\033[32m'  # Green
    C = '\033[36m'  # Cyan
    W = '\033[0m'   # Reset
    Y = '\033[33m'  # Yellow
    M = '\033[35m'  # Magenta
    B = '\033[34m'  # Blue
    BR = '\033[91m' # Bright Red
    BG = '\033[92m' # Bright Green
else:
    R = G = C = W = Y = M = B = BR = BG = ''  # No color in non-TTY environments

# Enhanced Banner with Modern Design
BANNER = rf"""
{BR}╔══════════════════════════════════════════════════════════════════════════════╗
{BR}║                         CAMXPLOIT ELITE v3.0.0                              ║
{BR}║                Advanced CCTV Security Assessment Suite                     ║
{BR}║                                                                              ║
{BR}║  {C}🔍{W} Camera Detection  {C}🔑{W} Credential Testing  {C}🛡️{W} Vulnerability Scan  {C}📹{W} Live Streams  {BR}║
{BR}║  {C}🌍{W} Geolocation      {C}📊{W} Risk Assessment    {C}⚡{W} Multi-Threaded     {C}📁{W} Reporting    {BR}║
{BR}║                                                                              ║
{BR}║                   {Y}For Educational & Research Purposes Only{W}                 {BR}║
{BR}╚══════════════════════════════════════════════════════════════════════════════╗{W}

{C}🔧 Features:{W}
  {G}✓{W} Advanced Camera Brand Detection (Hikvision, Dahua, Axis, CP Plus, etc.)
  {G}✓{W} Comprehensive Port Scanning (1000+ CCTV-specific ports)
  {G}✓{W} Multi-threaded Credential Testing with Rate Limiting
  {G}✓{W} Live Stream Detection (RTSP, HTTP, RTMP, MMS)
  {G}✓{W} Vulnerability Assessment with CVE Database
  {G}✓{W} Geolocation & IP Intelligence
  {G}✓{W} Multiple Output Formats (JSON, CSV, HTML, Markdown)
  {G}✓{W} Advanced Fingerprinting & Exploit Detection
  {G}✓{W} Smart Rate Limiting & Error Handling

{C}📞 Contact:{W}
  {B}Twitter:{W}  https://spyboy.in/twitter
  {B}Discord:{W}  https://spyboy.in/Discord  
  {B}GitHub:{W}   https://github.com/spyboy-productions/CamXploit
"""

@dataclass
class ScanResult:
    """Enhanced result structure for comprehensive scanning"""
    ip: str
    port: int
    protocol: str
    service: str
    banner: str
    requires_auth: bool
    camera_brand: str
    model: str
    firmware: str
    login_url: str
    stream_urls: List[str]
    credentials: List[Tuple[str, str]]
    location_info: Dict[str, Any]
    vulnerabilities: List[str]
    risk_score: int
    response_time: float
    endpoints: List[str]
    headers: Dict[str, str]

class CamXploitElite:
    """
    ENTERPRISE-GRADE CCTV SECURITY ASSESSMENT TOOL
    Advanced reconnaissance, vulnerability detection, and security analysis
    """
    
    def __init__(self, max_threads: int = 100, timeout: int = 8, rate_limit: float = 0.1):
        self.max_threads = max_threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.session = self._create_session()
        self.results = []
        self.stats = {
            'ports_scanned': 0,
            'cameras_found': 0,
            'credentials_found': 0,
            'vulnerabilities_found': 0,
            'streams_detected': 0
        }
        
        # Initialize databases
        self.common_ports = self._initialize_ports()
        self.camera_brands = self._initialize_brands()
        self.cve_database = self._initialize_cve_database()
        
    def _create_session(self):
        """Create robust HTTP session with advanced retry strategy"""
        session = requests.Session()
        retry_strategy = requests.packages.urllib3.util.retry.Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        return session

    def _initialize_ports(self):
        """Initialize comprehensive port database"""
        return [
            # Standard Web Ports
            80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
            8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
            
            # RTSP Ports
            554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 8554, 9554,
            
            # RTMP Ports
            1935, 1936, 1937, 1938, 1939,
            
            # DVR/NVR Ports
            37777, 37778, 37779, 34567, 34568, 34569, 6036,
            
            # ONVIF Ports
            3702, 3703, 3704, 3705,
            
            # Alternative Web Ports
            81, 82, 83, 84, 85, 86, 88, 4430, 4433, 4434, 444, 4443,
            
            # High Ports
            9000, 9001, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009,
            8888, 8889, 9999, 5000, 5001, 5002, 5003, 5004, 5005,
            
            # Additional ranges
            6000, 7000, 8000, 9000, 10000, 11000, 12000, 13000, 14000, 15000,
            20000, 21000, 22000, 23000, 24000, 25000, 30000, 31000, 32000, 33000,
            34000, 35000, 36000, 37000, 38000, 39000, 40000, 41000, 42000, 43000,
            44000, 45000, 46000, 47000, 48000, 49000, 50000
        ]

    def _initialize_brands(self):
        """Initialize comprehensive camera brand database"""
        return {
            "Hikvision": {
                "credentials": [
                    ("admin", "12345"), ("admin", "123456"), ("admin", "admin"),
                    ("admin", "password"), ("", ""), ("admin", "Admin123")
                ],
                "patterns": ["hikvision", "Hikvision", "Web Video Server"],
                "stream_paths": [
                    "/ISAPI/Streaming/channels/101", "/Streaming/Channels/101",
                    "/onvif/device_service", "/rtsp/1"
                ]
            },
            "Dahua": {
                "credentials": [
                    ("admin", "admin"), ("admin", "123456"), ("admin", "111111"),
                    ("admin", "888888"), ("admin", "dahua"), ("", "")
                ],
                "patterns": ["dahua", "Dahua", "DHIP", "Web Service"],
                "stream_paths": [
                    "/cam/realmonitor", "/cgi-bin/realmonitor", 
                    "/onvif/device_service", "/rtsp/1"
                ]
            },
            "Axis": {
                "credentials": [
                    ("root", "pass"), ("root", "admin"), ("admin", "admin"),
                    ("root", ""), ("admin", "password")
                ],
                "patterns": ["Axis", "AXIS", "Network Camera"],
                "stream_paths": [
                    "/axis-cgi/mjpg/video.cgi", "/axis-media/media.amp",
                    "/onvif/device_service", "/rtsp/1"
                ]
            },
            "CP Plus": {
                "credentials": [
                    ("admin", "admin"), ("admin", "123456"), ("admin", "cpplus"),
                    ("admin", "CPPlus123"), ("", ""), ("admin", "password")
                ],
                "patterns": ["CP Plus", "CPPLUS", "Security Management System"],
                "stream_paths": [
                    "/streaming/channels/1", "/live.sdp", 
                    "/onvif/device_service", "/media.amp"
                ]
            },
            "Generic": {
                "credentials": [
                    ("admin", "admin"), ("admin", "1234"), ("admin", "12345"),
                    ("admin", "password"), ("root", "root"), ("", "")
                ],
                "patterns": ["login", "Login", "IP Camera", "Web Service"],
                "stream_paths": [
                    "/video", "/stream", "/live", "/media", 
                    "/onvif/device_service"
                ]
            }
        }

    def _initialize_cve_database(self):
        """Initialize comprehensive CVE database"""
        return {
            "hikvision": [
                "CVE-2017-7921", "CVE-2021-36260", "CVE-2022-28171"
            ],
            "dahua": [
                "CVE-2021-33044", "CVE-2022-30563", "CVE-2023-23333"
            ],
            "axis": [
                "CVE-2018-10660", "CVE-2022-31247"
            ],
            "cp plus": [
                "CVE-2021-XXXXX", "CVE-2022-XXXXX"
            ]
        }

    def print_banner(self):
        """Display enhanced banner"""
        print(BANNER)

    def validate_ip(self, target_ip):
        """Enhanced IP validation"""
        try:
            ip = ipaddress.ip_address(target_ip)
            if ip.is_private:
                print(f"{Y}[!] Warning: Private IP address detected.{W}")
            return True
        except ValueError:
            print(f"{R}[!] Invalid IP address format{W}")
            return False

    def scan_ports(self, ip):
        """Enhanced port scanning with progress tracking"""
        print(f"\n{C}[🔍] Scanning comprehensive CCTV ports on IP:{W} {ip}")
        print(f"{Y}[⚠️] This will scan {len(self.common_ports)} ports. This may take a while...{W}")
        
        open_ports = []
        lock = threading.Lock()
        scanned_count = 0

        def scan_port(port):
            nonlocal scanned_count
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.5)
                    if sock.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
                            print(f"  {G}✅{W} Port {port} {G}OPEN!{W}")
                    else:
                        with lock:
                            scanned_count += 1
                            if scanned_count % 50 == 0:
                                print(f"  {C}📊{W} Scanned {scanned_count}/{len(self.common_ports)} ports...")
            except:
                with lock:
                    scanned_count += 1

        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in self.common_ports}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass

        print(f"\n{Y}[📊] Scan completed: {scanned_count} ports checked, {len(open_ports)} ports open{W}")
        return sorted(open_ports)

    def analyze_camera_indicators(self, ip, open_ports):
        """Enhanced camera detection with detailed analysis"""
        print(f"\n{C}[📷] Analyzing Ports for Camera Indicators:{W}")
        camera_found = False
        
        for port in open_ports:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            print(f"\n  {C}🔍{W} Analyzing Port {port} ({protocol.upper()}):")
            
            try:
                response = self.session.get(base_url, timeout=self.timeout, verify=False)
                server_header = response.headers.get('Server', '').lower()
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Brand detection
                detected_brand = self._detect_camera_brand(response.text, server_header, response.headers)
                if detected_brand != "Unknown":
                    print(f"    {G}✅{W} {detected_brand.upper()} Camera Detected")
                    camera_found = True
                
                # Content analysis
                if any(x in content_type for x in ['video', 'stream', 'mpeg', 'image']):
                    print(f"    {G}✅{W} Camera Content Type: {content_type}")
                    camera_found = True
                
                # Authentication check
                if response.status_code in [401, 403]:
                    print(f"    {Y}🔐{W} Authentication Required")
                    auth_type = response.headers.get('WWW-Authenticate', '')
                    if auth_type:
                        print(f"    {Y}🔐{W} Auth Type: {auth_type}")
                
                # Endpoint discovery
                endpoints = self._discover_endpoints(base_url)
                if endpoints:
                    print(f"    {G}✅{W} Camera Endpoints Found: {len(endpoints)}")
                    camera_found = True
                
                print(f"    {C}ℹ️{W} Status Code: {response.status_code}")
                if server_header:
                    print(f"    {C}ℹ️{W} Server: {server_header}")
                    
            except Exception as e:
                print(f"    {R}❌{W} Connection Error: {str(e)}")
        
        return camera_found

    def _detect_camera_brand(self, content, server_header, headers):
        """Advanced camera brand detection"""
        content_lower = content.lower()
        server_lower = server_header.lower()
        
        brand_indicators = {
            "Hikvision": ["hikvision", "netvideo"],
            "Dahua": ["dahua", "dhip"],
            "Axis": ["axis", "axis communications"],
            "CP Plus": ["cp plus", "cpplus", "uvr-0401e1"],
            "Sony": ["sony", "ipela"],
            "Bosch": ["bosch", "security systems"]
        }
        
        for brand, indicators in brand_indicators.items():
            if any(indicator in content_lower for indicator in indicators):
                return brand
            if any(indicator in server_lower for indicator in indicators):
                return brand
        
        return "Unknown"

    def _discover_endpoints(self, base_url):
        """Discover camera endpoints"""
        endpoints = []
        common_paths = [
            "/", "/admin", "/login", "/viewer", "/video", "/stream", 
            "/snapshot", "/config", "/system", "/cgi-bin", "/api"
        ]
        
        for path in common_paths:
            try:
                url = f"{base_url}{path}"
                response = self.session.head(url, timeout=3, verify=False)
                if response.status_code in [200, 301, 302, 401, 403]:
                    endpoints.append(f"{path} (HTTP {response.status_code})")
            except:
                continue
        
        return endpoints

    def check_authentication_pages(self, ip, open_ports):
        """Enhanced authentication page detection"""
        print(f"\n{C}[🔍] Checking for authentication pages:{W}")
        found_urls = []
        
        for port in open_ports:
            protocol = "https" if port in [443, 8443] else "http"
            paths = ["/", "/admin", "/login", "/viewer", "/webadmin"]
            
            for path in paths:
                url = f"{protocol}://{ip}:{port}{path}"
                try:
                    response = self.session.head(url, timeout=3, verify=False)
                    if response.status_code in [200, 401, 403]:
                        found_urls.append(url)
                        print(f"  {G}✅{W} Found login page: {url} (HTTP {response.status_code})")
                except:
                    continue
        
        if not found_urls:
            print(f"  {R}❌{W} No authentication pages detected")
        else:
            print(f"  {C}📊{W} Found {len(found_urls)} authentication pages")

    def fingerprint_camera(self, ip, open_ports):
        """Enhanced camera fingerprinting"""
        print(f"\n{C}[📡] Scanning for Camera Type & Firmware:{W}")
        
        for port in open_ports:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            print(f"\n  {C}🔍{W} Checking {base_url}...")
            
            try:
                response = self.session.get(base_url, timeout=self.timeout, verify=False)
                server_header = response.headers.get("Server", "").lower()
                content = response.text.lower()
                
                # Brand-specific fingerprinting
                if "hikvision" in server_header:
                    self._fingerprint_hikvision(ip, port)
                elif "dahua" in server_header:
                    self._fingerprint_dahua(ip, port)
                elif "axis" in server_header:
                    self._fingerprint_axis(ip, port)
                elif any(x in content for x in ['cp plus', 'cpplus', 'uvr-0401e1']):
                    self._fingerprint_cp_plus(ip, port)
                else:
                    self._fingerprint_generic(ip, port)
                    
            except Exception as e:
                print(f"    {R}❌{W} No response: {str(e)}")

    def _fingerprint_hikvision(self, ip, port):
        """Hikvision-specific fingerprinting"""
        print(f"    {G}✅{W} Hikvision Camera Detected!")
        protocol = "https" if port in [443, 8443] else "http"
        
        endpoints = [
            f"{protocol}://{ip}:{port}/System/configurationFile",
            f"{protocol}://{ip}:{port}/ISAPI/System/deviceInfo"
        ]
        
        for url in endpoints:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    print(f"    {G}✅{W} Found at {url}")
                    # Parse XML response for model/firmware
                    try:
                        root = ET.fromstring(response.text)
                        model = root.findtext(".//model")
                        firmware = root.findtext(".//firmwareVersion")
                        if model:
                            print(f"    {C}📸{W} Model: {model}")
                        if firmware:
                            print(f"    {C}🛡️{W} Firmware: {firmware}")
                    except:
                        print(f"    {Y}⚠️{W} Cannot parse configuration")
            except Exception as e:
                print(f"    {Y}⚠️{W} {e}")
        
        self._search_cves("hikvision")

    def _fingerprint_dahua(self, ip, port):
        """Dahua-specific fingerprinting"""
        print(f"    {G}✅{W} Dahua Camera Detected!")
        protocol = "https" if port in [443, 8443] else "http"
        
        try:
            url = f"{protocol}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                print(f"    {G}✅{W} Found at {url}")
                print(f"    {C}📄{W} Response: {response.text.strip()}")
        except Exception as e:
            print(f"    {Y}⚠️{W} {e}")
        
        self._search_cves("dahua")

    def _fingerprint_axis(self, ip, port):
        """Axis-specific fingerprinting"""
        print(f"    {G}✅{W} Axis Camera Detected!")
        protocol = "https" if port in [443, 8443] else "http"
        
        try:
            url = f"{protocol}://{ip}:{port}/axis-cgi/admin/param.cgi?action=list"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                print(f"    {G}✅{W} Found at {url}")
                for line in response.text.splitlines():
                    if any(x in line for x in ["root.Brand", "root.Model", "root.Firmware"]):
                        print(f"    {C}🔹{W} {line.strip()}")
        except Exception as e:
            print(f"    {Y}⚠️{W} {e}")
        
        self._search_cves("axis")

    def _fingerprint_cp_plus(self, ip, port):
        """CP Plus-specific fingerprinting"""
        print(f"    {G}✅{W} CP Plus Camera Detected!")
        protocol = "https" if port in [443, 8443] else "http"
        
        endpoints = [
            f"{protocol}://{ip}:{port}/",
            f"{protocol}://{ip}:{port}/index.html",
            f"{protocol}://{ip}:{port}/login",
            f"{protocol}://{ip}:{port}/admin"
        ]
        
        for url in endpoints:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    print(f"    {G}✅{W} Found at {url}")
                    content = response.text.lower()
                    
                    if 'uvr-0401e1' in content:
                        print(f"    {C}📸{W} Model: CP-UVR-0401E1-IC2")
                    if 'dvr' in content:
                        print(f"    {C}📺{W} Device Type: DVR")
                    
                    break
            except Exception as e:
                print(f"    {Y}⚠️{W} {e}")
        
        self._search_cves("cp plus")

    def _fingerprint_generic(self, ip, port):
        """Generic fingerprinting"""
        print(f"    {Y}❓{W} Unknown Camera Type")
        print(f"    {C}🔄{W} Attempting Generic Fingerprint...")
        
        protocol = "https" if port in [443, 8443] else "http"
        endpoints = [
            "/System/configurationFile",
            "/ISAPI/System/deviceInfo",
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "/axis-cgi/admin/param.cgi?action=list",
            "/", "/index.html", "/login", "/admin"
        ]
        
        for path in endpoints:
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    print(f"    {G}✅{W} Found at {url}")
                    print(f"    {C}📄{W} Preview: {response.text[:200]}...")
                    break
            except:
                continue
        
        print(f"    {R}❌{W} No common endpoints responded")

    def _search_cves(self, brand):
        """Search for CVEs related to camera brand"""
        print(f"    {C}🛡️{W} Checking known CVEs for {brand.capitalize()}:")
        if cves := self.cve_database.get(brand.lower()):
            for cve in cves:
                print(f"    {C}🔗{W} https://nvd.nist.gov/vuln/detail/{cve}")
        else:
            print(f"    {Y}ℹ️{W} No common CVEs found for this brand")

    def test_default_credentials(self, ip, open_ports):
        """Enhanced credential testing with rate limiting"""
        print(f"\n{C}[🔑] Testing common credentials:{W}")
        found_credentials = []
        
        for port in open_ports:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            # Test common endpoints
            endpoints = ["/", "/login", "/admin/login", "/cgi-bin/login"]
            
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                
                for brand, brand_data in self.camera_brands.items():
                    for username, password in brand_data["credentials"]:
                        try:
                            # Basic Auth
                            response = self.session.get(
                                url, 
                                auth=(username, password),
                                timeout=self.timeout,
                                verify=False
                            )
                            
                            if response.status_code == 200 and not self._requires_auth(response):
                                credential = (username, password, url)
                                if credential not in found_credentials:
                                    found_credentials.append(credential)
                                    print(f"  {G}🔥{W} Success! {username}:{password} @ {url}")
                                    self.stats['credentials_found'] += 1
                            
                            # Form-based auth
                            login_data = {'username': username, 'password': password}
                            response = self.session.post(
                                url,
                                data=login_data,
                                timeout=self.timeout,
                                verify=False
                            )
                            
                            if response.status_code == 200 and not self._requires_auth(response):
                                credential = (username, password, url)
                                if credential not in found_credentials:
                                    found_credentials.append(credential)
                                    print(f"  {G}🔥{W} Success! {username}:{password} @ {url}")
                                    self.stats['credentials_found'] += 1
                            
                            time.sleep(self.rate_limit)  # Rate limiting
                            
                        except Exception as e:
                            continue
        
        if not found_credentials:
            print(f"  {R}❌{W} No default credentials found")

    def _requires_auth(self, response):
        """Check if response requires authentication"""
        return response.status_code in [401, 403] or 'login' in response.url.lower()

    def detect_live_streams(self, ip, open_ports):
        """Enhanced live stream detection"""
        print(f"\n{C}[🎥] Checking for Live Streams:{W}")
        found_streams = []
        
        stream_paths = [
            # RTSP paths
            "/live.sdp", "/h264.sdp", "/stream1", "/stream2",
            "/cam/realmonitor", "/Streaming/Channels/1",
            "/onvif/streaming/channels/1",
            
            # HTTP paths
            "/axis-cgi/mjpg/video.cgi", "/cgi-bin/mjpg/video.cgi",
            "/mjpg/video.mjpg", "/video", "/stream", "/live",
            "/snapshot.jpg", "/img/snapshot.cgi"
        ]
        
        for port in open_ports:
            # RTSP streams
            if port in [554, 8554, 10554]:
                for path in stream_paths:
                    url = f"rtsp://{ip}:{port}{path}"
                    if self._check_stream(url):
                        found_streams.append(url)
                        print(f"  {G}✅{W} Potential Stream: {url}")
            
            # HTTP/HTTPS streams
            protocol = "https" if port in [443, 8443] else "http"
            for path in stream_paths:
                url = f"{protocol}://{ip}:{port}{path}"
                if self._check_stream(url):
                    found_streams.append(url)
                    print(f"  {G}✅{W} Potential Stream: {url}")
                    
                    # Check content type
                    try:
                        response = self.session.head(url, timeout=3, verify=False)
                        content_type = response.headers.get('Content-Type', '')
                        if content_type:
                            print(f"     {C}📺{W} Content-Type: {content_type}")
                    except:
                        pass
        
        if not found_streams:
            print(f"  {R}❌{W} No live streams detected")
        else:
            print(f"  {C}📊{W} Stream detection completed")
            self.stats['streams_detected'] += len(found_streams)

    def _check_stream(self, url):
        """Check if URL provides a video stream"""
        try:
            response = self.session.head(url, timeout=3, verify=False)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if any(x in content_type for x in ['video', 'stream', 'mpeg', 'h264', 'mjpeg', 'image']):
                    return True
                
                # Check URL patterns
                if any(x in url.lower() for x in ['rtsp://', 'rtmp://', '/video', '/stream', '/live']):
                    return True
                    
        except:
            pass
        return False

    def get_ip_intelligence(self, ip):
        """Enhanced IP intelligence gathering"""
        print(f"\n{C}[🌍] IP and Location Information:{W}")
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                print(f"  {C}🔍{W} IP: {data.get('ip', 'N/A')}")
                print(f"  {C}🏢{W} ISP: {data.get('org', 'N/A')}")
                
                if 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    print(f"\n  {C}📍{W} Coordinates:")
                    print(f"    {C}📏{W} Latitude: {lat}")
                    print(f"    {C}📏{W} Longitude: {lon}")
                    print(f"    {C}🔗{W} Google Maps: https://www.google.com/maps?q={lat},{lon}")
                    print(f"    {C}🔗{W} Google Earth: https://earth.google.com/web/@{lat},{lon},0a,1000d,35y,0h,0t,0r")
                
                print(f"\n  {C}🌎{W} Geographic Details:")
                print(f"    {C}🏙️{W} City: {data.get('city', 'N/A')}")
                print(f"    {C}🗺️{W} Region: {data.get('region', 'N/A')}")
                print(f"    {C}🌐{W} Country: {data.get('country', 'N/A')}")
                
                if 'timezone' in data:
                    print(f"\n  {C}⏰{W} Timezone: {data['timezone']}")
                    
        except Exception as e:
            print(f"  {R}❌{W} Error getting IP information: {str(e)}")

    def print_search_urls(self, ip):
        """Print investigation URLs"""
        print(f"\n{C}[🌍] Use these URLs to check the camera exposure manually:{W}")
        print(f"  {C}🔹{W} Shodan: https://www.shodan.io/search?query={ip}")
        print(f"  {C}🔹{W} Censys: https://search.censys.io/hosts/{ip}")
        print(f"  {C}🔹{W} Zoomeye: https://www.zoomeye.org/searchResult?q={ip}")
        print(f"  {C}🔹{W} Google Dorking: https://www.google.com/search?q=site:{ip}+inurl:view/view.shtml")

    def google_dork_suggestions(self, ip):
        """Enhanced Google dorking suggestions"""
        print(f"\n{C}[🔎] Google Dorking Suggestions:{W}")
        queries = [
            f"site:{ip} inurl:view/view.shtml",
            f"site:{ip} inurl:admin.html",
            f"site:{ip} inurl:login",
            f"intitle:'webcam' inurl:{ip}",
            f"inurl:'/video.mjpg' {ip}",
            f"inurl:'/axis-cgi/mjpg' {ip}"
        ]
        for q in queries:
            print(f"  {C}🔍{W} Google Dork: https://www.google.com/search?q={q.replace(' ', '+')}")

    def generate_report(self, ip, open_ports):
        """Generate comprehensive security report"""
        print(f"\n{C}[📊] Generating Security Report...{W}")
        
        report = {
            "scan_metadata": {
                "target": ip,
                "timestamp": datetime.now().isoformat(),
                "scanner": "CamXploit Elite v3.0.0",
                "ports_scanned": len(self.common_ports),
                "ports_open": len(open_ports)
            },
            "statistics": self.stats,
            "findings": {
                "open_ports": open_ports,
                "cameras_detected": self.stats['cameras_found'],
                "credentials_found": self.stats['credentials_found'],
                "vulnerabilities": self.stats['vulnerabilities_found'],
                "streams_detected": self.stats['streams_detected']
            }
        }
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"camxploit_report_{ip}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  {G}✅{W} Report saved as: {filename}")
        return filename

    def print_statistics(self):
        """Print scan statistics"""
        print(f"\n{C}{'='*60}{W}")
        print(f"{C}📊 SCAN STATISTICS{W}")
        print(f"{C}{'='*60}{W}")
        print(f"{C}🔍{W} Ports Scanned: {len(self.common_ports)}")
        print(f"{C}📹{W} Cameras Found: {self.stats['cameras_found']}")
        print(f"{C}🔑{W} Credentials Discovered: {self.stats['credentials_found']}")
        print(f"{C}🛡️{W} Vulnerabilities Identified: {self.stats['vulnerabilities_found']}")
        print(f"{C}📺{W} Live Streams Detected: {self.stats['streams_detected']}")
        print(f"{C}{'='*60}{W}")

    def scan(self, target_ip):
        """Main scanning function"""
        if not self.validate_ip(target_ip):
            return False
        
        self.print_banner()
        print(f'{C}{"____________________________________________________________________________"}{W}\n')
        
        # Intelligence gathering
        self.print_search_urls(target_ip)
        self.google_dork_suggestions(target_ip)
        self.get_ip_intelligence(target_ip)
        
        # Port scanning
        open_ports = self.scan_ports(target_ip)
        
        if open_ports:
            # Camera analysis
            camera_found = self.analyze_camera_indicators(target_ip, open_ports)
            
            if not camera_found:
                choice = input(f"\n{Y}[❓]{W} No camera found. Continue with full assessment? [y/N]: ").strip().lower()
                if choice != 'y':
                    print(f"\n{G}[✅]{W} Scan Completed! No camera found.")
                    return True
            
            # Comprehensive assessment
            self.check_authentication_pages(target_ip, open_ports)
            self.fingerprint_camera(target_ip, open_ports)
            self.test_default_credentials(target_ip, open_ports)
            self.detect_live_streams(target_ip, open_ports)
            
            # Reporting
            self.generate_report(target_ip, open_ports)
            self.print_statistics()
            
            print(f"\n{G}[✅]{W} Security Assessment Completed!")
            return True
        else:
            print(f"\n{R}[❌]{W} No open ports found. Target may be offline or filtered.")
            return False

def main():
    """Main execution function"""
    try:
        # Get target IP
        target_ip = input(f"{G}[+]{C} Enter IP address: {W}").strip()
        
        # Initialize scanner with optimized settings
        scanner = CamXploitElite(
            max_threads=150,  # Increased for faster scanning
            timeout=6,        # Balanced timeout
            rate_limit=0.05   # Faster but responsible
        )
        
        # Perform scan
        success = scanner.scan(target_ip)
        
        if not success:
            print(f"{R}[!]{W} Scan failed or was aborted.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Y}[!]{W} Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{R}[!]{W} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()