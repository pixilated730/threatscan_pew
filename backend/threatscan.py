#!/usr/bin/env python3
"""
ThreatScanUI/backend/threatscan.py
ThreatScan by Africahackon
"""
import asyncio
import logging
import json
import os
import time
import requests
import socket
import dns.resolver
from typing import List, Set, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import xml.etree.ElementTree as ET
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
@dataclass
class SubdomainTool:
    """Configuration for subdomain enumeration tools"""
    name: str
    command_template: str
    output_file: str
    timeout: int = 300
    description: str = ""
@dataclass
class LiveSubdomain:
    """Information about a live subdomain"""
    subdomain: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    content_length: int = 0
    redirect_url: str = ""
    technologies: List[str] = field(default_factory=list)
    is_live: bool = False
@dataclass
class IPInfo:
    """Information about resolved IP addresses"""
    subdomain: str
    ip_address: str
    ip_type: str = "" # IPv4 or IPv6
    cname: str = ""
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    is_private: bool = False
    is_cloudflare: bool = False
    is_aws: bool = False
    is_google: bool = False
    reverse_dns: str = ""
@dataclass
class ReconResults:
    """Comprehensive results from reconnaissance"""
    target: str = ""
    total_subdomains: int = 0
    live_subdomains: int = 0
    unique_ips: int = 0
    unique_subdomains: Set[str] = field(default_factory=set)
    tool_results: Dict[str, int] = field(default_factory=dict)
    live_results: List[LiveSubdomain] = field(default_factory=list)
    ip_results: List[IPInfo] = field(default_factory=list)
    unique_ip_addresses: Set[str] = field(default_factory=set)
    port_results: List[Dict[str, Any]] = field(default_factory=list)
    scan_duration: float = 0.0
    git_vulnerable: List[str] = field(default_factory=list)
    vuln_findings: int = 0
class IPResolver:
    """Handle IP resolution and DNS queries"""
   
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
       
        # Known cloud provider IP ranges (simplified)
        self.cloudflare_ranges = [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
            "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17"
        ]
       
        self.aws_ranges = [
            "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8",
            "35.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8"
        ]
       
        self.google_ranges = [
            "8.8.0.0/16", "8.15.0.0/16", "23.236.0.0/14", "23.251.0.0/16",
            "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15",
            "35.198.0.0/16", "35.199.0.0/17", "35.200.0.0/13", "35.208.0.0/12",
            "35.224.0.0/12", "35.240.0.0/13"
        ]
   
    def _is_ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP is in any of the provided CIDR ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in ranges:
                try:
                    network = ipaddress.ip_network(range_str, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False
   
    def _classify_ip(self, ip: str) -> Dict[str, bool]:
        """Classify IP address (private, cloudflare, aws, google)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'is_private': ip_obj.is_private,
                'is_cloudflare': self._is_ip_in_ranges(ip, self.cloudflare_ranges),
                'is_aws': self._is_ip_in_ranges(ip, self.aws_ranges),
                'is_google': self._is_ip_in_ranges(ip, self.google_ranges)
            }
        except ValueError:
            return {'is_private': False, 'is_cloudflare': False, 'is_aws': False, 'is_google': False}
   
    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""
   
    def resolve_subdomain(self, subdomain: str) -> List[IPInfo]:
        """Resolve a single subdomain to IP addresses and get DNS info"""
        results = []
        start_time = time.time()
       
        try:
            # A Records (IPv4)
            try:
                a_records = self.resolver.resolve(subdomain, 'A')
                for record in a_records:
                    ip = str(record)
                    classification = self._classify_ip(ip)
                    reverse_dns = self._get_reverse_dns(ip)
                   
                    ip_info = IPInfo(
                        subdomain=subdomain,
                        ip_address=ip,
                        ip_type="IPv4",
                        response_time_ms=(time.time() - start_time) * 1000,
                        reverse_dns=reverse_dns,
                        **classification
                    )
                    results.append(ip_info)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
           
            # AAAA Records (IPv6)
            try:
                aaaa_records = self.resolver.resolve(subdomain, 'AAAA')
                for record in aaaa_records:
                    ip = str(record)
                    classification = self._classify_ip(ip)
                    reverse_dns = self._get_reverse_dns(ip)
                   
                    ip_info = IPInfo(
                        subdomain=subdomain,
                        ip_address=ip,
                        ip_type="IPv6",
                        response_time_ms=(time.time() - start_time) * 1000,
                        reverse_dns=reverse_dns,
                        **classification
                    )
                    results.append(ip_info)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
           
            # If we have results, get additional DNS records for the first result
            if results:
                # CNAME
                try:
                    cname_records = self.resolver.resolve(subdomain, 'CNAME')
                    cname = str(cname_records[0])
                    for result in results:
                        result.cname = cname
                except:
                    pass
               
                # MX Records
                try:
                    mx_records = self.resolver.resolve(subdomain, 'MX')
                    mx_list = [str(record) for record in mx_records]
                    for result in results:
                        result.mx_records = mx_list
                except:
                    pass
               
                # TXT Records
                try:
                    txt_records = self.resolver.resolve(subdomain, 'TXT')
                    txt_list = [str(record) for record in txt_records]
                    for result in results:
                        result.txt_records = txt_list
                except:
                    pass
               
                # NS Records
                try:
                    ns_records = self.resolver.resolve(subdomain, 'NS')
                    ns_list = [str(record) for record in ns_records]
                    for result in results:
                        result.ns_records = ns_list
                except:
                    pass
       
        except Exception as e:
            logger.debug(f"Error resolving {subdomain}: {e}")
       
        return results
class UnifiedReconAgent:
    """Unified Security Reconnaissance Agent with improved LLM integration"""
   
    def __init__(self, target_domain: str, base_output_dir: str = "./recon_results"):
        self.target = self._validate_target(target_domain)
        self.base_output_dir = Path(base_output_dir).resolve()
        self.start_time = time.time()
       
        # Create target-specific output directory
        self.output_dir = self._create_target_directory()
       
        # Initialize tools
        self.subdomain_tools = self._initialize_subdomain_tools()
        self.ip_resolver = IPResolver()
       
        # Initialize results
        self.results = ReconResults(target=self.target)
   
    def _validate_target(self, target: str) -> str:
        """Validate and clean the target domain"""
        if not target:
            raise ValueError("Target domain cannot be empty")
       
        # Remove protocols if present
        target = target.replace('https://', '').replace('http://', '')
        target = target.rstrip('/')
       
        # Basic domain validation
        if '.' not in target:
            raise ValueError("Please provide a valid domain (e.g., example.com)")
       
        # Remove any paths
        if '/' in target:
            target = target.split('/')[0]
       
        logger.info(f"🎯 Target domain: {target}")
        return target
   
    def _create_target_directory(self) -> Path:
        """Create a target-specific output directory"""
        safe_target = self.target.replace('.', '_').replace(':', '_')
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        target_dir = self.base_output_dir / f"{safe_target}_{timestamp}"
       
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"📁 Created output directory: {target_dir}")
           
            # Create subdirectories
            subdirs = ['subdomains', 'urls', 'vulnerabilities', 'ports', 'reports', 'live_domains', 'ip_resolution', 'waf_detection', 'git_detection']
            for subdir in subdirs:
                (target_dir / subdir).mkdir(exist_ok=True)
           
            self._create_metadata_file(target_dir)
            return target_dir
           
        except Exception as e:
            logger.error(f"❌ Error creating directory: {e}")
            raise
   
    def _create_metadata_file(self, target_dir: Path):
        """Create a metadata file with scan information"""
        metadata = {
            "target": self.target,
            "scan_id": target_dir.name,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "output_directory": str(target_dir),
            "phases": ["Setup", "Subdomain Enumeration", "Live Domain Detection", "IP Resolution", "Port Scanning", "WAF Detection", "Git Exposure Detection", "Vulnerability Scanning"],
            "status": "initialized"
        }
       
        metadata_file = target_dir / "scan_metadata.json"
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"📄 Created metadata file: {metadata_file}")
        except Exception as e:
            logger.warning(f"⚠️ Could not create metadata file: {e}")
   
    def _initialize_subdomain_tools(self) -> List[SubdomainTool]:
        """Initialize subdomain enumeration tools"""
        return [
            SubdomainTool(
                name="subfinder",
                command_template="subfinder -d {target} -silent",
                output_file="subfinder_raw.txt",
                timeout=300,
                description="Fast subdomain discovery using multiple sources"
            ),
            SubdomainTool(
                name="findomain",
                command_template="findomain -t {target}",
                output_file="findomain_raw.txt",
                timeout=300,
                description="Subdomain enumeration with monitoring capability"
            ),
            SubdomainTool(
                name="assetfinder",
                command_template="assetfinder --subs-only {target}",
                output_file="assetfinder_raw.txt",
                timeout=300,
                description="Find domains and subdomains related to a given domain"
            )
        ]
   
    async def check_tool_availability(self) -> Dict[str, bool]:
        """Check if required tools are installed"""
        logger.info("🔧 Checking tool availability...")
       
        required_tools = [tool.name for tool in self.subdomain_tools] + ["httpx", "nmap", "wafw00f", "subgit", "nuclei"]
        availability = {}
       
        for tool in required_tools:
            try:
                process = await asyncio.create_subprocess_shell(
                    f"which {tool}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                returncode = await process.wait()
                availability[tool] = returncode == 0
               
                if availability[tool]:
                    logger.info(f"✅ {tool} is available")
                else:
                    logger.warning(f"⚠️ {tool} is not installed")
                   
            except Exception as e:
                logger.error(f"❌ Error checking {tool}: {e}")
                availability[tool] = False
       
        return availability
   
    async def run_command(self, command: str, timeout: Optional[int] = 300, cwd: Optional[Path] = None) -> Tuple[bool, str, str]:
        """Execute a system command asynchronously"""
        try:
            logger.debug(f"Executing: {command}")
           
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd or self.output_dir
            )
           
            if timeout is None:
                stdout, stderr = await process.communicate()
            else:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
           
            success = process.returncode == 0
            return success, stdout.decode().strip(), stderr.decode().strip()
           
        except asyncio.TimeoutError:
            logger.error(f"⏰ Command timed out after {timeout}s")
            return False, "", "Command timed out"
        except Exception as e:
            logger.error(f"❌ Error executing command: {e}")
            return False, "", str(e)
   
    async def run_subdomain_tool(self, tool: SubdomainTool) -> bool:
        """Run a single subdomain enumeration tool"""
        logger.info(f"🔍 Running {tool.name}: {tool.description}")
       
        subdomains_dir = self.output_dir / "subdomains"
        output_path = subdomains_dir / tool.output_file
        command = tool.command_template.format(target=self.target)
       
        start_time = time.time()
        success, stdout, stderr = await self.run_command(command, tool.timeout, subdomains_dir)
        duration = time.time() - start_time
       
        # Handle output
        subdomains_found = []
       
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path, 'r') as f:
                subdomains_found = [line.strip() for line in f if line.strip()]
        elif stdout.strip():
            subdomains_found = [line.strip() for line in stdout.split('\n') if line.strip()]
            with open(output_path, 'w') as f:
                f.write(stdout)
       
        # Filter valid subdomains
        valid_subdomains = [s for s in subdomains_found if self._is_valid_subdomain(s)]
        self.results.tool_results[tool.name] = len(valid_subdomains)
       
        if valid_subdomains:
            logger.info(f"✅ {tool.name} found {len(valid_subdomains)} valid subdomains in {duration:.1f}s")
           
            # Save cleaned results
            with open(output_path, 'w') as f:
                for subdomain in valid_subdomains:
                    f.write(f"{subdomain}\n")
           
            return True
        else:
            if success:
                logger.info(f"ℹ️ {tool.name} completed but found no subdomains")
            else:
                logger.error(f"❌ {tool.name} failed: {stderr}")
            return success
   
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain:
            return False
       
        # Clean up subdomain
        if subdomain.startswith(('http://', 'https://')):
            subdomain = subdomain.split('://', 1)[1]
       
        if '/' in subdomain:
            subdomain = subdomain.split('/')[0]
       
        if '.' not in subdomain:
            return False
       
        # Must be target domain or subdomain of target
        return subdomain == self.target or subdomain.endswith('.' + self.target)
   
    def combine_subdomain_results(self) -> int:
        """Combine and deduplicate subdomain results"""
        logger.info("🔄 Combining subdomain results...")
       
        all_subdomains = set()
        subdomains_dir = self.output_dir / "subdomains"
       
        # Load results from each tool
        for tool in self.subdomain_tools:
            output_file = subdomains_dir / tool.output_file
            if output_file.exists():
                with open(output_file, 'r') as f:
                    tool_subdomains = {line.strip().lower() for line in f if line.strip() and self._is_valid_subdomain(line.strip())}
                    all_subdomains.update(tool_subdomains)
                    logger.info(f" 📊 {tool.name}: {len(tool_subdomains)} subdomains")
       
        # Add the main domain
        all_subdomains.add(self.target.lower())
       
        # Sort and save
        sorted_subdomains = sorted(all_subdomains)
       
        # Save to multiple locations
        combined_file = subdomains_dir / "all_subdomains.txt"
        main_file = self.output_dir / "subdomains.txt"
       
        for file_path in [combined_file, main_file]:
            with open(file_path, 'w') as f:
                for subdomain in sorted_subdomains:
                    f.write(f"{subdomain}\n")
       
        self.results.unique_subdomains = all_subdomains
        self.results.total_subdomains = len(all_subdomains)
       
        logger.info(f"✅ Total unique subdomains: {len(all_subdomains)}")
        return len(all_subdomains)
   
    async def check_live_subdomains(self, subdomains: Set[str]) -> List[LiveSubdomain]:
        """Check which subdomains are live using httpx"""
        logger.info("🌐 Checking live subdomains with httpx...")
       
        if not subdomains:
            logger.warning("⚠️ No subdomains to check")
            return []
       
        live_domains_dir = self.output_dir / "live_domains"
        input_file = live_domains_dir / "all_subdomains.txt"
        live_output = live_domains_dir / "live_subdomains.txt"
        detailed_output = live_domains_dir / "httpx_detailed.json"
       
        # Write subdomains to input file (this will be the source for piping)
        with open(input_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
       
        logger.info(f"🔍 Running httpx on {len(subdomains)} subdomains...")
        start_time = time.time()
       
        # First run: Get simple list of live domains (using pipe as you specified)
        simple_command = f"cat {input_file.name} | httpx -silent | tee {live_output.name}"
        success1, stdout1, stderr1 = await self.run_command(simple_command, timeout=600, cwd=live_domains_dir)
       
        # Second run: Get detailed JSON information for analysis
        detailed_command = f"cat {input_file.name} | httpx -silent -json -title -sc -td -ws -cl -follow-redirects | tee {detailed_output.name}"
        success2, stdout2, stderr2 = await self.run_command(detailed_command, timeout=600, cwd=live_domains_dir)
       
        duration = time.time() - start_time
        live_results = []
       
        # Parse the simple live domains list first
        live_domains_set = set()
        if live_output.exists():
            with open(live_output, 'r') as f:
                for line in f:
                    if line.strip():
                        # Clean the URL to get just the domain
                        domain = line.strip().replace('http://', '').replace('https://', '').split('/')[0]
                        live_domains_set.add(domain)
       
        # Parse detailed JSON output for additional information
        if detailed_output.exists() and detailed_output.stat().st_size > 0:
            try:
                with open(detailed_output, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line.strip())
                                domain = data.get('input', '').replace('http://', '').replace('https://', '').split('/')[0]
                               
                                live_sub = LiveSubdomain(
                                    subdomain=domain,
                                    status_code=data.get('status_code', 0),
                                    title=data.get('title', ''),
                                    server=data.get('web_server', ''),
                                    content_length=data.get('content_length', 0),
                                    redirect_url=data.get('location', ''),
                                    technologies=data.get('technologies', []),
                                    is_live=True
                                )
                                live_results.append(live_sub)
                            except json.JSONDecodeError as e:
                                logger.debug(f"JSON decode error: {e}")
                                continue
               
                logger.info(f"✅ Found {len(live_domains_set)} live subdomains in {duration:.1f}s")
               
                # If we have live domains but no detailed results, create basic LiveSubdomain objects
                if live_domains_set and not live_results:
                    logger.info("ℹ️ Creating basic live domain records (detailed scan failed)")
                    live_results = [
                        LiveSubdomain(subdomain=domain, is_live=True, status_code=200)
                        for domain in sorted(live_domains_set)
                    ]
               
                # Create a detailed report if we have results
                if live_results:
                    self._create_live_domains_report(live_results)
               
            except Exception as e:
                logger.error(f"❌ Error parsing detailed httpx output: {e}")
                # Fall back to basic live domain list
                if live_domains_set:
                    logger.info("ℹ️ Using basic live domain list")
                    live_results = [
                        LiveSubdomain(subdomain=domain, is_live=True, status_code=200)
                        for domain in sorted(live_domains_set)
                    ]
        else:
            # If detailed output failed but we have the simple list
            if live_domains_set:
                logger.info("ℹ️ Detailed scan failed, using simple live domain list")
                live_results = [
                    LiveSubdomain(subdomain=domain, is_live=True, status_code=200)
                    for domain in sorted(live_domains_set)
                ]
       
        if not success1 and not success2:
            logger.warning(f"⚠️ httpx failed: {stderr1}")
       
        return live_results
   
    def _create_live_domains_report(self, live_results: List[LiveSubdomain]):
        """Create a detailed report of live domains"""
        report_file = self.output_dir / "reports" / "live_domains_report.txt"
       
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("LIVE DOMAINS REPORT\n")
            f.write("="*70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Live Domains: {len(live_results)}\n")
            f.write("="*70 + "\n\n")
           
            # Group by status code
            status_groups = {}
            for result in live_results:
                status = result.status_code
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(result)
           
            for status_code in sorted(status_groups.keys()):
                domains = status_groups[status_code]
                f.write(f"📊 STATUS {status_code} ({len(domains)} domains):\n")
               
                for domain in sorted(domains, key=lambda x: x.subdomain):
                    f.write(f" 🌐 {domain.subdomain}\n")
                    if domain.title:
                        f.write(f" Title: {domain.title[:100]}{'...' if len(domain.title) > 100 else ''}\n")
                    if domain.server:
                        f.write(f" Server: {domain.server}\n")
                    if domain.technologies:
                        f.write(f" Tech: {', '.join(domain.technologies[:5])}\n")
                    if domain.redirect_url:
                        f.write(f" Redirects to: {domain.redirect_url}\n")
                    f.write("\n")
               
                f.write("\n")
   
    async def resolve_subdomains_to_ips(self, subdomains: Set[str], max_workers: int = 50) -> List[IPInfo]:
        """Resolve all subdomains to IP addresses using threading"""
        logger.info("🔍 Starting IP resolution for all subdomains...")
       
        if not subdomains:
            logger.warning("⚠️ No subdomains to resolve")
            return []
       
        ip_results = []
        resolved_count = 0
        failed_count = 0
       
        start_time = time.time()
       
        # Use ThreadPoolExecutor for concurrent DNS resolution
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all resolution tasks
            future_to_subdomain = {
                executor.submit(self.ip_resolver.resolve_subdomain, subdomain): subdomain
                for subdomain in subdomains
            }
           
            # Process completed tasks
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result(timeout=10)
                    if result:
                        ip_results.extend(result)
                        resolved_count += 1
                        logger.debug(f"✅ Resolved {subdomain}: {len(result)} IPs")
                    else:
                        failed_count += 1
                        logger.debug(f"❌ Failed to resolve {subdomain}")
                       
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"❌ Error resolving {subdomain}: {e}")
               
                # Progress update every 10 resolutions
                total_processed = resolved_count + failed_count
                if total_processed % 10 == 0:
                    logger.info(f" 📊 Progress: {total_processed}/{len(subdomains)} subdomains processed")
       
        duration = time.time() - start_time
       
        # Collect unique IPs
        unique_ips = set()
        for ip_info in ip_results:
            unique_ips.add(ip_info.ip_address)
       
        self.results.ip_results = ip_results
        self.results.unique_ips = len(unique_ips)
        self.results.unique_ip_addresses = unique_ips
       
        logger.info(f"✅ IP Resolution completed in {duration:.1f}s")
        logger.info(f" 📊 Resolved: {resolved_count}/{len(subdomains)} subdomains")
        logger.info(f" 🌐 Unique IPs: {len(unique_ips)}")
        logger.info(f" ❌ Failed: {failed_count}")
       
        # Save IP resolution results
        await self._save_ip_results(ip_results)
       
        return ip_results
   
    async def _save_ip_results(self, ip_results: List[IPInfo]):
        """Save IP resolution results to various formats"""
        logger.info("💾 Saving IP resolution results...")
       
        ip_dir = self.output_dir / "ip_resolution"
       
        # 1. Save all IPs (simple list)
        all_ips_file = ip_dir / "all_ips.txt"
        unique_ips = sorted(set(ip.ip_address for ip in ip_results))
        with open(all_ips_file, 'w') as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
       
        # 2. Save IPv4 IPs only
        ipv4_file = ip_dir / "ipv4_addresses.txt"
        ipv4_ips = sorted(set(ip.ip_address for ip in ip_results if ip.ip_type == "IPv4"))
        with open(ipv4_file, 'w') as f:
            for ip in ipv4_ips:
                f.write(f"{ip}\n")
       
        # 3. Save IPv6 IPs only
        ipv6_file = ip_dir / "ipv6_addresses.txt"
        ipv6_ips = sorted(set(ip.ip_address for ip in ip_results if ip.ip_type == "IPv6"))
        with open(ipv6_file, 'w') as f:
            for ip in ipv6_ips:
                f.write(f"{ip}\n")
       
        # 4. Save subdomain to IP mapping
        mapping_file = ip_dir / "subdomain_ip_mapping.txt"
        with open(mapping_file, 'w') as f:
            f.write("SUBDOMAIN -> IP ADDRESS MAPPING\n")
            f.write("="*50 + "\n\n")
           
            # Group by subdomain
            subdomain_groups = {}
            for ip_info in ip_results:
                if ip_info.subdomain not in subdomain_groups:
                    subdomain_groups[ip_info.subdomain] = []
                subdomain_groups[ip_info.subdomain].append(ip_info)
           
            for subdomain in sorted(subdomain_groups.keys()):
                f.write(f"🌐 {subdomain}:\n")
                for ip_info in subdomain_groups[subdomain]:
                    f.write(f" └─ {ip_info.ip_address} ({ip_info.ip_type})")
                    if ip_info.is_private:
                        f.write(" [PRIVATE]")
                    if ip_info.is_cloudflare:
                        f.write(" [CLOUDFLARE]")
                    if ip_info.is_aws:
                        f.write(" [AWS]")
                    if ip_info.is_google:
                        f.write(" [GOOGLE]")
                    if ip_info.reverse_dns:
                        f.write(f" -> {ip_info.reverse_dns}")
                    f.write("\n")
                f.write("\n")
       
        # 5. Save detailed JSON report
        json_file = ip_dir / "ip_resolution_detailed.json"
        json_data = {
            "target": self.target,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "summary": {
                "total_subdomains_resolved": len(set(ip.subdomain for ip in ip_results)),
                "total_unique_ips": len(set(ip.ip_address for ip in ip_results)),
                "ipv4_count": len([ip for ip in ip_results if ip.ip_type == "IPv4"]),
                "ipv6_count": len([ip for ip in ip_results if ip.ip_type == "IPv6"]),
                "private_ips": len([ip for ip in ip_results if ip.is_private]),
                "cloudflare_ips": len([ip for ip in ip_results if ip.is_cloudflare]),
                "aws_ips": len([ip for ip in ip_results if ip.is_aws]),
                "google_ips": len([ip for ip in ip_results if ip.is_google])
            },
            "results": [
                {
                    "subdomain": ip.subdomain,
                    "ip_address": ip.ip_address,
                    "ip_type": ip.ip_type,
                    "cname": ip.cname,
                    "mx_records": ip.mx_records,
                    "txt_records": ip.txt_records,
                    "ns_records": ip.ns_records,
                    "response_time_ms": ip.response_time_ms,
                    "is_private": ip.is_private,
                    "is_cloudflare": ip.is_cloudflare,
                    "is_aws": ip.is_aws,
                    "is_google": ip.is_google,
                    "reverse_dns": ip.reverse_dns
                }
                for ip in ip_results
            ]
        }
       
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
       
        # 6. Save cloud provider specific IPs
        cloudflare_file = ip_dir / "cloudflare_ips.txt"
        cloudflare_ips = sorted(set(ip.ip_address for ip in ip_results if ip.is_cloudflare))
        with open(cloudflare_file, 'w') as f:
            for ip in cloudflare_ips:
                f.write(f"{ip}\n")
       
        aws_file = ip_dir / "aws_ips.txt"
        aws_ips = sorted(set(ip.ip_address for ip in ip_results if ip.is_aws))
        with open(aws_file, 'w') as f:
            for ip in aws_ips:
                f.write(f"{ip}\n")
       
        google_file = ip_dir / "google_ips.txt"
        google_ips = sorted(set(ip.ip_address for ip in ip_results if ip.is_google))
        with open(google_file, 'w') as f:
            for ip in google_ips:
                f.write(f"{ip}\n")
       
        # 7. Save private IPs
        private_file = ip_dir / "private_ips.txt"
        private_ips = sorted(set(ip.ip_address for ip in ip_results if ip.is_private))
        with open(private_file, 'w') as f:
            for ip in private_ips:
                f.write(f"{ip}\n")
       
        logger.info(f"💾 Saved {len(unique_ips)} unique IPs to multiple formats:")
        logger.info(f" 📄 All IPs: all_ips.txt ({len(unique_ips)} IPs)")
        logger.info(f" 📄 IPv4: ipv4_addresses.txt ({len(ipv4_ips)} IPs)")
        logger.info(f" 📄 IPv6: ipv6_addresses.txt ({len(ipv6_ips)} IPs)")
        logger.info(f" 📄 Mapping: subdomain_ip_mapping.txt")
        logger.info(f" 📄 JSON: ip_resolution_detailed.json")
        if cloudflare_ips:
            logger.info(f" ☁️ Cloudflare: cloudflare_ips.txt ({len(cloudflare_ips)} IPs)")
        if aws_ips:
            logger.info(f" ☁️ AWS: aws_ips.txt ({len(aws_ips)} IPs)")
        if google_ips:
            logger.info(f" ☁️ Google: google_ips.txt ({len(google_ips)} IPs)")
        if private_ips:
            logger.info(f" 🔒 Private: private_ips.txt ({len(private_ips)} IPs)")
   
    def _create_ip_resolution_report(self, ip_results: List[IPInfo]):
        """Create a detailed IP resolution report"""
        report_file = self.output_dir / "reports" / "ip_resolution_report.txt"
       
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("IP RESOLUTION REPORT\n")
            f.write("="*70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Resolved: {len(set(ip.subdomain for ip in ip_results))}\n")
            f.write(f"Total Unique IPs: {len(set(ip.ip_address for ip in ip_results))}\n")
            f.write("="*70 + "\n\n")
           
            # Summary statistics
            ipv4_count = len([ip for ip in ip_results if ip.ip_type == "IPv4"])
            ipv6_count = len([ip for ip in ip_results if ip.ip_type == "IPv6"])
            private_count = len([ip for ip in ip_results if ip.is_private])
            cloudflare_count = len([ip for ip in ip_results if ip.is_cloudflare])
            aws_count = len([ip for ip in ip_results if ip.is_aws])
            google_count = len([ip for ip in ip_results if ip.is_google])
           
            f.write("📊 SUMMARY STATISTICS:\n")
            f.write(f" • IPv4 Addresses: {ipv4_count}\n")
            f.write(f" • IPv6 Addresses: {ipv6_count}\n")
            f.write(f" • Private IPs: {private_count}\n")
            f.write(f" • Cloudflare IPs: {cloudflare_count}\n")
            f.write(f" • AWS IPs: {aws_count}\n")
            f.write(f" • Google IPs: {google_count}\n")
            f.write("\n")
           
            # IP Distribution by provider
            if cloudflare_count > 0 or aws_count > 0 or google_count > 0:
                f.write("☁️ CLOUD PROVIDER DISTRIBUTION:\n")
                if cloudflare_count > 0:
                    f.write(f" 🟠 Cloudflare: {cloudflare_count} IPs\n")
                if aws_count > 0:
                    f.write(f" 🟡 AWS: {aws_count} IPs\n")
                if google_count > 0:
                    f.write(f" 🔵 Google Cloud: {google_count} IPs\n")
                f.write("\n")
           
            # Most common IPs
            ip_frequency = {}
            for ip_info in ip_results:
                ip = ip_info.ip_address
                if ip not in ip_frequency:
                    ip_frequency[ip] = []
                ip_frequency[ip].append(ip_info.subdomain)
           
            common_ips = sorted(ip_frequency.items(), key=lambda x: len(x[1]), reverse=True)[:10]
           
            if common_ips:
                f.write("🔥 MOST COMMON IP ADDRESSES:\n")
                for ip, subdomains in common_ips:
                    f.write(f" 📍 {ip} ({len(subdomains)} subdomains)")
                   
                    # Add provider info
                    sample_ip_info = next((info for info in ip_results if info.ip_address == ip), None)
                    if sample_ip_info:
                        providers = []
                        if sample_ip_info.is_cloudflare:
                            providers.append("Cloudflare")
                        if sample_ip_info.is_aws:
                            providers.append("AWS")
                        if sample_ip_info.is_google:
                            providers.append("Google")
                        if sample_ip_info.is_private:
                            providers.append("Private")
                       
                        if providers:
                            f.write(f" [{', '.join(providers)}]")
                   
                    f.write("\n")
                   
                    # Show first few subdomains
                    for subdomain in subdomains[:3]:
                        f.write(f" └─ {subdomain}\n")
                    if len(subdomains) > 3:
                        f.write(f" └─ ... and {len(subdomains) - 3} more\n")
                    f.write("\n")
           
            # Subdomains with most IPs
            subdomain_ip_count = {}
            for ip_info in ip_results:
                subdomain = ip_info.subdomain
                if subdomain not in subdomain_ip_count:
                    subdomain_ip_count[subdomain] = set()
                subdomain_ip_count[subdomain].add(ip_info.ip_address)
           
            multi_ip_subdomains = sorted(
                [(sub, ips) for sub, ips in subdomain_ip_count.items() if len(ips) > 1],
                key=lambda x: len(x[1]), reverse=True
            )[:10]
           
            if multi_ip_subdomains:
                f.write("🔄 SUBDOMAINS WITH MULTIPLE IPs:\n")
                for subdomain, ips in multi_ip_subdomains:
                    f.write(f" 🌐 {subdomain} ({len(ips)} IPs):\n")
                    for ip in sorted(ips):
                        f.write(f" └─ {ip}\n")
                    f.write("\n")
       
        logger.info(f"📄 IP resolution report saved: {report_file}")
   
    async def run_port_scanning(self) -> bool:
        """Run Nmap to scan for open ports on all unique IPv4 addresses"""
        logger.info("🔍 Starting port scanning with Nmap...")
       
        if not self.results.unique_ip_addresses:
            logger.warning("⚠️ No IP addresses to scan")
            return False
       
        # Get unique IPv4 addresses
        ipv4_ips = sorted(set(ip.ip_address for ip in self.results.ip_results if ip.ip_type == "IPv4"))
       
        if not ipv4_ips:
            logger.warning("⚠️ No IPv4 addresses to scan")
            return False
       
        ports_dir = self.output_dir / "ports"
        input_file = ports_dir / "scan_ips.txt"
       
        with open(input_file, 'w') as f:
            for ip in ipv4_ips:
                f.write(f"{ip}\n")
       
        output_txt = ports_dir / "nmap_ports.txt"
        output_xml = ports_dir / "nmap_ports.xml"
       
        command = f"sudo nmap -T5 --open -oN {output_txt} -oX {output_xml} -iL {input_file}"
       
        start_time = time.time()
        success, stdout, stderr = await self.run_command(command, timeout=3600, cwd=ports_dir)
        duration = time.time() - start_time
       
        if success:
            logger.info(f"✅ Port scanning completed in {duration:.1f}s")
            self._parse_nmap_output(output_xml)
            self._create_port_scanning_report()
            return True
        else:
            logger.error(f"❌ Port scanning failed: {stderr}")
            logger.warning("⚠️  Ensure you have sudo privileges for nmap or run without -sS flag")
            return False
    
    def _parse_nmap_output(self, xml_file: Path):
        """Parse Nmap XML output to extract open ports"""
        if not xml_file.exists():
            logger.warning("⚠️  Nmap XML output not found")
            return
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            port_results = []
            
            for host in root.findall('host'):
                # Find IP
                addresses = host.findall('address')
                ip = None
                for addr in addresses:
                    if addr.get('addrtype') == 'ipv4':
                        ip = addr.get('addr')
                        break
                if ip is None:
                    continue
                
                # Find ports
                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue
                
                port_elems = ports_elem.findall('port')
                ports = []
                for port_elem in port_elems:
                    state_elem = port_elem.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        port_id = port_elem.get('portid')
                        service = port_elem.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        ports.append({'port': port_id, 'service': service_name})
                
                if ports:
                    port_results.append({'ip': ip, 'ports': ports})
            
            self.results.port_results = port_results
            logger.info(f"📊 Parsed {len(port_results)} IPs with open ports")
            
        except Exception as e:
            logger.error(f"❌ Error parsing Nmap XML: {e}")
    
    def _create_port_scanning_report(self):
        """Create a detailed port scanning report"""
        report_file = self.output_dir / "reports" / "port_scanning_report.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("PORT SCANNING REPORT\n")
            f.write("="*70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total IPs Scanned: {len(set(ip.ip_address for ip in self.results.ip_results if ip.ip_type == 'IPv4'))}\n")
            f.write(f"IPs with Open Ports: {len(self.results.port_results)}\n")
            f.write("="*70 + "\n\n")
            
            if self.results.port_results:
                f.write("📊 OPEN PORTS BY IP:\n\n")
                for result in sorted(self.results.port_results, key=lambda x: x['ip']):
                    f.write(f"📍 {result['ip']}:\n")
                    for port in sorted(result['ports'], key=lambda p: int(p['port'])):
                        f.write(f"   └─ Port {port['port']} ({port['service']})\n")
                    f.write("\n")
            else:
                f.write("ℹ️  No open ports found\n")
        
        logger.info(f"📄 Port scanning report saved: {report_file}")
    
    async def run_waf_detection(self) -> bool:
        """Run wafw00f to check for WAF on live domains"""
        logger.info("🔍 Starting WAF detection with wafw00f...")
        
        if self.results.live_subdomains == 0:
            logger.warning("⚠️  No live domains to check for WAF")
            return False
        
        waf_dir = self.output_dir / "waf_detection"
        input_file = self.output_dir / "live_domains" / "live_subdomains.txt"
        output_file = waf_dir / "waf.txt"
        
        command = f"wafw00f -a -i {input_file} -o {output_file}"
        
        start_time = time.time()
        success, stdout, stderr = await self.run_command(command, timeout=600, cwd=waf_dir)
        duration = time.time() - start_time
        
        if success:
            logger.info(f"✅ WAF detection completed in {duration:.1f}s")
            return True
        else:
            logger.error(f"❌ WAF detection failed: {stderr}")
            return False
    
    async def run_git_detection(self) -> bool:
        """Run subgit to check for exposed .git files on live domains"""
        logger.info("🔍 Starting Git exposure detection with subgit...")
        
        if self.results.live_subdomains == 0:
            logger.warning("⚠️  No live domains to check for Git exposure")
            return False
        
        git_dir = self.output_dir / "git_detection"
        input_file = self.output_dir / "live_domains" / "live_subdomains.txt"
        output_file = git_dir / "subgit_results.txt"
        
        command = f"cat {input_file} | subgit > {output_file}"
        
        start_time = time.time()
        success, stdout, stderr = await self.run_command(command, timeout=600, cwd=git_dir)
        duration = time.time() - start_time
        
        if success:
            logger.info(f"✅ Git exposure detection completed in {duration:.1f}s")
            # Parse output - assuming subgit outputs vulnerable URLs one per line
            if output_file.exists():
                with open(output_file, 'r') as f:
                    lines = f.readlines()
                    vulnerable = [line.strip() for line in lines if line.strip()]
                    self.results.git_vulnerable = vulnerable
                    logger.info(f"📊 Found {len(vulnerable)} potentially vulnerable .git exposures")
            return True
        else:
            logger.error(f"❌ Git detection failed: {stderr}")
            return False
    
    async def run_vulnerability_scanning(self) -> bool:
        """Run nuclei to check for vulnerabilities on live domains"""
        logger.info("🔍 Starting vulnerability scanning with nuclei...")
        
        if self.results.live_subdomains == 0:
            logger.warning("⚠️  No live domains to scan for vulnerabilities")
            return False
        
        vuln_dir = self.output_dir / "vulnerabilities"
        input_file = self.output_dir / "live_domains" / "live_subdomains.txt"
        output_file = vuln_dir / "nuclei.txt"
        
        command = f"nuclei -l {input_file} -es info -o {output_file} -c 50 -rl 100"
        
        start_time = time.time()
        success, stdout, stderr = await self.run_command(command, timeout=1800, cwd=vuln_dir)
        duration = time.time() - start_time
        
        if success:
            logger.info(f"✅ Vulnerability scanning completed in {duration:.1f}s")
            if output_file.exists():
                with open(output_file, 'r') as f:
                    lines = f.readlines()
                    self.results.vuln_findings = len(lines)
                    logger.info(f"📊 Found {len(lines)} vulnerability findings")
            return True
        else:
            logger.error(f"❌ Vulnerability scanning failed: {stderr}")
            return False
    
    async def run_subdomain_enumeration(self) -> bool:
        """Run the subdomain enumeration phase"""
        logger.info("🔍 Starting subdomain enumeration...")
       
        # Check tool availability
        tool_availability = await self.check_tool_availability()
       
        # Check for httpx specifically
        if not tool_availability.get('httpx', False):
            logger.error("❌ httpx is required for live domain detection!")
            logger.error(" Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            return False
       
        # Check for nmap
        if not tool_availability.get('nmap', False):
            logger.warning("⚠️ nmap is not installed - port scanning will be skipped")
       
        # Check for wafw00f
        if not tool_availability.get('wafw00f', False):
            logger.warning("⚠️ wafw00f is not installed - WAF detection will be skipped")
       
        # Check for subgit
        if not tool_availability.get('subgit', False):
            logger.warning("⚠️ subgit is not installed - Git exposure detection will be skipped")
       
        # Check for nuclei
        if not tool_availability.get('nuclei', False):
            logger.warning("⚠️ nuclei is not installed - vulnerability scanning will be skipped")
       
        # Filter available subdomain tools
        available_tools = [tool for tool in self.subdomain_tools if tool_availability.get(tool.name, False)]
       
        if not available_tools:
            logger.warning("⚠️ No subdomain enumeration tools available!")
            logger.warning(" Install at least one of: subfinder, findomain, assetfinder")
            # Add just the target domain
            self.results.unique_subdomains.add(self.target.lower())
            self.results.total_subdomains = 1
        else:
            logger.info(f"🔧 Using {len(available_tools)} tools: {', '.join([t.name for t in available_tools])}")
           
            # Run tools in parallel
            tasks = [asyncio.create_task(self.run_subdomain_tool(tool)) for tool in available_tools]
            await asyncio.gather(*tasks, return_exceptions=True)
           
            # Combine results
            self.combine_subdomain_results()
       
        return True
   
    async def run_live_detection(self) -> bool:
        """Run the live domain detection phase"""
        logger.info("🌐 Starting live domain detection...")
       
        if not self.results.unique_subdomains:
            logger.warning("⚠️ No subdomains to check for liveness")
            return False
       
        # Check live domains
        live_results = await self.check_live_subdomains(self.results.unique_subdomains)
        self.results.live_results = live_results
        self.results.live_subdomains = len(live_results)
       
        return True
   
    async def run_ip_resolution(self) -> bool:
        """Run the IP resolution phase"""
        logger.info("🔍 Starting IP resolution phase...")
       
        if not self.results.unique_subdomains:
            logger.warning("⚠️ No subdomains to resolve")
            return False
       
        # Resolve all subdomains to IPs
        ip_results = await self.resolve_subdomains_to_ips(self.results.unique_subdomains)
       
        if ip_results:
            # Create IP resolution report
            self._create_ip_resolution_report(ip_results)
            logger.info(f"✅ IP resolution completed - found {self.results.unique_ips} unique IPs")
            return True
        else:
            logger.warning("⚠️ No IPs were successfully resolved")
            return False
   
    async def run_full_reconnaissance(self) -> Dict:
        """Run the complete reconnaissance workflow"""
        logger.info("🚀 Starting Full Security Reconnaissance")
        logger.info("="*70)
       
        try:
            # Phase 1: Setup (already done in __init__)
            logger.info("✅ Phase 1: Setup completed")
           
            # Phase 2: Subdomain Enumeration
            logger.info("🔍 Phase 2: Starting subdomain enumeration...")
            subdomain_success = await self.run_subdomain_enumeration()
           
            if not subdomain_success:
                return {"status": "failed", "phase": "subdomain_enumeration", "error": "Failed to enumerate subdomains"}
           
            logger.info(f"✅ Phase 2: Found {self.results.total_subdomains} total subdomains")
           
            # Phase 3: Live Domain Detection
            logger.info("🌐 Phase 3: Starting live domain detection...")
            live_success = await self.run_live_detection()
           
            if not live_success:
                logger.warning("⚠️ Phase 3: Live detection had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 3: Found {self.results.live_subdomains} live subdomains")
           
            # Phase 4: IP Resolution
            logger.info("🔍 Phase 4: Starting IP resolution...")
            ip_success = await self.run_ip_resolution()
           
            if not ip_success:
                logger.warning("⚠️ Phase 4: IP resolution had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 4: Resolved {self.results.unique_ips} unique IP addresses")
           
            # Phase 5: Port Scanning
            logger.info("🔍 Phase 5: Starting port scanning...")
            port_success = await self.run_port_scanning()
           
            if not port_success:
                logger.warning("⚠️ Phase 5: Port scanning had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 5: Scanned ports on IPv4 addresses")
           
            # Phase 6: WAF Detection
            logger.info("🔍 Phase 6: Starting WAF detection...")
            waf_success = await self.run_waf_detection()
           
            if not waf_success:
                logger.warning("⚠️ Phase 6: WAF detection had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 6: Completed WAF detection on live domains")
           
            # Phase 7: Git Exposure Detection
            logger.info("🔍 Phase 7: Starting Git exposure detection...")
            git_success = await self.run_git_detection()
            if not git_success:
                logger.warning("⚠️ Phase 7: Git detection had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 7: Completed Git exposure detection")
           
            # Phase 8: Vulnerability Scanning
            logger.info("🔍 Phase 8: Starting vulnerability scanning...")
            vuln_success = await self.run_vulnerability_scanning()
            if not vuln_success:
                logger.warning("⚠️ Phase 8: Vulnerability scanning had issues, but continuing...")
            else:
                logger.info(f"✅ Phase 8: Completed vulnerability scanning")
           
            # Set scan duration
            self.results.scan_duration = time.time() - self.start_time
           
            # Generate final reports
            self.generate_final_report()
            self.save_json_summary()
           
            # Display final results
            self._display_final_results()
           
            logger.info("="*70)
            logger.info("🎉 Full reconnaissance completed successfully!")
           
            return {
                "status": "completed",
                "target": self.target,
                "total_subdomains": self.results.total_subdomains,
                "live_subdomains": self.results.live_subdomains,
                "unique_ips": self.results.unique_ips,
                "output_directory": str(self.output_dir),
                "duration": self.results.scan_duration
            }
           
        except Exception as e:
            logger.error(f"❌ Reconnaissance failed: {e}")
            return {"status": "failed", "error": str(e)}
    def generate_final_report(self):
        """Generate a comprehensive final reconnaissance report"""
        report_file = self.output_dir / "reports" / "final_recon_report.txt"
       
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("FINAL RECONNAISSANCE REPORT\n")
            f.write("="*70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains: {self.results.total_subdomains}\n")
            f.write(f"Live Subdomains: {self.results.live_subdomains}\n")
            f.write(f"Unique IPs: {self.results.unique_ips}\n")
            f.write(f"Scan Duration: {self.results.scan_duration:.1f} seconds\n")
            f.write(f"Vulnerable Git Exposures: {len(self.results.git_vulnerable)}\n")
            f.write(f"Vulnerability Findings: {self.results.vuln_findings}\n")
            f.write("="*70 + "\n\n")
           
            # Tool Results
            f.write("🔧 TOOL RESULTS:\n")
            for tool, count in self.results.tool_results.items():
                f.write(f" • {tool}: {count} subdomains\n")
            f.write("\n")
           
            # Live Subdomains Summary
            if self.results.live_results:
                f.write("🌐 LIVE SUBDOMAINS:\n")
                for live in sorted(self.results.live_results, key=lambda x: x.subdomain):
                    f.write(f" • {live.subdomain} (Status: {live.status_code})\n")
                f.write("\n")
           
            # IP Summary
            if self.results.ip_results:
                f.write("🔍 IP RESOLUTION SUMMARY:\n")
                unique_ips = sorted(self.results.unique_ip_addresses)
                for ip in unique_ips:
                    f.write(f" • {ip}\n")
                f.write("\n")
           
            # Port Results
            if self.results.port_results:
                f.write("📊 OPEN PORTS:\n")
                for result in self.results.port_results:
                    f.write(f" 📍 {result['ip']}:\n")
                    for port in result['ports']:
                        f.write(f" └─ {port['port']} ({port['service']})\n")
                f.write("\n")
           
            # Git Vulnerabilities
            if self.results.git_vulnerable:
                f.write("⚠️ GIT EXPOSURES:\n")
                for url in self.results.git_vulnerable:
                    f.write(f" • {url}\n")
                f.write("\n")
       
        logger.info(f"📄 Final report saved: {report_file}")
    def save_json_summary(self):
        """Save reconnaissance results as JSON"""
        from dataclasses import asdict
        summary_file = self.output_dir / "recon_summary.json"
       
        # Convert sets to lists for JSON serialization
        results_dict = asdict(self.results)
        results_dict['unique_subdomains'] = list(self.results.unique_subdomains)
        results_dict['unique_ip_addresses'] = list(self.results.unique_ip_addresses)
       
        with open(summary_file, 'w') as f:
            json.dump(results_dict, f, indent=2)
       
        logger.info(f"💾 JSON summary saved: {summary_file}")
    def _display_final_results(self):
        """Display final results summary in console"""
        logger.info("\n" + "="*70)
        logger.info("🎉 RECONNAISSANCE SUMMARY")
        logger.info("="*70)
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📊 Total Subdomains: {self.results.total_subdomains}")
        logger.info(f"🌐 Live Subdomains: {self.results.live_subdomains}")
        logger.info(f"🔍 Unique IPs: {self.results.unique_ips}")
        logger.info(f"⏱️ Duration: {self.results.scan_duration:.1f} seconds")
        logger.info(f"📁 Output Directory: {self.output_dir}")
        logger.info("="*70)
def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                  CCI ThreatScan                              ║
║                                                              ║
║ 🎯 Target Discovery 🔍 Subdomain Enumeration                 ║
║ 🌐 Live Detection 🔍 IP Resolution                           ║
║ 🔍 Port Scanning 🔍 WAF Detection                            ║
║ 📊 Comprehensive Reporting                                   ║
║ 📁 Organized Output ☁️ Cloud Provider Detection              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)
def check_dependencies():
    """Check if required tools are installed"""
    required_tools = ["subfinder", "findomain", "assetfinder", "httpx", "nmap", "wafw00f", "subgit", "nuclei"]
    missing_tools = []
   
    for tool in required_tools:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode != 0:
                missing_tools.append(tool)
        except:
            missing_tools.append(tool)
   
    if missing_tools:
        print("⚠️ Missing required tools:")
        for tool in missing_tools:
            if tool == "subfinder":
                print(f" ❌ {tool} - Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            elif tool == "findomain":
                print(f" ❌ {tool} - Install: https://github.com/Findomain/Findomain#installation")
            elif tool == "assetfinder":
                print(f" ❌ {tool} - Install: go install github.com/tomnomnom/assetfinder@latest")
            elif tool == "httpx":
                print(f" ❌ {tool} - Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            elif tool == "nmap":
                print(f" ❌ {tool} - Install: sudo apt install nmap (or equivalent for your OS)")
            elif tool == "wafw00f":
                print(f" ❌ {tool} - Install: pip install wafw00f")
            elif tool == "subgit":
                print(f" ❌ {tool} - Install: go install github.com/hahwul/subgit@latest")
            elif tool == "nuclei":
                print(f" ❌ {tool} - Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
       
        print("\n💡 At least one subdomain tool and httpx are required for full functionality")
        print(" nmap is required for port scanning")
        print(" wafw00f is required for WAF detection")
        print(" subgit is required for Git exposure detection")
        print(" nuclei is required for vulnerability scanning")
        print(" You can still run with partial functionality if some tools are missing")
       
        choice = input("\nContinue anyway? (y/N): ").lower().strip()
        if choice not in ['y', 'yes']:
            sys.exit(1)
def main():
    """Main entry point with improved error handling and debugging"""
    import argparse
   
    print_banner()
   
    parser = argparse.ArgumentParser(
        description="Fixed Security Assessment Agent with improved AI integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -o /tmp/recon
  %(prog)s example.com --max-workers 100 --timeout 600
  %(prog)s example.com --check-deps-only
        """
    )
   
    parser.add_argument("target", help="Target domain for reconnaissance")
    parser.add_argument("-o", "--output", default="./recon_results",
                       help="Base output directory (default: ./recon_results)")
    parser.add_argument("--timeout", type=int, default=300,
                       help="Timeout for each tool in seconds (default: 300)")
    parser.add_argument("--max-workers", type=int, default=50,
                       help="Maximum workers for IP resolution (default: 50)")
    parser.add_argument("--check-deps", action="store_true",
                       help="Check dependencies and exit")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug mode for AI integration")
   
    args = parser.parse_args()
   
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
   
    # Check dependencies if requested
    if args.check_deps:
        check_dependencies()
        return 0
   
    # Check dependencies before starting
    check_dependencies()
   
    try:
        print(f"🎯 Starting reconnaissance for: {args.target}")
        print(f"📁 Output directory: {args.output}")
        print(f"👥 Max workers for IP resolution: {args.max_workers}")
        if args.debug:
            print("🐛 Debug mode: Enabled")
        print("")
       
        # Create and run reconnaissance agent
        agent = UnifiedReconAgent(args.target, args.output)
       
        # Update tool timeouts if specified
        if args.timeout != 300:
            for tool in agent.subdomain_tools:
                tool.timeout = args.timeout
            logger.info(f"⏰ Tool timeout set to {args.timeout}s")
       
        # Run the full reconnaissance
        result = asyncio.run(agent.run_full_reconnaissance())
       
        # Print final summary
        if result["status"] == "completed":
            print("\n" + "="*70)
            print("🎉 RECONNAISSANCE COMPLETED SUCCESSFULLY!")
            print("="*70)
            print(f"🎯 Target: {result['target']}")
            print(f"📊 Total Subdomains: {result['total_subdomains']}")
            print(f"🌐 Live Subdomains: {result['live_subdomains']}")
            print(f"🔍 Unique IPs: {result['unique_ips']}")
            print(f"⏱️ Duration: {result['duration']:.1f} seconds")
            print(f"📁 Results Directory: {result['output_directory']}")
           
            print("\n📋 Key Files Generated:")
            print(" • subdomains.txt - All discovered subdomains")
            print(" • live_domains/live_subdomains.txt - Live domains only")
            print(" • ip_resolution/all_ips.txt - All unique IP addresses")
            print(" • ip_resolution/ipv4_addresses.txt - IPv4 addresses only")
            print(" • ip_resolution/ipv6_addresses.txt - IPv6 addresses only")
            print(" • ip_resolution/subdomain_ip_mapping.txt - Domain to IP mapping")
            print(" • ip_resolution/cloudflare_ips.txt - Cloudflare IPs (if any)")
            print(" • ip_resolution/aws_ips.txt - AWS IPs (if any)")
            print(" • ip_resolution/google_ips.txt - Google IPs (if any)")
            print(" • ports/nmap_ports.txt - Nmap text output")
            print(" • ports/nmap_ports.xml - Nmap XML output")
            print(" • waf_detection/waf.txt - WAF detection results")
            print(" • git_detection/subgit_results.txt - Git exposure results")
            print(" • vulnerabilities/nuclei.txt - Vulnerability scanning results")
            print(" • reports/final_recon_report.txt - Comprehensive report")
            print(" • reports/ip_resolution_report.txt - IP analysis report")
            print(" • reports/port_scanning_report.txt - Port scanning report")
            print(" • recon_summary.json - Machine-readable summary")
           
            print("\n🔄 Suggested Next Steps:")
            if result['live_subdomains'] > 0:
                print(" • Port scan live subdomains with nmap")
                print(" • Run web application scans")
                print(" • Check for common vulnerabilities")
                print(" • Analyze service configurations")
           
            if result['unique_ips'] > 0:
                print(" • Port scan unique IP addresses")
                print(" • Perform network reconnaissance")
                print(" • Analyze cloud infrastructure patterns")
                print(" • Check for shared hosting environments")
           
            if result['live_subdomains'] == 0 and result['unique_ips'] == 0:
                print(" • Verify target domain is active")
                print(" • Try additional subdomain discovery methods")
                print(" • Check DNS configuration")
                print(" • Consider passive reconnaissance techniques")
           
            return 0
        else:
            print(f"\n❌ Reconnaissance failed: {result.get('error', 'Unknown error')}")
            return 1
       
    except ValueError as e:
        logger.error(f"❌ Invalid input: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("\n👋 Interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        if args.verbose or args.debug:
            import traceback
            traceback.print_exc()
        return 1
if __name__ == "__main__":
    exit(main())