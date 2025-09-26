#!/usr/bin/env python3
"""
IP Block Analysis Utility
A comprehensive tool for IP range classification using IPInfo API.
"""

import json
import logging
import requests
import ipaddress
import sqlite3
import argparse
import time
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class IPAnalysisResult:
    """Data class for IP analysis results"""
    ip: str
    asn: str
    asn_name: str
    organization: str
    country: str
    region: str
    city: str
    classification: str
    is_datacenter: bool
    is_vpn: bool
    is_proxy: bool
    is_residential: bool
    is_mobile: bool
    threat_score: int
    timestamp: str


class IPAnalysisUtility:
    """Main IP Analysis Utility Class"""

    def __init__(self, config_file: str = "config.json"):
        self.config = self.load_config(config_file)
        if not self.validate_config():
            raise ValueError("Invalid configuration. Please check your config.json file.")
        
        self.db_path = self.config.get('database_path', 'ip_analysis.db')
        self.init_database()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'IP-Block-Analysis-Utility/1.0'
        })

    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "ipinfo_token": "",
            "database_path": "ip_analysis.db",
            "output_directory": "reports",
            "rate_limit_delay": 0.1,
            "max_workers": 3
        }

        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)

                # Handle both old and new config formats
                if 'api_keys' in user_config and 'ipinfo' in user_config['api_keys']:
                    user_config['ipinfo_token'] = user_config['api_keys']['ipinfo']

                default_config.update(user_config)
        except FileNotFoundError:
            logger.info(f"Config file {config_file} not found, creating default")
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Please edit {config_file} and add your IPInfo token")
            logger.info("Get a free token at: https://ipinfo.io/signup")

        return default_config

    def validate_config(self) -> bool:
        """Validate configuration parameters"""
        required_fields = ['ipinfo_token']
        
        for field in required_fields:
            value = self.config.get(field)
            if not value or value == "your-ipinfo-token-here":
                logger.error(f"Missing or invalid required configuration: {field}")
                logger.info("Please edit config.json and add your IPInfo token")
                logger.info("Get a free token at: https://ipinfo.io/signup")
                return False
        
        # Validate numeric fields
        try:
            rate_limit = float(self.config.get('rate_limit_delay', 0.1))
            if rate_limit < 0:
                logger.error("rate_limit_delay must be non-negative")
                return False
                
            max_workers = int(self.config.get('max_workers', 3))
            if max_workers < 1:
                logger.error("max_workers must be at least 1")
                return False
                
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid numeric configuration: {e}")
            return False
            
        return True

    def validate_ip_input(self, ip_string: str) -> bool:
        """Validate IP address input"""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            logger.error(f"Invalid IP address: {ip_string}")
            return False

    def validate_cidr_input(self, cidr_string: str) -> bool:
        """Validate CIDR range input"""
        try:
            ipaddress.ip_network(cidr_string, strict=False)
            return True
        except ValueError:
            logger.error(f"Invalid CIDR range: {cidr_string}")
            return False

    @contextmanager
    def get_db_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def init_database(self):
        """Initialize SQLite database for caching results"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS ip_analysis
                           (
                               ip
                               TEXT
                               PRIMARY
                               KEY,
                               asn
                               TEXT,
                               asn_name
                               TEXT,
                               organization
                               TEXT,
                               country
                               TEXT,
                               region
                               TEXT,
                               city
                               TEXT,
                               classification
                               TEXT,
                               is_datacenter
                               BOOLEAN,
                               is_vpn
                               BOOLEAN,
                               is_proxy
                               BOOLEAN,
                               is_residential
                               BOOLEAN,
                               is_mobile
                               BOOLEAN,
                               threat_score
                               INTEGER,
                               timestamp
                               TEXT
                           )
                           ''')

            conn.commit()

    def get_cached_result(self, ip: str) -> Optional[IPAnalysisResult]:
        """Get cached result from database"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            # Check for results from last 24 hours
            cursor.execute('''
                           SELECT *
                           FROM ip_analysis
                           WHERE ip = ?
                             AND datetime(timestamp) > datetime('now', '-1 day')
                           ''', (ip,))

            result = cursor.fetchone()

            if result:
                return IPAnalysisResult(*result)
        return None

    def cache_result(self, result: IPAnalysisResult):
        """Cache result to database"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO ip_analysis VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.ip, result.asn, result.asn_name, result.organization,
                result.country, result.region, result.city, result.classification,
                result.is_datacenter, result.is_vpn, result.is_proxy,
                result.is_residential, result.is_mobile, result.threat_score,
                result.timestamp
            ))

            conn.commit()

    def analyze_with_ipinfo(self, ip: str) -> Optional[Dict]:
        """Analyze IP using IPInfo API with additional data fields"""
        token = self.config.get('ipinfo_token')
        if not token:
            logger.error("IPInfo token not configured. Please add your token to config.json")
            return None

        try:
            # Request additional fields for better classification
            url = f"https://ipinfo.io/{ip}?token={token}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            # Check for error in response
            if 'error' in data:
                logger.error(f"IPInfo API error for {ip}: {data['error']}")
                return None

            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"IPInfo API request error for {ip}: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"IPInfo API JSON decode error for {ip}: {e}")
        except Exception as e:
            logger.error(f"IPInfo API unexpected error for {ip}: {e}")

        return None

    def classify_ip_type(self, ipinfo_data: Dict) -> tuple:
        """Classify IP type based on IPInfo data and manual classification"""
        org = ipinfo_data.get('org', '').lower()

        # Extract ASN info if it's in the org field (format: "AS1234 Organization Name")
        if org.startswith('as') and ' ' in org:
            asn_part, org_part = org.split(' ', 1)
            org = org_part

        # Initialize flags
        is_datacenter = False
        is_vpn = False
        is_proxy = False
        is_residential = False
        is_mobile = False

        # Check if IPInfo provides hosting/privacy information
        hosting = ipinfo_data.get('hosting', {})
        privacy = ipinfo_data.get('privacy', {})
        abuse = ipinfo_data.get('abuse', {})
        domains = ipinfo_data.get('domains', {})

        # Use IPInfo's hosting detection if available
        if isinstance(hosting, dict):
            is_datacenter = hosting.get('host', False)

        # Use IPInfo's privacy detection if available
        if isinstance(privacy, dict):
            is_vpn = privacy.get('vpn', False)
            is_proxy = privacy.get('proxy', False)
            is_hosting = privacy.get('hosting', False)
            if is_hosting:
                is_datacenter = True

        # Manual classification as fallback
        if not any([is_datacenter, is_vpn, is_proxy]):
            # Check for hosting/datacenter indicators
            datacenter_keywords = [
                'hosting', 'cloud', 'datacenter', 'data center', 'server',
                'colocation', 'dedicated', 'vps', 'amazon', 'google',
                'microsoft', 'digitalocean', 'linode', 'vultr', 'ovh',
                'hetzner', 'scaleway', 'contabo', 'rackspace', 'aws'
            ]

            is_datacenter = any(keyword in org for keyword in datacenter_keywords)

            # Check for VPN indicators
            vpn_keywords = [
                'vpn', 'virtual private', 'tunnel', 'nordvpn',
                'expressvpn', 'surfshark', 'cyberghost', 'purevpn'
            ]

            is_vpn = any(keyword in org for keyword in vpn_keywords)

            # Check for proxy indicators
            proxy_keywords = [
                'proxy', 'anonymizer', 'tor', 'exit'
            ]

            is_proxy = any(keyword in org for keyword in proxy_keywords)

        # Check for mobile indicators
        mobile_keywords = [
            'mobile', 'cellular', 'wireless', 'lte', '4g', '5g',
            'verizon', 'att', 't-mobile', 'sprint', 'vodafone',
            'telcom', 'telecom'
        ]

        is_mobile = any(keyword in org for keyword in mobile_keywords)

        # Check for residential ISP indicators
        residential_keywords = [
            'broadband', 'cable', 'dsl', 'fiber', 'internet service',
            'telecom', 'telecommunications', 'residential', 'comcast',
            'charter', 'cox', 'frontier', 'centurylink', 'spectrum',
            'telcom', 'hawaiian telcom', 'services company'
        ]

        is_residential = any(keyword in org for keyword in residential_keywords) and not is_datacenter

        # Determine primary classification
        if is_proxy:
            classification = "proxy"
        elif is_vpn:
            classification = "vpn"
        elif is_datacenter:
            classification = "datacenter"
        elif is_mobile:
            classification = "mobile"
        elif is_residential:
            classification = "residential"
        else:
            classification = "business"

        return classification, is_datacenter, is_vpn, is_proxy, is_residential, is_mobile

    def calculate_threat_score(self, is_vpn: bool, is_proxy: bool,
                               is_datacenter: bool) -> int:
        """Calculate threat score from 0-100"""
        score = 0
        if is_proxy:
            score += 70
        elif is_vpn:
            score += 50
        elif is_datacenter:
            score += 30
        return min(score, 100)

    def analyze_single_ip(self, ip: str) -> IPAnalysisResult:
        """Analyze a single IP address"""
        # Validate IP format
        if not self.validate_ip_input(ip):
            raise ValueError(f"Invalid IP address format: {ip}")

        # Check cache first
        cached = self.get_cached_result(ip)
        if cached:
            logger.debug(f"Using cached result for {ip}")
            return cached

        logger.debug(f"Analyzing IP: {ip}")

        # Rate limiting
        time.sleep(self.config.get('rate_limit_delay', 0.1))

        # Initialize result with defaults
        result = IPAnalysisResult(
            ip=ip,
            asn="Unknown",
            asn_name="Unknown",
            organization="Unknown",
            country="Unknown",
            region="Unknown",
            city="Unknown",
            classification="unknown",
            is_datacenter=False,
            is_vpn=False,
            is_proxy=False,
            is_residential=False,
            is_mobile=False,
            threat_score=0,
            timestamp=datetime.now().isoformat()
        )

        # Get data from IPInfo
        ipinfo_data = self.analyze_with_ipinfo(ip)

        if ipinfo_data:
            # Extract basic info
            result.country = ipinfo_data.get('country', 'Unknown')
            result.region = ipinfo_data.get('region', 'Unknown')
            result.city = ipinfo_data.get('city', 'Unknown')

            # Extract organization info
            org_info = ipinfo_data.get('org', '')
            if org_info:
                # Parse ASN and organization from org field (format: "AS1234 Organization Name")
                if org_info.startswith('AS') and ' ' in org_info:
                    parts = org_info.split(' ', 1)
                    result.asn = parts[0]
                    result.organization = parts[1]
                    result.asn_name = parts[1]  # Use org name as ASN name
                else:
                    result.organization = org_info
                    result.asn_name = org_info

            # Check for separate ASN data (some IPInfo responses have this)
            if 'asn' in ipinfo_data:
                asn_field = ipinfo_data['asn']
                if isinstance(asn_field, dict):
                    result.asn = asn_field.get('asn', result.asn)
                    result.asn_name = asn_field.get('name', result.asn_name)
                    result.organization = asn_field.get('name', result.organization)
                elif isinstance(asn_field, str) and asn_field.startswith('AS'):
                    result.asn = asn_field

            # Classify IP type using enhanced classification
            classification, is_dc, is_vpn, is_proxy, is_res, is_mobile = self.classify_ip_type(ipinfo_data)

            result.classification = classification
            result.is_datacenter = is_dc
            result.is_vpn = is_vpn
            result.is_proxy = is_proxy
            result.is_residential = is_res
            result.is_mobile = is_mobile
            result.threat_score = self.calculate_threat_score(is_vpn, is_proxy, is_dc)

        # Cache result
        self.cache_result(result)

        return result

    def analyze_ip_range(self, ip_range: str) -> List[IPAnalysisResult]:
        """Analyze an IP range (CIDR notation)"""
        if not self.validate_cidr_input(ip_range):
            raise ValueError(f"Invalid CIDR range format: {ip_range}")

        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses

            logger.info(f"Analyzing IP range: {ip_range} ({total_hosts} usable addresses)")

            # Limit analysis for large ranges
            max_ips = 50  # Default limit
            if total_hosts > max_ips:
                logger.warning(f"Large range detected ({total_hosts} IPs). Analyzing sample of first {max_ips} IPs.")
                logger.info("Use a smaller range or increase max_workers in config for full analysis.")
                ips = [str(ip) for ip in list(network.hosts())[:max_ips]]
            else:
                ips = [str(ip) for ip in network.hosts()]

            if not ips:
                # Handle single IP networks like /32
                ips = [str(network.network_address)]

            results = []

            print(f"Starting analysis of {len(ips)} IP addresses...")

            # Use threading for faster analysis but respect rate limits
            max_workers = min(self.config.get('max_workers', 3), len(ips))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(self.analyze_single_ip, ip): ip for ip in ips}

                completed = 0
                for future in as_completed(future_to_ip):
                    try:
                        result = future.result()
                        results.append(result)
                        completed += 1

                        # Progress indicator
                        if completed % 10 == 0 or completed == len(ips):
                            print(f"Progress: {completed}/{len(ips)} IPs analyzed")

                    except Exception as e:
                        ip = future_to_ip[future]
                        logger.error(f"Error analyzing {ip}: {e}")

            logger.info(f"Completed analysis of {len(results)} IPs from range {ip_range}")
            return results

        except Exception as e:
            logger.error(f"Error analyzing IP range {ip_range}: {e}")
            raise

    def generate_json_report(self, results: List[IPAnalysisResult],
                             output_file: str = None) -> str:
        """Generate JSON report from analysis results"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path(self.config.get('output_directory', 'reports'))
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / f"ip_analysis_report_{timestamp}.json"

        # Ensure output directory exists
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        # Generate summary statistics
        total_ips = len(results)
        classification_counts = {}
        threat_levels = {"low": 0, "medium": 0, "high": 0}
        country_counts = {}

        for result in results:
            # Count classifications
            classification_counts[result.classification] = \
                classification_counts.get(result.classification, 0) + 1

            # Count countries
            country_counts[result.country] = \
                country_counts.get(result.country, 0) + 1

            # Count threat levels
            if result.threat_score >= 60:
                threat_levels["high"] += 1
            elif result.threat_score >= 30:
                threat_levels["medium"] += 1
            else:
                threat_levels["low"] += 1

        # Sort countries by count
        top_countries = dict(sorted(country_counts.items(),
                                    key=lambda x: x[1], reverse=True)[:10])

        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "1.0",
                "total_ips_analyzed": total_ips,
                "data_source": "IPInfo API"
            },
            "summary": {
                "classification_breakdown": classification_counts,
                "threat_level_distribution": threat_levels,
                "top_countries": top_countries
            },
            "results": [asdict(result) for result in results]
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"JSON report generated: {output_file}")
        return str(output_file)


def generate_terraform_infrastructure(output_dir: str = "terraform"):
    """Generate Terraform infrastructure using the terraform_infrastructure module"""
    try:
        # Try to import and use the terraform generator
        from terraform_infrastructure import TerraformGenerator

        generator = TerraformGenerator(output_dir)
        generator.generate_all_files()

        print(f"\nTerraform infrastructure generated in: {output_dir}")
        print("\nNext steps:")
        print(f"1. cd {output_dir}")
        print("2. cp terraform.tfvars.example terraform.tfvars")
        print("3. Edit terraform.tfvars with your AWS/GCP credentials")
        print("4. terraform init")
        print("5. terraform plan")
        print("6. terraform apply")

    except ImportError:
        logger.error("terraform_infrastructure.py not found. Please ensure it's in the same directory.")
        return False
    except Exception as e:
        logger.error(f"Error generating Terraform infrastructure: {e}")
        return False

    return True


def print_single_ip_result(result: IPAnalysisResult):
    """Print detailed results for a single IP"""
    print(f"\nAnalysis for {result.ip}:")
    print(f"  Organization: {result.organization}")
    print(f"  ASN: {result.asn}")
    print(f"  ASN Name: {result.asn_name}")
    print(f"  Country: {result.country}")
    print(f"  Region: {result.region}")
    print(f"  City: {result.city}")
    print(f"  Classification: {result.classification}")
    print(f"  Threat Score: {result.threat_score}/100")
    print(f"  Datacenter: {result.is_datacenter}")
    print(f"  VPN: {result.is_vpn}")
    print(f"  Proxy: {result.is_proxy}")
    print(f"  Residential: {result.is_residential}")
    print(f"  Mobile: {result.is_mobile}")


def print_summary_stats(results: List[IPAnalysisResult]):
    """Print summary statistics for multiple results"""
    if not results:
        return

    classifications = {}
    countries = {}
    threat_distribution = {"low": 0, "medium": 0, "high": 0}

    for result in results:
        classifications[result.classification] = \
            classifications.get(result
