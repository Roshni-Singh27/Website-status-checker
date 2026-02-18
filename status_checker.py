#!/usr/bin/env python3
"""
Website Status Checker with HTTP Error Handling
Checks the availability and response time of websites with comprehensive error handling
"""

import requests
import argparse
import json
import csv
import time
import logging
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('status_checker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class StatusCategory(Enum):
    """Categories for HTTP status codes"""
    SUCCESS = "success"
    REDIRECTION = "redirection"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    CONNECTION_ERROR = "connection_error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass
class CheckResult:
    """Data class for storing check results"""
    url: str
    status_code: Optional[int]
    category: str
    response_time: float
    error_message: Optional[str]
    timestamp: str
    is_accessible: bool
    content_type: Optional[str]
    server: Optional[str]


class WebsiteStatusChecker:
    """Main class for checking website statuses"""
    
    def __init__(self, timeout: int = 10, max_workers: int = 5, 
                 user_agent: str = None, verify_ssl: bool = True):
        """
        Initialize the status checker
        
        Args:
            timeout: Request timeout in seconds
            max_workers: Maximum number of concurrent workers
            user_agent: Custom user agent string
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Website-Status-Checker/1.0'
        })
        
        # Statistics tracking
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'total_time': 0
        }
    
    def categorize_status(self, status_code: Optional[int]) -> str:
        """Categorize HTTP status code"""
        if status_code is None:
            return StatusCategory.UNKNOWN.value
        
        if 200 <= status_code < 300:
            return StatusCategory.SUCCESS.value
        elif 300 <= status_code < 400:
            return StatusCategory.REDIRECTION.value
        elif 400 <= status_code < 500:
            return StatusCategory.CLIENT_ERROR.value
        elif 500 <= status_code < 600:
            return StatusCategory.SERVER_ERROR.value
        else:
            return StatusCategory.UNKNOWN.value
    
    def check_website(self, url: str) -> CheckResult:
        """
        Check a single website status
        
        Args:
            url: URL to check
            
        Returns:
            CheckResult object with status information
        """
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        start_time = time.time()
        timestamp = datetime.now().isoformat()
        
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            response_time = time.time() - start_time
            status_code = response.status_code
            category = self.categorize_status(status_code)
            
            result = CheckResult(
                url=url,
                status_code=status_code,
                category=category,
                response_time=response_time,
                error_message=None,
                timestamp=timestamp,
                is_accessible=True,
                content_type=response.headers.get('Content-Type'),
                server=response.headers.get('Server')
            )
            
            self.stats['success'] += 1
            logger.info(f"✓ {url} - {status_code} ({response_time:.2f}s)")
            
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            result = CheckResult(
                url=url,
                status_code=None,
                category=StatusCategory.TIMEOUT.value,
                response_time=response_time,
                error_message="Request timeout",
                timestamp=timestamp,
                is_accessible=False,
                content_type=None,
                server=None
            )
            self.stats['failed'] += 1
            logger.error(f"✗ {url} - Timeout after {self.timeout}s")
            
        except requests.exceptions.ConnectionError:
            response_time = time.time() - start_time
            result = CheckResult(
                url=url,
                status_code=None,
                category=StatusCategory.CONNECTION_ERROR.value,
                response_time=response_time,
                error_message="Connection error",
                timestamp=timestamp,
                is_accessible=False,
                content_type=None,
                server=None
            )
            self.stats['failed'] += 1
            logger.error(f"✗ {url} - Connection error")
            
        except requests.exceptions.SSLError:
            response_time = time.time() - start_time
            result = CheckResult(
                url=url,
                status_code=None,
                category=StatusCategory.CONNECTION_ERROR.value,
                response_time=response_time,
                error_message="SSL certificate error",
                timestamp=timestamp,
                is_accessible=False,
                content_type=None,
                server=None
            )
            self.stats['failed'] += 1
            logger.error(f"✗ {url} - SSL certificate error")
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            result = CheckResult(
                url=url,
                status_code=None,
                category=StatusCategory.UNKNOWN.value,
                response_time=response_time,
                error_message=str(e),
                timestamp=timestamp,
                is_accessible=False,
                content_type=None,
                server=None
            )
            self.stats['failed'] += 1
            logger.error(f"✗ {url} - Error: {str(e)}")
            
        self.stats['total'] += 1
        self.stats['total_time'] += response_time
        
        return result
    
    def check_multiple_urls(self, urls: List[str]) -> List[CheckResult]:
        """
        Check multiple websites concurrently
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.check_website, url): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Unexpected error checking {url}: {str(e)}")
                    results.append(CheckResult(
                        url=url,
                        status_code=None,
                        category=StatusCategory.UNKNOWN.value,
                        response_time=0,
                        error_message=f"Unexpected error: {str(e)}",
                        timestamp=datetime.now().isoformat(),
                        is_accessible=False,
                        content_type=None,
                        server=None
                    ))
        
        return results
    
    def print_summary(self, results: List[CheckResult]):
        """Print summary of check results"""
        print("\n" + "="*50)
        print("CHECK SUMMARY")
        print("="*50)
        
        total = len(results)
        accessible = sum(1 for r in results if r.is_accessible)
        success = sum(1 for r in results if r.category == StatusCategory.SUCCESS.value)
        redirection = sum(1 for r in results if r.category == StatusCategory.REDIRECTION.value)
        client_errors = sum(1 for r in results if r.category == StatusCategory.CLIENT_ERROR.value)
        server_errors = sum(1 for r in results if r.category == StatusCategory.SERVER_ERROR.value)
        timeouts = sum(1 for r in results if r.category == StatusCategory.TIMEOUT.value)
        connection_errors = sum(1 for r in results if r.category == StatusCategory.CONNECTION_ERROR.value)
        
        avg_response_time = sum(r.response_time for r in results) / total if total > 0 else 0
        
        print(f"Total URLs checked: {total}")
        print(f"Accessible: {accessible}")
        print(f"Success (2xx): {success}")
        print(f"Redirection (3xx): {redirection}")
        print(f"Client Errors (4xx): {client_errors}")
        print(f"Server Errors (5xx): {server_errors}")
        print(f"Timeouts: {timeouts}")
        print(f"Connection Errors: {connection_errors}")
        print(f"Average Response Time: {avg_response_time:.2f}s")
        print("="*50)
    
    def export_to_json(self, results: List[CheckResult], filename: str):
        """Export results to JSON file"""
        data = [asdict(result) for result in results]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results exported to {filename}")
    
    def export_to_csv(self, results: List[CheckResult], filename: str):
        """Export results to CSV file"""
        if not results:
            return
        
        fieldnames = ['url', 'status_code', 'category', 'response_time', 
                     'error_message', 'timestamp', 'is_accessible', 
                     'content_type', 'server']
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow(asdict(result))
        
        logger.info(f"Results exported to {filename}")


def load_urls_from_file(filename: str) -> List[str]:
    """Load URLs from a text file"""
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(urls)} URLs from {filename}")
        return urls
    except FileNotFoundError:
        logger.error(f"URL file {filename} not found")
        return []
    except Exception as e:
        logger.error(f"Error loading URLs: {str(e)}")
        return []


def load_config(filename: str) -> Dict:
    """Load configuration from JSON file"""
    try:
        with open(filename, 'r') as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from {filename}")
        return config
    except FileNotFoundError:
        logger.warning(f"Config file {filename} not found, using defaults")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in config file {filename}")
        return {}


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Website Status Checker with HTTP Error Handling')
    parser.add_argument('-u', '--urls', nargs='+', help='URLs to check')
    parser.add_argument('-f', '--file', help='File containing URLs to check')
    parser.add_argument('-c', '--config', default='config.json', help='Configuration file')
    parser.add_argument('-t', '--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('-w', '--workers', type=int, help='Maximum number of concurrent workers')
    parser.add_argument('-o', '--output', help='Output file prefix (creates .json and .csv)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--user-agent', help='Custom user agent string')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Merge configuration with command line arguments
    timeout = args.timeout or config.get('timeout', 10)
    max_workers = args.workers or config.get('max_workers', 5)
    verify_ssl = not args.no_ssl_verify if args.no_ssl_verify else config.get('verify_ssl', True)
    user_agent = args.user_agent or config.get('user_agent')
    
    # Load URLs
    urls = []
    
    if args.urls:
        urls.extend(args.urls)
    
    if args.file:
        file_urls = load_urls_from_file(args.file)
        urls.extend(file_urls)
    
    if not urls:
        # Try to load from default file
        urls = load_urls_from_file('urls.txt')
    
    if not urls:
        logger.error("No URLs provided. Use -u/--urls or -f/--file")
        sys.exit(1)
    
    # Remove duplicates while preserving order
    urls = list(dict.fromkeys(urls))
    logger.info(f"Checking {len(urls)} unique URLs")
    
    # Create checker and run
    checker = WebsiteStatusChecker(
        timeout=timeout,
        max_workers=max_workers,
        verify_ssl=verify_ssl,
        user_agent=user_agent
    )
    
    print(f"\nStarting website status check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Timeout: {timeout}s, Max workers: {max_workers}\n")
    
    results = checker.check_multiple_urls(urls)
    
    # Print summary
    checker.print_summary(results)
    
    # Export results if requested
    if args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_file = f"{args.output}_{timestamp}.json"
        csv_file = f"{args.output}_{timestamp}.csv"
        checker.export_to_json(results, json_file)
        checker.export_to_csv(results, csv_file)
    elif config.get('auto_export', False):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_file = f"status_check_{timestamp}.json"
        csv_file = f"status_check_{timestamp}.csv"
        checker.export_to_json(results, json_file)
        checker.export_to_csv(results, csv_file)
    
    # Return exit code based on results
    failed = sum(1 for r in results if not r.is_accessible)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()