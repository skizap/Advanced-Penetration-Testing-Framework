"""
NVD (National Vulnerability Database) API Client
Provides CVE lookup, filtering, and vulnerability data retrieval
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CVEData:
    """CVE vulnerability data structure"""
    cve_id: str
    description: str
    published_date: str
    modified_date: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    cvss_v2_score: Optional[float]
    cvss_v2_severity: Optional[str]
    cpe_matches: List[str]
    references: List[str]
    weaknesses: List[str]
    configurations: List[Dict]

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class VulnerabilityMatch:
    """Vulnerability match result"""
    service_name: str
    service_version: str
    port: int
    protocol: str
    cve_data: CVEData
    confidence: float
    match_reason: str

class NVDClient:
    """
    National Vulnerability Database API Client
    Provides CVE lookup and vulnerability data retrieval
    """

    def __init__(self, api_key: Optional[str] = None, cache_dir: str = "data/cache"):
        """
        Initialize NVD client

        Args:
            api_key: Optional NVD API key for higher rate limits
            cache_dir: Directory for caching responses
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiting (without API key: 5 requests per 30 seconds)
        # With API key: 50 requests per 30 seconds
        self.rate_limit = 50 if api_key else 5
        self.rate_window = 30
        self.request_times = []

        # Session for connection pooling
        self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'PenTestFramework/1.0',
                'apiKey': self.api_key if self.api_key else ''
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path for a given key"""
        return self.cache_dir / f"nvd_{cache_key}.json"

    def _is_cache_valid(self, cache_path: Path, ttl_hours: int = 24) -> bool:
        """Check if cache file is still valid"""
        if not cache_path.exists():
            return False

        file_age = time.time() - cache_path.stat().st_mtime
        return file_age < (ttl_hours * 3600)

    def _load_from_cache(self, cache_key: str) -> Optional[Dict]:
        """Load data from cache if valid"""
        cache_path = self._get_cache_path(cache_key)

        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache {cache_key}: {e}")

        return None

    def _save_to_cache(self, cache_key: str, data: Dict) -> None:
        """Save data to cache"""
        cache_path = self._get_cache_path(cache_key)

        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            logger.warning(f"Failed to save cache {cache_key}: {e}")

    async def _rate_limit_wait(self) -> None:
        """Wait if rate limit would be exceeded"""
        now = time.time()

        # Remove old requests outside the window
        self.request_times = [t for t in self.request_times if now - t < self.rate_window]

        # Check if we need to wait
        if len(self.request_times) >= self.rate_limit:
            oldest_request = min(self.request_times)
            wait_time = self.rate_window - (now - oldest_request)
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        self.request_times.append(now)

    async def _make_request(self, endpoint: str, params: Dict) -> Optional[Dict]:
        """Make API request with rate limiting and caching"""
        if not self.session:
            raise RuntimeError("NVDClient must be used as async context manager")

        # Create cache key from endpoint and params
        cache_key = f"{endpoint}_{hash(str(sorted(params.items())))}"

        # Try cache first
        cached_data = self._load_from_cache(cache_key)
        if cached_data:
            logger.debug(f"Using cached data for {endpoint}")
            return cached_data

        # Rate limiting
        await self._rate_limit_wait()

        url = f"{self.base_url}/{endpoint}"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    self._save_to_cache(cache_key, data)
                    return data
                elif response.status == 429:
                    logger.warning("Rate limited by NVD API")
                    await asyncio.sleep(60)  # Wait 1 minute
                    return await self._make_request(endpoint, params)
                else:
                    logger.error(f"NVD API error {response.status}: {await response.text()}")
                    return None

        except asyncio.TimeoutError:
            logger.error(f"Timeout requesting {endpoint}")
            return None
        except Exception as e:
            logger.error(f"Error requesting {endpoint}: {e}")
            return None

    def _parse_cve_data(self, cve_item: Dict) -> CVEData:
        """Parse CVE data from NVD API response"""
        cve = cve_item.get('cve', {})

        # Basic info
        cve_id = cve.get('id', '')
        descriptions = cve.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')

        published_date = cve.get('published', '')
        modified_date = cve.get('lastModified', '')

        # CVSS scores
        metrics = cve.get('metrics', {})
        cvss_v3_score = None
        cvss_v3_severity = None
        cvss_v2_score = None
        cvss_v2_severity = None

        # CVSS v3
        if 'cvssMetricV31' in metrics:
            cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
            cvss_v3_score = cvss_v3.get('baseScore')
            cvss_v3_severity = cvss_v3.get('baseSeverity')
        elif 'cvssMetricV30' in metrics:
            cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
            cvss_v3_score = cvss_v3.get('baseScore')
            cvss_v3_severity = cvss_v3.get('baseSeverity')

        # CVSS v2
        if 'cvssMetricV2' in metrics:
            cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
            cvss_v2_score = cvss_v2.get('baseScore')
            cvss_v2_severity = cvss_v2.get('baseSeverity')

        # CPE matches and configurations
        configurations = cve.get('configurations', [])
        cpe_matches = []
        config_list = []

        for config in configurations:
            config_list.append(config)
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        cpe_matches.append(cpe_match.get('criteria', ''))

        # References
        references = [ref.get('url', '') for ref in cve.get('references', [])]

        # Weaknesses
        weaknesses = []
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    weaknesses.append(desc.get('value', ''))

        return CVEData(
            cve_id=cve_id,
            description=description,
            published_date=published_date,
            modified_date=modified_date,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_severity=cvss_v2_severity,
            cpe_matches=cpe_matches,
            references=references,
            weaknesses=weaknesses,
            configurations=config_list
        )

    async def get_cve_by_id(self, cve_id: str) -> Optional[CVEData]:
        """
        Get CVE data by CVE ID

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            CVE data or None if not found
        """
        params = {'cveId': cve_id}

        response = await self._make_request('cves/2.0', params)
        if not response or 'vulnerabilities' not in response:
            return None

        vulnerabilities = response['vulnerabilities']
        if not vulnerabilities:
            return None

        return self._parse_cve_data(vulnerabilities[0])

    async def search_cves_by_keyword(self, keyword: str, limit: int = 100) -> List[CVEData]:
        """
        Search CVEs by keyword

        Args:
            keyword: Search keyword
            limit: Maximum number of results

        Returns:
            List of CVE data
        """
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(limit, 2000)
        }

        response = await self._make_request('cves/2.0', params)
        if not response or 'vulnerabilities' not in response:
            return []

        cves = []
        for vuln in response['vulnerabilities']:
            try:
                cve_data = self._parse_cve_data(vuln)
                cves.append(cve_data)
            except Exception as e:
                logger.warning(f"Failed to parse CVE data: {e}")

        return cves[:limit]

    async def search_cves_by_cpe(self, cpe_name: str, limit: int = 100) -> List[CVEData]:
        """
        Search CVEs by CPE (Common Platform Enumeration)

        Args:
            cpe_name: CPE name (e.g., cpe:2.3:a:apache:http_server:2.4.41)
            limit: Maximum number of results

        Returns:
            List of CVE data
        """
        params = {
            'cpeName': cpe_name,
            'resultsPerPage': min(limit, 2000)
        }

        response = await self._make_request('cves/2.0', params)
        if not response or 'vulnerabilities' not in response:
            return []

        cves = []
        for vuln in response['vulnerabilities']:
            try:
                cve_data = self._parse_cve_data(vuln)
                cves.append(cve_data)
            except Exception as e:
                logger.warning(f"Failed to parse CVE data: {e}")

        return cves[:limit]