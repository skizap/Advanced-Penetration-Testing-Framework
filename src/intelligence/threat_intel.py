"""
Threat Intelligence Integration
Integrates with Rapid7, RiskIQ, and other threat intelligence sources
"""

import asyncio
import aiohttp
import json
import time
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    source: str
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    threat_types: List[str]
    confidence: float
    severity: str
    first_seen: Optional[str]
    last_seen: Optional[str]
    description: str
    references: List[str]
    tags: List[str]
    attribution: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class ReputationScore:
    """Reputation scoring result"""
    indicator: str
    indicator_type: str
    overall_score: float  # 0-100, higher is more malicious
    source_scores: Dict[str, float]
    threat_categories: Set[str]
    confidence: float
    last_updated: str

class ThreatIntelClient:
    """
    Threat Intelligence API Client
    Integrates with multiple threat intelligence sources
    """

    def __init__(self, config: Dict[str, str], cache_dir: str = "data/cache"):
        """
        Initialize threat intelligence client

        Args:
            config: API configuration with keys for different services
            cache_dir: Directory for caching responses
        """
        self.config = config
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiting per service
        self.rate_limits = {
            'rapid7': {'limit': 100, 'window': 3600, 'requests': []},
            'riskiq': {'limit': 1000, 'window': 3600, 'requests': []},
            'virustotal': {'limit': 500, 'window': 86400, 'requests': []},
            'shodan': {'limit': 100, 'window': 60, 'requests': []}
        }

        self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'PenTestFramework/1.0'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path for a given key"""
        return self.cache_dir / f"threat_intel_{cache_key}.json"

    def _is_cache_valid(self, cache_path: Path, ttl_hours: int = 6) -> bool:
        """Check if cache file is still valid (shorter TTL for threat intel)"""
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

    async def _rate_limit_wait(self, service: str) -> None:
        """Wait if rate limit would be exceeded for a service"""
        if service not in self.rate_limits:
            return

        rate_info = self.rate_limits[service]
        now = time.time()

        # Remove old requests outside the window
        rate_info['requests'] = [t for t in rate_info['requests']
                               if now - t < rate_info['window']]

        # Check if we need to wait
        if len(rate_info['requests']) >= rate_info['limit']:
            oldest_request = min(rate_info['requests'])
            wait_time = rate_info['window'] - (now - oldest_request)
            if wait_time > 0:
                logger.info(f"Rate limit reached for {service}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        rate_info['requests'].append(now)

    async def _make_request(self, service: str, url: str, headers: Dict = None,
                          params: Dict = None) -> Optional[Dict]:
        """Make API request with rate limiting and caching"""
        if not self.session:
            raise RuntimeError("ThreatIntelClient must be used as async context manager")

        # Create cache key
        cache_key = hashlib.md5(f"{service}_{url}_{str(params)}".encode()).hexdigest()

        # Try cache first
        cached_data = self._load_from_cache(cache_key)
        if cached_data:
            logger.debug(f"Using cached data for {service}")
            return cached_data

        # Rate limiting
        await self._rate_limit_wait(service)

        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    self._save_to_cache(cache_key, data)
                    return data
                elif response.status == 429:
                    logger.warning(f"Rate limited by {service}")
                    await asyncio.sleep(60)
                    return await self._make_request(service, url, headers, params)
                else:
                    logger.error(f"{service} API error {response.status}: {await response.text()}")
                    return None

        except asyncio.TimeoutError:
            logger.error(f"Timeout requesting {service}")
            return None
        except Exception as e:
            logger.error(f"Error requesting {service}: {e}")
            return None

    async def query_rapid7(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelligence]:
        """
        Query Rapid7 threat intelligence

        Args:
            indicator: The indicator to query (IP, domain, etc.)
            indicator_type: Type of indicator (ip, domain, hash, url)

        Returns:
            Threat intelligence data or None
        """
        api_key = self.config.get('rapid7_api_key')
        if not api_key:
            logger.warning("Rapid7 API key not configured")
            return None

        # Rapid7 InsightIDR API endpoint (example)
        url = f"https://us.api.insight.rapid7.com/idr/v1/investigations/threat_command/indicators/{indicator}"
        headers = {'X-Api-Key': api_key}

        response = await self._make_request('rapid7', url, headers)
        if not response:
            return None

        # Parse Rapid7 response (structure may vary)
        try:
            return ThreatIntelligence(
                source='rapid7',
                indicator=indicator,
                indicator_type=indicator_type,
                threat_types=response.get('threat_types', []),
                confidence=response.get('confidence', 0.5),
                severity=response.get('severity', 'unknown'),
                first_seen=response.get('first_seen'),
                last_seen=response.get('last_seen'),
                description=response.get('description', ''),
                references=response.get('references', []),
                tags=response.get('tags', []),
                attribution=response.get('attribution')
            )
        except Exception as e:
            logger.warning(f"Failed to parse Rapid7 response: {e}")
            return None

    async def query_shodan(self, ip: str) -> Optional[ThreatIntelligence]:
        """
        Query Shodan for IP intelligence

        Args:
            ip: IP address to query

        Returns:
            Threat intelligence data or None
        """
        api_key = self.config.get('shodan_api_key')
        if not api_key:
            logger.warning("Shodan API key not configured")
            return None

        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': api_key}

        response = await self._make_request('shodan', url, params=params)
        if not response:
            return None

        try:
            # Extract threat indicators from Shodan data
            threat_types = []
            tags = response.get('tags', [])

            # Check for malicious indicators
            malicious_tags = ['malware', 'botnet', 'compromised', 'tor', 'proxy', 'vpn']
            for tag in tags:
                if any(mal_tag in tag.lower() for mal_tag in malicious_tags):
                    threat_types.append(tag)

            # Check ports for suspicious services
            ports = response.get('ports', [])
            suspicious_ports = [1433, 3389, 5900, 6667, 6697, 8080, 8443, 9050]
            if any(port in suspicious_ports for port in ports):
                threat_types.append('suspicious_services')

            return ThreatIntelligence(
                source='shodan',
                indicator=ip,
                indicator_type='ip',
                threat_types=threat_types,
                confidence=0.7 if threat_types else 0.3,
                severity='medium' if threat_types else 'low',
                first_seen=None,
                last_seen=response.get('last_update'),
                description=f"Shodan scan data for {ip}",
                references=[f"https://www.shodan.io/host/{ip}"],
                tags=tags
            )
        except Exception as e:
            logger.warning(f"Failed to parse Shodan response: {e}")
            return None

    async def query_virustotal(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelligence]:
        """
        Query VirusTotal for threat intelligence

        Args:
            indicator: The indicator to query
            indicator_type: Type of indicator (ip, domain, hash, url)

        Returns:
            Threat intelligence data or None
        """
        api_key = self.config.get('virustotal_api_key')
        if not api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        # Map indicator types to VT endpoints
        endpoint_map = {
            'ip': f"ip_addresses/{indicator}",
            'domain': f"domains/{indicator}",
            'hash': f"files/{indicator}",
            'url': f"urls/{hashlib.sha256(indicator.encode()).hexdigest()}"
        }

        if indicator_type not in endpoint_map:
            logger.warning(f"Unsupported indicator type for VirusTotal: {indicator_type}")
            return None

        url = f"https://www.virustotal.com/api/v3/{endpoint_map[indicator_type]}"
        headers = {'x-apikey': api_key}

        response = await self._make_request('virustotal', url, headers)
        if not response:
            return None

        try:
            data = response.get('data', {})
            attributes = data.get('attributes', {})

            # Extract threat information
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            total_engines = sum(last_analysis_stats.values())

            threat_types = []
            if malicious_count > 0:
                threat_types.append('malware')
            if suspicious_count > 0:
                threat_types.append('suspicious')

            # Calculate confidence based on detection ratio
            confidence = 0.0
            if total_engines > 0:
                detection_ratio = (malicious_count + suspicious_count) / total_engines
                confidence = min(detection_ratio * 2, 1.0)  # Scale to 0-1

            # Determine severity
            severity = 'low'
            if malicious_count > 5:
                severity = 'high'
            elif malicious_count > 2 or suspicious_count > 5:
                severity = 'medium'

            return ThreatIntelligence(
                source='virustotal',
                indicator=indicator,
                indicator_type=indicator_type,
                threat_types=threat_types,
                confidence=confidence,
                severity=severity,
                first_seen=attributes.get('first_submission_date'),
                last_seen=attributes.get('last_analysis_date'),
                description=f"VirusTotal analysis: {malicious_count}/{total_engines} engines detected as malicious",
                references=[f"https://www.virustotal.com/gui/{indicator_type}/{indicator}"],
                tags=attributes.get('tags', [])
            )
        except Exception as e:
            logger.warning(f"Failed to parse VirusTotal response: {e}")
            return None

    async def correlate_with_scan_results(self, scan_results,
                                        threat_intel: List[ThreatIntelligence]) -> Dict:
        """
        Correlate threat intelligence with scan results

        Args:
            scan_results: Network scan results
            threat_intel: List of threat intelligence data

        Returns:
            Correlation analysis results
        """
        correlations = {
            'high_risk_hosts': [],
            'suspicious_services': [],
            'threat_indicators': [],
            'attribution_analysis': {}
        }

        # Create lookup for threat intel by indicator
        threat_lookup = {ti.indicator: ti for ti in threat_intel}

        # Analyze each scan result
        for scan_result in scan_results:
            ip = getattr(scan_result, 'ip', None)
            if not ip:
                continue

            # Check if IP has threat intelligence
            if ip in threat_lookup:
                threat_info = threat_lookup[ip]

                risk_factors = []
                if 'malware' in threat_info.threat_types:
                    risk_factors.append('Known malware host')
                if 'botnet' in threat_info.threat_types:
                    risk_factors.append('Botnet member')
                if threat_info.confidence > 0.7:
                    risk_factors.append('High confidence threat')

                if risk_factors:
                    correlations['high_risk_hosts'].append({
                        'ip': ip,
                        'threat_info': threat_info.to_dict(),
                        'risk_factors': risk_factors,
                        'ports': getattr(scan_result, 'ports', [])
                    })

            # Analyze services for suspicious patterns
            if hasattr(scan_result, 'ports'):
                for port in scan_result.ports:
                    service_name = getattr(port, 'service', 'unknown')
                    port_num = getattr(port, 'port', 0)

                    # Check for suspicious service combinations
                    suspicious_patterns = [
                        (22, 'ssh', 'Exposed SSH service'),
                        (3389, 'rdp', 'Exposed RDP service'),
                        (1433, 'mssql', 'Exposed MSSQL service'),
                        (5432, 'postgresql', 'Exposed PostgreSQL service'),
                        (6379, 'redis', 'Exposed Redis service'),
                        (27017, 'mongodb', 'Exposed MongoDB service')
                    ]

                    for sus_port, sus_service, description in suspicious_patterns:
                        if port_num == sus_port or sus_service.lower() in service_name.lower():
                            correlations['suspicious_services'].append({
                                'ip': ip,
                                'port': port_num,
                                'service': service_name,
                                'description': description,
                                'threat_level': 'medium'
                            })

        return correlations

    async def get_reputation_score(self, indicator: str, indicator_type: str) -> ReputationScore:
        """
        Get aggregated reputation score from multiple sources

        Args:
            indicator: The indicator to score
            indicator_type: Type of indicator (ip, domain, hash, url)

        Returns:
            Aggregated reputation score
        """
        # Query multiple sources
        sources = []

        # Query available sources based on indicator type
        if indicator_type == 'ip':
            if self.config.get('shodan_api_key'):
                shodan_result = await self.query_shodan(indicator)
                if shodan_result:
                    sources.append(shodan_result)

        if self.config.get('virustotal_api_key'):
            vt_result = await self.query_virustotal(indicator, indicator_type)
            if vt_result:
                sources.append(vt_result)

        if self.config.get('rapid7_api_key'):
            rapid7_result = await self.query_rapid7(indicator, indicator_type)
            if rapid7_result:
                sources.append(rapid7_result)

        # Calculate aggregated score
        source_scores = {}
        threat_categories = set()
        total_weighted_score = 0.0
        total_weight = 0.0

        for source in sources:
            # Convert severity to numeric score
            severity_scores = {
                'low': 25,
                'medium': 50,
                'high': 75,
                'critical': 100,
                'unknown': 10
            }

            base_score = severity_scores.get(source.severity, 10)

            # Weight by confidence and threat types
            weight = source.confidence
            if source.threat_types:
                weight *= (1 + len(source.threat_types) * 0.1)

            final_score = base_score * weight
            source_scores[source.source] = final_score

            total_weighted_score += final_score
            total_weight += weight

            # Collect threat categories
            threat_categories.update(source.threat_types)

        # Calculate overall score
        overall_score = 0.0
        if total_weight > 0:
            overall_score = min(total_weighted_score / total_weight, 100.0)

        # Calculate overall confidence
        confidence = min(total_weight / len(sources) if sources else 0.0, 1.0)

        return ReputationScore(
            indicator=indicator,
            indicator_type=indicator_type,
            overall_score=overall_score,
            source_scores=source_scores,
            threat_categories=threat_categories,
            confidence=confidence,
            last_updated=datetime.now().isoformat()
        )

    async def bulk_reputation_check(self, indicators: List[Tuple[str, str]]) -> List[ReputationScore]:
        """
        Perform bulk reputation checking

        Args:
            indicators: List of (indicator, indicator_type) tuples

        Returns:
            List of reputation scores
        """
        tasks = []
        for indicator, indicator_type in indicators:
            task = self.get_reputation_score(indicator, indicator_type)
            tasks.append(task)

        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(5)  # Limit concurrent requests

        async def bounded_task(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[bounded_task(task) for task in tasks],
                                     return_exceptions=True)

        # Filter out exceptions
        valid_results = [r for r in results if isinstance(r, ReputationScore)]

        return valid_results

    def analyze_attribution(self, threat_intel_list: List[ThreatIntelligence]) -> Dict:
        """
        Analyze threat actor attribution from intelligence data

        Args:
            threat_intel_list: List of threat intelligence data

        Returns:
            Attribution analysis results
        """
        attribution_data = {
            'threat_actors': {},
            'campaigns': {},
            'techniques': {},
            'infrastructure_overlap': []
        }

        # Group by attribution
        for intel in threat_intel_list:
            if intel.attribution:
                actor = intel.attribution
                if actor not in attribution_data['threat_actors']:
                    attribution_data['threat_actors'][actor] = {
                        'indicators': [],
                        'threat_types': set(),
                        'confidence_scores': [],
                        'sources': set()
                    }

                actor_data = attribution_data['threat_actors'][actor]
                actor_data['indicators'].append(intel.indicator)
                actor_data['threat_types'].update(intel.threat_types)
                actor_data['confidence_scores'].append(intel.confidence)
                actor_data['sources'].add(intel.source)

        # Convert sets to lists for JSON serialization
        for actor_data in attribution_data['threat_actors'].values():
            actor_data['threat_types'] = list(actor_data['threat_types'])
            actor_data['sources'] = list(actor_data['sources'])
            actor_data['avg_confidence'] = (
                sum(actor_data['confidence_scores']) / len(actor_data['confidence_scores'])
                if actor_data['confidence_scores'] else 0.0
            )

        return attribution_data

    async def enrich_scan_results(self, scan_results) -> Dict:
        """
        Enrich scan results with threat intelligence

        Args:
            scan_results: Network scan results

        Returns:
            Enriched results with threat intelligence
        """
        # Extract indicators from scan results
        indicators = []
        for scan_result in scan_results:
            ip = getattr(scan_result, 'ip', None)
            if ip:
                indicators.append((ip, 'ip'))

            # Extract domains from hostnames if available
            hostname = getattr(scan_result, 'hostname', None)
            if hostname and hostname != ip:
                indicators.append((hostname, 'domain'))

        # Remove duplicates
        indicators = list(set(indicators))

        # Get reputation scores
        reputation_scores = await self.bulk_reputation_check(indicators)

        # Get detailed threat intelligence
        threat_intel = []
        for indicator, indicator_type in indicators[:20]:  # Limit to avoid rate limits
            if indicator_type == 'ip' and self.config.get('shodan_api_key'):
                intel = await self.query_shodan(indicator)
                if intel:
                    threat_intel.append(intel)

            if self.config.get('virustotal_api_key'):
                intel = await self.query_virustotal(indicator, indicator_type)
                if intel:
                    threat_intel.append(intel)

        # Correlate with scan results
        correlations = await self.correlate_with_scan_results(scan_results, threat_intel)

        # Analyze attribution
        attribution = self.analyze_attribution(threat_intel)

        return {
            'reputation_scores': [score.__dict__ for score in reputation_scores],
            'threat_intelligence': [intel.to_dict() for intel in threat_intel],
            'correlations': correlations,
            'attribution_analysis': attribution,
            'summary': {
                'total_indicators': len(indicators),
                'high_risk_indicators': len([s for s in reputation_scores if s.overall_score > 70]),
                'threat_actors_identified': len(attribution['threat_actors']),
                'high_risk_hosts': len(correlations['high_risk_hosts'])
            }
        }