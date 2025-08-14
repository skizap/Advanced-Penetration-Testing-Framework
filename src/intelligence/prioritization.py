"""
Vulnerability Prioritization Engine
Implements CVSS scoring, custom risk algorithms, and vulnerability ranking
"""

import math
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum

from .nvd_client import CVEData, VulnerabilityMatch
from .vulnerability_matcher import VulnerabilityResult

logger = logging.getLogger(__name__)

class ExploitAvailability(Enum):
    """Exploit availability levels"""
    NONE = "none"
    POC = "proof_of_concept"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"
    IN_THE_WILD = "in_the_wild"

@dataclass
class ExploitInfo:
    """Exploit information structure"""
    cve_id: str
    exploit_id: str
    source: str
    availability: ExploitAvailability
    reliability: float  # 0.0 to 1.0
    complexity: str  # low, medium, high
    description: str
    references: List[str]
    last_updated: str

@dataclass
class PrioritizedVulnerability:
    """Prioritized vulnerability with risk scoring"""
    vulnerability_match: VulnerabilityMatch
    priority_score: float
    risk_factors: List[str]
    exploit_info: Optional[ExploitInfo]
    business_impact: str
    remediation_complexity: str
    temporal_score: float
    environmental_score: float

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        result = asdict(self)
        if self.exploit_info:
            result['exploit_info']['availability'] = self.exploit_info.availability.value
        return result

class VulnerabilityPrioritizer:
    """
    Vulnerability Prioritization Engine
    Implements advanced risk scoring and prioritization algorithms
    """

    def __init__(self, config: Dict = None):
        """
        Initialize vulnerability prioritizer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.exploit_sources = self._initialize_exploit_sources()

        # Risk weighting factors
        self.risk_weights = {
            'cvss_score': 0.3,
            'exploit_availability': 0.25,
            'asset_criticality': 0.2,
            'exposure_level': 0.15,
            'temporal_factors': 0.1
        }

    def _initialize_exploit_sources(self) -> Dict:
        """Initialize exploit database sources"""
        return {
            'exploitdb': {
                'url': 'https://www.exploit-db.com/api/v1/search',
                'reliability': 0.8
            },
            'metasploit': {
                'patterns': ['metasploit', 'msf', 'exploit/'],
                'reliability': 0.9
            },
            'github': {
                'patterns': ['exploit', 'poc', 'cve-'],
                'reliability': 0.6
            }
        }

    def _calculate_cvss_score(self, cve_data: CVEData) -> float:
        """
        Calculate normalized CVSS score

        Args:
            cve_data: CVE data

        Returns:
            Normalized CVSS score (0.0 to 10.0)
        """
        # Prefer CVSS v3 over v2
        if cve_data.cvss_v3_score is not None:
            return float(cve_data.cvss_v3_score)
        elif cve_data.cvss_v2_score is not None:
            return float(cve_data.cvss_v2_score)
        else:
            # Estimate based on severity
            severity_scores = {
                'critical': 9.0,
                'high': 7.5,
                'medium': 5.0,
                'low': 2.5
            }
            severity = (cve_data.cvss_v3_severity or cve_data.cvss_v2_severity or 'medium').lower()
            return severity_scores.get(severity, 5.0)

    def _assess_exploit_availability(self, cve_data: CVEData) -> Tuple[ExploitAvailability, float]:
        """
        Assess exploit availability for a CVE

        Args:
            cve_data: CVE data

        Returns:
            Tuple of (availability level, reliability score)
        """
        # Check references for exploit indicators
        exploit_indicators = {
            ExploitAvailability.IN_THE_WILD: ['in the wild', 'active exploitation', 'mass exploitation'],
            ExploitAvailability.WEAPONIZED: ['metasploit', 'exploit kit', 'weaponized'],
            ExploitAvailability.FUNCTIONAL: ['working exploit', 'functional exploit', 'exploit code'],
            ExploitAvailability.POC: ['proof of concept', 'poc', 'demonstration']
        }

        description_lower = cve_data.description.lower()
        references_text = ' '.join(cve_data.references).lower()
        combined_text = f"{description_lower} {references_text}"

        # Check for exploit availability indicators
        for availability, indicators in exploit_indicators.items():
            for indicator in indicators:
                if indicator in combined_text:
                    return availability, 0.7

        # Check age - newer CVEs are more likely to have exploits
        try:
            published = datetime.fromisoformat(cve_data.published_date.replace('Z', '+00:00'))
            age_days = (datetime.now() - published.replace(tzinfo=None)).days

            if age_days < 30:
                return ExploitAvailability.POC, 0.5
            elif age_days < 365:
                return ExploitAvailability.NONE, 0.3
            else:
                return ExploitAvailability.NONE, 0.1
        except:
            return ExploitAvailability.NONE, 0.2

    def _calculate_temporal_score(self, cve_data: CVEData) -> float:
        """
        Calculate temporal score based on CVE age and activity

        Args:
            cve_data: CVE data

        Returns:
            Temporal score (0.0 to 1.0)
        """
        try:
            published = datetime.fromisoformat(cve_data.published_date.replace('Z', '+00:00'))
            modified = datetime.fromisoformat(cve_data.modified_date.replace('Z', '+00:00'))
            now = datetime.now()

            # Age factor (newer is higher priority)
            age_days = (now - published.replace(tzinfo=None)).days
            age_factor = max(0.1, 1.0 - (age_days / 365))  # Decay over 1 year

            # Activity factor (recent modifications indicate ongoing research)
            mod_days = (now - modified.replace(tzinfo=None)).days
            activity_factor = max(0.1, 1.0 - (mod_days / 90))  # Decay over 3 months

            return (age_factor * 0.7) + (activity_factor * 0.3)
        except:
            return 0.5  # Default score if date parsing fails

    def _assess_asset_criticality(self, service_name: str, port: int) -> float:
        """
        Assess asset criticality based on service type and port

        Args:
            service_name: Name of the service
            port: Port number

        Returns:
            Criticality score (0.0 to 1.0)
        """
        # Critical services
        critical_services = {
            'ssh': 0.9,
            'rdp': 0.9,
            'ftp': 0.7,
            'telnet': 0.8,
            'smtp': 0.6,
            'dns': 0.8,
            'ldap': 0.8,
            'kerberos': 0.9
        }

        # Critical ports
        critical_ports = {
            22: 0.9,    # SSH
            23: 0.8,    # Telnet
            21: 0.7,    # FTP
            25: 0.6,    # SMTP
            53: 0.8,    # DNS
            88: 0.9,    # Kerberos
            135: 0.8,   # RPC
            139: 0.7,   # NetBIOS
            389: 0.8,   # LDAP
            445: 0.8,   # SMB
            993: 0.6,   # IMAPS
            995: 0.6,   # POP3S
            1433: 0.8,  # MSSQL
            3306: 0.8,  # MySQL
            3389: 0.9,  # RDP
            5432: 0.8,  # PostgreSQL
            5985: 0.8,  # WinRM
            6379: 0.7,  # Redis
            27017: 0.8  # MongoDB
        }

        # Check service name
        service_score = 0.5  # Default
        for service, score in critical_services.items():
            if service.lower() in service_name.lower():
                service_score = max(service_score, score)

        # Check port
        port_score = critical_ports.get(port, 0.3)

        # Return the higher of the two scores
        return max(service_score, port_score)

    def _assess_exposure_level(self, port: int, protocol: str) -> float:
        """
        Assess exposure level based on port and protocol

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)

        Returns:
            Exposure score (0.0 to 1.0)
        """
        # Internet-facing services are higher risk
        internet_facing_ports = {
            80, 443, 8080, 8443,  # Web services
            22, 23,                # Remote access
            21, 20,                # FTP
            25, 587, 465,          # Email
            53,                    # DNS
            110, 143, 993, 995     # Email retrieval
        }

        # Internal services that shouldn't be exposed
        internal_ports = {
            135, 139, 445,         # Windows networking
            1433, 1521, 3306, 5432, # Databases
            389, 636,              # LDAP
            5985, 5986,            # WinRM
            6379,                  # Redis
            27017                  # MongoDB
        }

        if port in internet_facing_ports:
            return 0.6  # Medium exposure (expected to be public)
        elif port in internal_ports:
            return 0.9  # High exposure (shouldn't be public)
        elif port < 1024:
            return 0.7  # System ports
        else:
            return 0.4  # User ports

    def _calculate_priority_score(self, vuln_match: VulnerabilityMatch,
                                exploit_info: Optional[ExploitInfo] = None) -> Tuple[float, List[str]]:
        """
        Calculate comprehensive priority score

        Args:
            vuln_match: Vulnerability match data
            exploit_info: Optional exploit information

        Returns:
            Tuple of (priority score, risk factors list)
        """
        risk_factors = []

        # Base CVSS score
        cvss_score = self._calculate_cvss_score(vuln_match.cve_data)
        cvss_normalized = cvss_score / 10.0

        # Exploit availability score
        exploit_availability, _ = self._assess_exploit_availability(vuln_match.cve_data)
        exploit_scores = {
            ExploitAvailability.NONE: 0.1,
            ExploitAvailability.POC: 0.3,
            ExploitAvailability.FUNCTIONAL: 0.6,
            ExploitAvailability.WEAPONIZED: 0.8,
            ExploitAvailability.IN_THE_WILD: 1.0
        }
        exploit_score = exploit_scores[exploit_availability]

        if exploit_score > 0.5:
            risk_factors.append(f"Exploit available ({exploit_availability.value})")

        # Asset criticality
        asset_score = self._assess_asset_criticality(vuln_match.service_name, vuln_match.port)
        if asset_score > 0.7:
            risk_factors.append("Critical service")

        # Exposure level
        exposure_score = self._assess_exposure_level(vuln_match.port, vuln_match.protocol)
        if exposure_score > 0.7:
            risk_factors.append("High exposure risk")

        # Temporal factors
        temporal_score = self._calculate_temporal_score(vuln_match.cve_data)
        if temporal_score > 0.7:
            risk_factors.append("Recent vulnerability")

        # Confidence factor
        confidence_factor = vuln_match.confidence
        if confidence_factor > 0.8:
            risk_factors.append("High confidence match")

        # Calculate weighted score
        weighted_score = (
            cvss_normalized * self.risk_weights['cvss_score'] +
            exploit_score * self.risk_weights['exploit_availability'] +
            asset_score * self.risk_weights['asset_criticality'] +
            exposure_score * self.risk_weights['exposure_level'] +
            temporal_score * self.risk_weights['temporal_factors']
        )

        # Apply confidence multiplier
        final_score = weighted_score * confidence_factor

        # Scale to 0-100
        priority_score = min(final_score * 100, 100.0)

        return priority_score, risk_factors

    def _determine_business_impact(self, service_name: str, port: int, cvss_score: float) -> str:
        """
        Determine business impact level

        Args:
            service_name: Name of the service
            port: Port number
            cvss_score: CVSS score

        Returns:
            Business impact level (low, medium, high, critical)
        """
        # Critical business services
        critical_services = ['ldap', 'kerberos', 'dns', 'dhcp']
        high_impact_services = ['ssh', 'rdp', 'database', 'web', 'email']

        service_lower = service_name.lower()

        # Check for critical services
        if any(svc in service_lower for svc in critical_services):
            return 'critical'

        # Check for high impact services
        if any(svc in service_lower for svc in high_impact_services):
            if cvss_score >= 7.0:
                return 'critical'
            else:
                return 'high'

        # Based on CVSS score
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def _assess_remediation_complexity(self, cve_data: CVEData, service_name: str) -> str:
        """
        Assess remediation complexity

        Args:
            cve_data: CVE data
            service_name: Service name

        Returns:
            Complexity level (low, medium, high)
        """
        # Check if it's a configuration issue
        config_keywords = ['configuration', 'misconfiguration', 'default', 'weak password']
        if any(keyword in cve_data.description.lower() for keyword in config_keywords):
            return 'low'

        # Check if it requires system updates
        update_keywords = ['update', 'patch', 'upgrade', 'version']
        if any(keyword in cve_data.description.lower() for keyword in update_keywords):
            return 'medium'

        # Critical system services are harder to remediate
        critical_services = ['kernel', 'system', 'driver', 'firmware']
        if any(svc in service_name.lower() for svc in critical_services):
            return 'high'

        return 'medium'  # Default

    async def prioritize_vulnerabilities(self, vuln_results: List[VulnerabilityResult]) -> List[PrioritizedVulnerability]:
        """
        Prioritize vulnerabilities using comprehensive risk scoring

        Args:
            vuln_results: List of vulnerability results

        Returns:
            List of prioritized vulnerabilities sorted by priority score
        """
        prioritized = []

        for vuln_result in vuln_results:
            for vuln_match in vuln_result.vulnerabilities:
                # Calculate priority score
                priority_score, risk_factors = self._calculate_priority_score(vuln_match)

                # Assess exploit availability
                exploit_availability, reliability = self._assess_exploit_availability(vuln_match.cve_data)
                exploit_info = None

                if exploit_availability != ExploitAvailability.NONE:
                    exploit_info = ExploitInfo(
                        cve_id=vuln_match.cve_data.cve_id,
                        exploit_id="",
                        source="assessment",
                        availability=exploit_availability,
                        reliability=reliability,
                        complexity="medium",
                        description=f"Exploit availability: {exploit_availability.value}",
                        references=vuln_match.cve_data.references,
                        last_updated=datetime.now().isoformat()
                    )

                # Determine business impact
                cvss_score = self._calculate_cvss_score(vuln_match.cve_data)
                business_impact = self._determine_business_impact(
                    vuln_match.service_name, vuln_match.port, cvss_score
                )

                # Assess remediation complexity
                remediation_complexity = self._assess_remediation_complexity(
                    vuln_match.cve_data, vuln_match.service_name
                )

                # Calculate temporal and environmental scores
                temporal_score = self._calculate_temporal_score(vuln_match.cve_data)
                environmental_score = (
                    self._assess_asset_criticality(vuln_match.service_name, vuln_match.port) +
                    self._assess_exposure_level(vuln_match.port, vuln_match.protocol)
                ) / 2.0

                prioritized_vuln = PrioritizedVulnerability(
                    vulnerability_match=vuln_match,
                    priority_score=priority_score,
                    risk_factors=risk_factors,
                    exploit_info=exploit_info,
                    business_impact=business_impact,
                    remediation_complexity=remediation_complexity,
                    temporal_score=temporal_score,
                    environmental_score=environmental_score
                )

                prioritized.append(prioritized_vuln)

        # Sort by priority score (highest first)
        prioritized.sort(key=lambda v: v.priority_score, reverse=True)

        return prioritized

    def filter_by_priority(self, prioritized_vulns: List[PrioritizedVulnerability],
                          min_score: float = 50.0) -> List[PrioritizedVulnerability]:
        """
        Filter vulnerabilities by minimum priority score

        Args:
            prioritized_vulns: List of prioritized vulnerabilities
            min_score: Minimum priority score threshold

        Returns:
            Filtered list of high-priority vulnerabilities
        """
        return [v for v in prioritized_vulns if v.priority_score >= min_score]

    def get_prioritization_summary(self, prioritized_vulns: List[PrioritizedVulnerability]) -> Dict:
        """
        Get summary statistics for prioritized vulnerabilities

        Args:
            prioritized_vulns: List of prioritized vulnerabilities

        Returns:
            Summary statistics
        """
        if not prioritized_vulns:
            return {
                'total_vulnerabilities': 0,
                'priority_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'exploit_availability': {'none': 0, 'poc': 0, 'functional': 0, 'weaponized': 0, 'in_the_wild': 0},
                'business_impact': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'average_priority_score': 0.0,
                'top_risk_factors': []
            }

        # Priority breakdown
        priority_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in prioritized_vulns:
            if vuln.priority_score >= 80:
                priority_breakdown['critical'] += 1
            elif vuln.priority_score >= 60:
                priority_breakdown['high'] += 1
            elif vuln.priority_score >= 40:
                priority_breakdown['medium'] += 1
            else:
                priority_breakdown['low'] += 1

        # Exploit availability breakdown
        exploit_breakdown = {'none': 0, 'poc': 0, 'functional': 0, 'weaponized': 0, 'in_the_wild': 0}
        for vuln in prioritized_vulns:
            if vuln.exploit_info:
                exploit_breakdown[vuln.exploit_info.availability.value] += 1
            else:
                exploit_breakdown['none'] += 1

        # Business impact breakdown
        business_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in prioritized_vulns:
            business_breakdown[vuln.business_impact] += 1

        # Top risk factors
        risk_factor_counts = {}
        for vuln in prioritized_vulns:
            for factor in vuln.risk_factors:
                risk_factor_counts[factor] = risk_factor_counts.get(factor, 0) + 1

        top_risk_factors = sorted(risk_factor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            'total_vulnerabilities': len(prioritized_vulns),
            'priority_breakdown': priority_breakdown,
            'exploit_availability': exploit_breakdown,
            'business_impact': business_breakdown,
            'average_priority_score': sum(v.priority_score for v in prioritized_vulns) / len(prioritized_vulns),
            'top_risk_factors': top_risk_factors
        }