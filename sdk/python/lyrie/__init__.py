"""
Lyrie Agent — Python SDK.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Embed the Shield Doctrine, Attack-Surface Mapper, Stages A–F validator,
multi-language scanners, threat-intel client, HTTP proxy, and EditEngine
in any Python project.
"""

from __future__ import annotations

__all__ = [
    "__version__",
    "SIGNATURE",
    # Shield Doctrine
    "Shield",
    "ShieldVerdict",
    # Attack-Surface Mapper
    "AttackSurfaceMapper",
    "AttackSurface",
    "EntryPoint",
    "TrustBoundary",
    "DataFlow",
    "RiskHotspot",
    # Stages A-F validator
    "StagesValidator",
    "ValidatedFinding",
    "StageVerdict",
    "Finding",
    # Multi-language scanners
    "scan_files",
    "ScanReport",
    # HTTP proxy
    "HttpProxy",
    "HttpExchange",
    "Mutator",
    # EditEngine
    "EditEngine",
    "EditPlan",
    # Threat-Intel
    "ThreatIntelClient",
    "ThreatAdvisory",
    # OSS-Scan
    "run_oss_scan",
    "OssScanResult",
    # LyrieEvolve
    "LyrieEvolve",
    "TaskOutcome",
    "SkillContext",
    "TrainingEntry",
    "ExtractionResult",
]

__version__ = "0.5.0"
SIGNATURE: str = "Lyrie.ai by OTT Cybersecurity LLC"

from lyrie.shield import Shield, ShieldVerdict
from lyrie.attack_surface import (
    AttackSurfaceMapper,
    AttackSurface,
    EntryPoint,
    TrustBoundary,
    DataFlow,
    RiskHotspot,
)
from lyrie.stages import (
    StagesValidator,
    ValidatedFinding,
    StageVerdict,
    Finding,
)
from lyrie.scanners import scan_files, ScanReport
from lyrie.proxy import HttpProxy, HttpExchange, Mutator
from lyrie.edits import EditEngine, EditPlan
from lyrie.threat_intel import ThreatIntelClient, ThreatAdvisory
from lyrie.oss_scan import run_oss_scan, OssScanResult
from lyrie.evolve import LyrieEvolve, TaskOutcome, SkillContext, TrainingEntry, ExtractionResult
