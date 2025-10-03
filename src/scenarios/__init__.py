"""
Cortex Security Scenarios Package
=================================

This package contains Cortex XSIAM/Cloud specific security scenarios with competitive
analysis and realistic event generation capabilities.
"""

from .cortex_scenarios import (
    CortexScenarioLibrary,
    CortexScenario, 
    CortexCapability,
    ScenarioType,
    CORTEX_SCENARIO_LIBRARY
)

from .scenario_generator import (
    CortexScenarioGenerator,
    CortexEvent,
    CORTEX_SCENARIO_GENERATOR
)

__all__ = [
    'CortexScenarioLibrary',
    'CortexScenario',
    'CortexCapability', 
    'ScenarioType',
    'CortexScenarioGenerator',
    'CortexEvent',
    'CORTEX_SCENARIO_LIBRARY',
    'CORTEX_SCENARIO_GENERATOR'
]