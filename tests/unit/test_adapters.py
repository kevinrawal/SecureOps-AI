"""Unit tests for source adapters and the normalizer.

Adapters are pure ``dict -> SecureEvent`` transforms, so these run fully offline
against representative fixtures — no network, no Pinecone, no Redis.
"""

from __future__ import annotations

import pytest

from src.core.schema import EventSourceType, SecureEvent, SeverityLevel
from src.ingestion.adapters.nvd_adapter import NVDAdapter
from src.ingestion.adapters.siem_adapter import SIEMAdapter
from src.ingestion.adapters.syslog_adapter import SyslogAdapter
from src.ingestion.normalizer import Normalizer

# --- fixtures ---------------------------------------------------------------

NVD_CVE = {
    "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:00.000",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect "
                                    "against attacker controlled LDAP endpoints."}
        ],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]
        },
        "configurations": [
            {"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
            ]}]}
        ],
    }
}

SIEM_ALERT = {
    "rule_name": "Suspicious PowerShell Execution",
    "message": "Encoded PowerShell command spawned by Office process.",
    "severity": "high",
    "product": "Splunk",
    "host": "WIN-APP-07",
    "src_ip": "10.4.2.19",
    "timestamp": "2026-06-21T08:00:00Z",
    "tags": ["endpoint", "execution"],
}

SYSLOG_LINE = {
    "line": "<11>Jun 21 08:30:01 web01 sshd[2451]: Failed password for invalid "
            "user admin from 203.0.113.9 port 51022 ssh2",
    "host": "web01",
}


# --- NVD --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nvd_adapter_maps_cvss_to_critical():
    event = await NVDAdapter().parse(NVD_CVE)
    assert isinstance(event, SecureEvent)
    assert event.source_type is EventSourceType.CVE
    assert event.source_name == "NVD"
    assert event.severity is SeverityLevel.CRITICAL          # CVSS 10.0
    assert "CVE-2021-44228" in event.indicators
    assert any("log4j" in a for a in event.affected_assets)
    assert event.raw_data == NVD_CVE                          # raw preserved


@pytest.mark.asyncio
async def test_nvd_adapter_missing_metrics_defaults_info():
    minimal = {"cve": {"id": "CVE-0000-0000", "descriptions": []}}
    event = await NVDAdapter().parse(minimal)
    assert event.severity is SeverityLevel.INFO
    assert event.indicators == ["CVE-0000-0000"]


# --- SIEM -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_siem_adapter_best_effort_mapping():
    event = await SIEMAdapter().parse(SIEM_ALERT)
    assert event.source_type is EventSourceType.SIEM_ALERT
    assert event.source_name == "Splunk"
    assert event.severity is SeverityLevel.HIGH
    assert event.title == "Suspicious PowerShell Execution"
    assert "WIN-APP-07" in event.affected_assets
    assert "10.4.2.19" in event.indicators


@pytest.mark.asyncio
async def test_siem_adapter_unknown_fields_fall_back():
    event = await SIEMAdapter().parse({"foo": "bar"})
    assert event.title == "SIEM Alert"
    assert event.severity is SeverityLevel.INFO
    assert event.source_type is EventSourceType.SIEM_ALERT


# --- Syslog -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_syslog_adapter_decodes_pri_and_ip():
    event = await SyslogAdapter().parse(SYSLOG_LINE)
    assert event.source_type is EventSourceType.SYSLOG
    # PRI 11 -> severity 11 % 8 = 3 (Error) -> HIGH
    assert event.severity is SeverityLevel.HIGH
    assert "203.0.113.9" in event.indicators
    assert "web01" in event.affected_assets


# --- Normalizer registry routing -------------------------------------------

@pytest.mark.asyncio
async def test_normalizer_routes_by_hint():
    normalizer = Normalizer()
    event = await normalizer.normalize(NVD_CVE, EventSourceType.CVE)
    assert event.source_type is EventSourceType.CVE

    event2 = await normalizer.normalize(SIEM_ALERT, "SIEM_ALERT")
    assert event2.source_type is EventSourceType.SIEM_ALERT


@pytest.mark.asyncio
async def test_normalizer_unknown_source_raises():
    normalizer = Normalizer()
    with pytest.raises(ValueError):
        await normalizer.normalize({}, "NOT_A_SOURCE")
