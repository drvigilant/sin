"""
tests/unit/test_cpe_correlator.py
Unit tests for sin.scanner.cpe_correlator
All NVD network I/O is mocked — no real HTTP traffic.
"""
from unittest.mock import MagicMock, patch
import pytest

from sin.scanner.cpe_correlator import (
    CPEBuilder,
    CPECorrelator,
    NVDClient,
    _VENDOR_NORM,
    cpe_correlator,
)


# ── CPEBuilder ─────────────────────────────────────────────────────────────

class TestCPEBuilder:

    def test_basic_string_format(self):
        cpe = CPEBuilder.build("hikvision", "ds-2cd2143g2", "5.6.0")
        assert cpe.startswith("cpe:2.3:")
        assert "hikvision" in cpe

    def test_vendor_lowercased(self):
        cpe = CPEBuilder.build("Hikvision", "Camera", "V5.6.0")
        assert "hikvision" in cpe

    def test_version_strips_leading_v(self):
        cpe = CPEBuilder.build("dahua", "ipc", "V2.840.00")
        assert "v" not in cpe.split(":")[5]
        assert "2.840.00" in cpe

    def test_spaces_replaced_with_underscores(self):
        cpe = CPEBuilder.build("tp-link", "tapo c200", "1.0.0")
        assert " " not in cpe
        assert "tapo_c200" in cpe

    def test_wildcard_when_empty_vendor(self):
        # CPE 2.3: cpe:2.3:type:vendor:product:version
        # indexes:  0   1  2   3      4       5
        cpe = CPEBuilder.build("", "product", "1.0")
        assert cpe.split(":")[3] == "*"   # vendor = field 3

    def test_wildcard_when_unknown_version(self):
        cpe = CPEBuilder.build("axis", "p3245", "unknown")
        assert cpe.split(":")[5] == "*"

    def test_from_device_hikvision(self):
        dd = {"vendor": "Hikvision", "model": "DS-2CD2143G2-I", "firmware": "V5.5.800"}
        vendor, product, version, cpe = CPEBuilder.from_device(dd)
        assert vendor   == "hikvision"
        assert product  == "ds-2cd2143g2-i"
        assert "5.5.800" in version

    def test_from_device_dahua(self):
        dd = {"manufacturer": "Dahua Technology", "model": "IPC-HDW2831T", "firmware": "V2.840.00"}
        vendor, product, version, cpe = CPEBuilder.from_device(dd)
        assert vendor == "dahua"

    def test_from_device_no_vendor_returns_wildcard(self):
        dd = {"model": "Camera", "firmware": "1.0"}
        vendor, product, version, cpe = CPEBuilder.from_device(dd)
        assert vendor == "*"

    def test_from_device_securus_maps_to_xiongmai(self):
        dd = {"vendor": "Securus", "model": "DVR", "firmware": "unknown"}
        vendor, product, version, cpe = CPEBuilder.from_device(dd)
        assert vendor == "xiongmai"

    def test_from_device_xiongmai_oem(self):
        dd = {"vendor": "Xiongmai-OEM"}
        vendor, product, version, cpe = CPEBuilder.from_device(dd)
        assert vendor == "xiongmai"

    def test_from_device_uses_vendor_over_manufacturer(self):
        dd = {"vendor": "Hikvision", "manufacturer": "Unknown"}
        vendor, _, _, _ = CPEBuilder.from_device(dd)
        assert vendor == "hikvision"

    def test_special_chars_stripped(self):
        cpe = CPEBuilder.build("test/vendor", "product!name", "1.0")
        assert "/" not in cpe.split(":")[4]
        assert "!" not in cpe


# ── Offline seed — version-aware matching ─────────────────────────────────

class TestSeedMatching:

    def _correlate(self, vendor, firmware="unknown", model="*"):
        correlator = CPECorrelator.__new__(CPECorrelator)
        correlator._nvd = MagicMock()
        correlator._nvd.query_cpe.return_value = []
        correlator._builder = CPEBuilder()

        dd = {"vendor": vendor, "firmware": firmware, "model": model,
              "open_ports": []}
        return correlator.correlate(dd)

    def test_hikvision_old_firmware_triggers_cve_2017_7921(self):
        findings = self._correlate("Hikvision", firmware="V5.4.0")
        cves = [f["cve"] for f in findings]
        assert "CVE-2017-7921" in cves

    def test_hikvision_new_firmware_no_cve_2017_7921(self):
        findings = self._correlate("Hikvision", firmware="V5.6.0")
        cves = [f["cve"] for f in findings]
        assert "CVE-2017-7921" not in cves

    def test_hikvision_old_firmware_triggers_cve_2021_36260(self):
        findings = self._correlate("Hikvision", firmware="V5.5.0")
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-36260" in cves

    def test_hikvision_new_firmware_no_cve_2021_36260(self):
        findings = self._correlate("Hikvision", firmware="V5.7.0")
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-36260" not in cves

    def test_hikvision_unknown_firmware_conservative(self):
        """Unknown version → assume affected (conservative security posture)."""
        findings = self._correlate("Hikvision", firmware="unknown")
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-36260" in cves

    def test_dahua_triggers_cve_2021_33044(self):
        findings = self._correlate("Dahua")
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-33044" in cves

    def test_dahua_triggers_cve_2021_33045(self):
        findings = self._correlate("Dahua")
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-33045" in cves

    def test_xiongmai_triggers_cve_2018_10088(self):
        findings = self._correlate("Xiongmai")
        cves = [f["cve"] for f in findings]
        assert "CVE-2018-10088" in cves

    def test_securus_maps_to_xiongmai_cves(self):
        findings = self._correlate("Securus")
        cves = [f["cve"] for f in findings]
        assert "CVE-2018-10088" in cves

    def test_zyxel_triggers_cves(self):
        findings = self._correlate("zyxel")
        cves = [f["cve"] for f in findings]
        assert "CVE-2022-30525" in cves

    def test_unknown_vendor_returns_empty(self):
        findings = self._correlate("UnknownBrandXYZ")
        assert findings == []

    def test_findings_have_required_fields(self):
        findings = self._correlate("Hikvision", "V5.4.0")
        for f in findings:
            assert "cve"         in f
            assert "severity"    in f
            assert "cvss"        in f
            assert "description" in f
            assert "type"        in f
            assert "source"      in f

    def test_kev_flag_set_on_seed_entries(self):
        findings = self._correlate("Hikvision", "V5.4.0")
        hik_cve = next(f for f in findings if f["cve"] == "CVE-2021-36260")
        assert hik_cve["in_kev"] is True

    def test_cpe_string_embedded_in_finding(self):
        findings = self._correlate("Hikvision", "V5.4.0", "DS-2CD2143G2")
        assert all("cpe" in f for f in findings)
        assert all("hikvision" in f["cpe"] for f in findings)

    def test_no_duplicate_cves(self):
        findings = self._correlate("Hikvision", "V5.4.0")
        cves = [f["cve"] for f in findings]
        assert len(cves) == len(set(cves))


# ── NVD client (mocked) ───────────────────────────────────────────────────

class TestNVDClient:

    def _client(self):
        c = NVDClient.__new__(NVDClient)
        c._redis    = None
        c._last_req = 0.0
        c._api_key  = ""
        return c

    def test_wildcard_cpe_skips_nvd(self):
        client = self._client()
        result = client.query_cpe("cpe:2.3:*:hikvision:*:*:*:*:*:*:*:*:*")
        assert result == []

    def test_parse_nvd_response_extracts_cve(self):
        mock_resp = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-99999",
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }]
                    }
                }
            }]
        }
        results = NVDClient._parse_nvd_response(mock_resp)
        assert len(results) == 1
        assert results[0]["cve"]      == "CVE-2021-99999"
        assert results[0]["cvss"]     == 9.8
        assert results[0]["severity"] == "CRITICAL"
        assert "Test vuln" in results[0]["description"]

    def test_parse_nvd_response_empty(self):
        assert NVDClient._parse_nvd_response({}) == []
        assert NVDClient._parse_nvd_response({"vulnerabilities": []}) == []

    def test_nvd_http_error_returns_empty(self):
        import urllib.error
        client = self._client()
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=503, msg="", hdrs=None, fp=None
        )):
            result = client._fetch("cpe:2.3:*:hikvision:ds-2cd2143g2:5.5.0:*:*:*:*:*:*:*")
        assert result == []

    def test_nvd_network_error_returns_empty(self):
        import urllib.error
        client = self._client()
        with patch("urllib.request.urlopen", side_effect=ConnectionError("unreachable")):
            result = client._fetch("cpe:2.3:*:hikvision:ds-2cd2143g2:5.5.0:*:*:*:*:*:*:*")
        assert result == []

    def test_nvd_results_merged_without_duplicates(self):
        """NVD result for CVE already in seed should not appear twice."""
        correlator = CPECorrelator.__new__(CPECorrelator)
        correlator._builder = CPEBuilder()
        mock_nvd = MagicMock()
        # NVD returns CVE-2021-36260 which seed already has
        mock_nvd.query_cpe.return_value = [{
            "cve": "CVE-2021-36260",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "NVD copy",
            "source": "nvd",
        }]
        correlator._nvd = mock_nvd
        dd = {"vendor": "Hikvision", "firmware": "V5.4.0",
              "model": "DS-2CD2143G2-I", "open_ports": []}
        findings = correlator.correlate(dd)
        cves = [f["cve"] for f in findings]
        assert cves.count("CVE-2021-36260") == 1

    def test_nvd_new_cve_added_to_findings(self):
        """NVD returns a NEW CVE not in the seed — it should appear."""
        correlator = CPECorrelator.__new__(CPECorrelator)
        correlator._builder = CPEBuilder()
        mock_nvd = MagicMock()
        mock_nvd.query_cpe.return_value = [{
            "cve": "CVE-2024-99999",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "A new NVD finding",
            "source": "nvd",
        }]
        correlator._nvd = mock_nvd
        dd = {"vendor": "Hikvision", "firmware": "V5.4.0",
              "model": "DS-2CD2143G2-I", "open_ports": []}
        findings = correlator.correlate(dd)
        cves = [f["cve"] for f in findings]
        assert "CVE-2024-99999" in cves


# ── Module-level singleton ─────────────────────────────────────────────────

def test_singleton_exists():
    assert cpe_correlator is not None
    assert isinstance(cpe_correlator, CPECorrelator)


# ── Vendor normalisation table completeness ────────────────────────────────

def test_vendor_norm_covers_major_brands():
    for brand in ("hikvision", "dahua", "xiongmai", "axis", "zyxel",
                  "cisco", "fortinet", "tp-link", "ubiquiti"):
        assert brand in _VENDOR_NORM, f"{brand} missing from _VENDOR_NORM"
