"""
tests/unit/test_sbom_generator.py
Unit tests for sin.firmware.sbom_generator.SBOMGenerator
"""
import json
import os
import tempfile
import pytest
from sin.firmware.sbom_generator import SBOMGenerator


def make_tree(files: dict) -> str:
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if isinstance(content, bytes):
            with open(full, "wb") as f:
                f.write(content)
        else:
            with open(full, "w") as f:
                f.write(content)
    return d


# ── CycloneDX schema shape ─────────────────────────────────────────────────

def test_bom_has_required_cyclonedx_fields():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    bom = r["sbom_document"]
    assert bom["bomFormat"]   == "CycloneDX"
    assert bom["specVersion"] == "1.4"
    assert "serialNumber" in bom
    assert "metadata"     in bom
    assert "components"   in bom


def test_bom_serial_is_urn_uuid():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    assert r["sbom_document"]["serialNumber"].startswith("urn:uuid:")


def test_bom_metadata_has_timestamp():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    assert "timestamp" in r["sbom_document"]["metadata"]


def test_bom_metadata_tool_is_sin():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    tools = r["sbom_document"]["metadata"]["tools"]
    assert any(t["vendor"] == "SIN" for t in tools)


# ── opkg parsing ───────────────────────────────────────────────────────────

OPKG_STATUS = """\
Package: busybox
Version: 1.35.0-r0
Architecture: arm_cortex-a9
Description: The Swiss Army Knife of Embedded Linux

Package: dropbear
Version: 2022.82-r0
Architecture: arm_cortex-a9
Description: A lightweight SSH server

Package: openssl
Version: 1.1.1q-r0
Architecture: arm_cortex-a9
Description: Cryptographic library

"""


def test_parses_opkg_status():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "busybox"  in names
    assert "dropbear" in names
    assert "openssl"  in names


def test_opkg_components_have_purl():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    comps = r["sbom_document"]["components"]
    for c in comps:
        assert "purl" in c
        assert c["purl"].startswith("pkg:opkg/")


def test_opkg_sets_risk_low():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    assert r["sbom_risk_level"] == "LOW"
    assert r["sbom_component_count"] == 3


def test_opkg_component_has_version():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    busybox = next(c for c in r["sbom_document"]["components"] if c["name"] == "busybox")
    assert busybox["version"] == "1.35.0-r0"


def test_opkg_var_lib_path_also_works():
    d = make_tree({"var/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    assert r["sbom_component_count"] == 3


# ── dpkg parsing ───────────────────────────────────────────────────────────

DPKG_STATUS = """\
Package: libc6
Status: install ok installed
Version: 2.31-13+deb11u5

Package: libssl1.1
Status: install ok installed
Version: 1.1.1n-0+deb11u4

"""


def test_parses_dpkg_status():
    d = make_tree({"var/lib/dpkg/status": DPKG_STATUS})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "libc6"     in names
    assert "libssl1.1" in names


def test_dpkg_purl_uses_deb_ecosystem():
    d = make_tree({"var/lib/dpkg/status": DPKG_STATUS})
    r = SBOMGenerator().generate(d)
    for c in r["sbom_document"]["components"]:
        assert c["purl"].startswith("pkg:deb/")


# ── Python dist-info ───────────────────────────────────────────────────────

DISTINFO_META = """\
Metadata-Version: 2.1
Name: requests
Version: 2.28.1
Summary: Python HTTP for Humans.
"""


def test_parses_python_distinfo():
    d = make_tree({"usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA": DISTINFO_META})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "requests" in names


def test_distinfo_purl_uses_pypi():
    d = make_tree({"lib/python3.9/site-packages/urllib3-1.26.12.dist-info/METADATA":
                   "Name: urllib3\nVersion: 1.26.12\n"})
    r = SBOMGenerator().generate(d)
    c = next((c for c in r["sbom_document"]["components"] if c["name"] == "urllib3"), None)
    assert c is not None
    assert "pkg:pypi/urllib3" in c["purl"]


# ── Node.js package.json ───────────────────────────────────────────────────

PKG_JSON = json.dumps({
    "name": "camera-ui",
    "version": "3.1.0",
    "description": "Camera web interface",
    "dependencies": {
        "express": "^4.18.2",
        "ws": "^8.12.0",
    }
})


def test_parses_package_json():
    d = make_tree({"app/package.json": PKG_JSON})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "camera-ui" in names
    assert "express"   in names
    assert "ws"        in names


def test_npm_purl_ecosystem():
    d = make_tree({"app/package.json": PKG_JSON})
    r = SBOMGenerator().generate(d)
    for c in r["sbom_document"]["components"]:
        assert c["purl"].startswith("pkg:npm/")


# ── requirements.txt ───────────────────────────────────────────────────────

REQUIREMENTS = """\
flask>=2.2.0
requests==2.28.1
# a comment
cryptography>=38.0.0
"""


def test_parses_requirements_txt():
    d = make_tree({"app/requirements.txt": REQUIREMENTS})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "flask"        in names
    assert "requests"     in names
    assert "cryptography" in names


def test_requirements_comments_ignored():
    d = make_tree({"app/requirements.txt": REQUIREMENTS})
    r = SBOMGenerator().generate(d)
    names = [c["name"] for c in r["sbom_document"]["components"]]
    assert "a comment" not in names


# ── Deduplication ─────────────────────────────────────────────────────────

def test_dedup_same_package_from_two_sources():
    """requests appears in both distinfo and requirements.txt — should be one component."""
    d = make_tree({
        "lib/requests-2.28.1.dist-info/METADATA": "Name: requests\nVersion: 2.28.1\n",
        "app/requirements.txt": "requests==2.28.1\n",
    })
    r = SBOMGenerator().generate(d)
    req_comps = [c for c in r["sbom_document"]["components"] if c["name"] == "requests"]
    assert len(req_comps) == 1
    # Should prefer higher-priority source (distinfo > requirements.txt)
    assert "pkg:pypi/requests" in req_comps[0]["purl"]


# ── bom-ref uniqueness ─────────────────────────────────────────────────────

def test_all_components_have_bom_ref():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    refs = [c["bom-ref"] for c in r["sbom_document"]["components"]]
    assert len(refs) == len(set(refs))   # all unique


# ── Risk level logic ───────────────────────────────────────────────────────

def test_risk_high_when_no_components_found():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    assert r["sbom_risk_level"] == "HIGH"
    assert r["sbom_component_count"] == 0


def test_risk_low_when_authoritative_source():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    assert r["sbom_risk_level"] == "LOW"


def test_sbom_sources_listed():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    assert "opkg" in r["sbom_sources"]


# ── Result schema contract ─────────────────────────────────────────────────

def test_result_has_all_required_keys():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SBOMGenerator().generate(d)
    for key in ("sbom_success", "sbom_component_count", "sbom_risk_level",
                "sbom_document", "sbom_error"):
        assert key in r


def test_missing_directory_returns_error():
    r = SBOMGenerator().generate("/nonexistent/path")
    assert r["sbom_success"]  == False
    assert r["sbom_error"]    is not None
    assert r["sbom_document"] == {}


def test_firmware_name_in_bom_metadata():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d, firmware_name="IPC-HFW2831T-ZAS", firmware_version="V2.840.00")
    comp = r["sbom_document"]["metadata"]["component"]
    assert comp["name"]    == "IPC-HFW2831T-ZAS"
    assert comp["version"] == "V2.840.00"


def test_empty_dir_returns_success_zero_components():
    d = tempfile.mkdtemp()
    r = SBOMGenerator().generate(d)
    assert r["sbom_success"] == True
    assert r["sbom_component_count"] == 0
    assert r["sbom_error"] is None


def test_bom_is_json_serializable():
    d = make_tree({"usr/lib/opkg/status": OPKG_STATUS})
    r = SBOMGenerator().generate(d)
    # Must not raise
    serialized = json.dumps(r["sbom_document"])
    assert len(serialized) > 100
