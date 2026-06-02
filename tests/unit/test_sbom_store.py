"""
tests/unit/test_sbom_store.py
Unit tests for sin.firmware.sbom_store.SBOMStore
All filesystem I/O uses a temp directory — nothing written to /var/lib/sin.
"""
import json
import os
import tempfile
import pytest
from unittest.mock import patch

from sin.firmware.sbom_store import SBOMStore, _slugify


# ── Helpers ────────────────────────────────────────────────────────────────

def make_store(tmp_dir: str) -> SBOMStore:
    """Return a SBOMStore pointed at a temp directory."""
    store = SBOMStore()
    # Patch the module-level _SBOM_DIR used inside the store methods
    import sin.firmware.sbom_store as _mod
    _mod._SBOM_DIR = tmp_dir
    return store


def fake_sbom_result(component_count: int = 3, risk: str = "LOW") -> dict:
    return {
        "sbom_success":         True,
        "sbom_component_count": component_count,
        "sbom_risk_level":      risk,
        "sbom_sources":         ["opkg"],
        "sbom_error":           None,
        "sbom_document": {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:test-1234",
            "components": [{"name": f"pkg{i}", "version": "1.0"} for i in range(component_count)],
        },
    }


# ── _slugify ───────────────────────────────────────────────────────────────

def test_slugify_simple():
    assert _slugify("firmware.bin") == "firmware"

def test_slugify_strips_extension():
    assert _slugify("IPC-HFW2831T.bin") == "ipc-hfw2831t"

def test_slugify_spaces_to_underscores():
    assert _slugify("my firmware v2.bin") == "my_firmware_v2"

def test_slugify_special_chars():
    slug = _slugify("fw!@#$%.bin")
    assert re.search(r"[!@#$%]", slug) is None if True else True
    assert slug  # non-empty

def test_slugify_empty_name():
    assert _slugify(".bin") == "firmware"

def test_slugify_lowercased():
    assert _slugify("FIRMWARE.BIN") == "firmware"


# ── save ──────────────────────────────────────────────────────────────────

def test_save_creates_sbom_file():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("firmware.bin", fake_sbom_result())
        files = os.listdir(d)
        assert any(f.endswith(".sbom.json") for f in files)

def test_save_creates_meta_file():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("firmware.bin", fake_sbom_result())
        files = os.listdir(d)
        assert any(f.endswith(".meta.json") for f in files)

def test_save_returns_meta_dict():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("firmware.bin", fake_sbom_result(5, "HIGH"))
        assert meta["component_count"] == 5
        assert meta["risk_level"]      == "HIGH"
        assert meta["firmware_filename"] == "firmware.bin"
        assert "slug"     in meta
        assert "saved_at" in meta

def test_save_sbom_file_is_valid_json():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result())
        with open(os.path.join(d, f"{meta['slug']}.sbom.json")) as fh:
            doc = json.load(fh)
        assert doc["bomFormat"] == "CycloneDX"

def test_save_meta_contains_sources():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result())
        assert "opkg" in meta["sources"]

def test_save_same_filename_overwrites():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("fw.bin", fake_sbom_result(3))
        store.save("fw.bin", fake_sbom_result(10))
        meta = store.get_meta("fw")
        assert meta["component_count"] == 10

def test_save_different_filenames_get_different_slugs():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        m1 = store.save("camera_a.bin", fake_sbom_result())
        m2 = store.save("camera_b.bin", fake_sbom_result())
        assert m1["slug"] != m2["slug"]


# ── get ───────────────────────────────────────────────────────────────────

def test_get_returns_cyclonedx_document():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result())
        doc  = store.get(meta["slug"])
        assert doc is not None
        assert doc["bomFormat"] == "CycloneDX"

def test_get_missing_slug_returns_none():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        assert store.get("nonexistent_slug") is None

def test_get_components_match_saved():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result(7))
        doc  = store.get(meta["slug"])
        assert len(doc["components"]) == 7


# ── get_meta ──────────────────────────────────────────────────────────────

def test_get_meta_returns_dict():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta  = store.save("fw.bin", fake_sbom_result())
        fetched = store.get_meta(meta["slug"])
        assert fetched is not None
        assert fetched["slug"] == meta["slug"]

def test_get_meta_missing_returns_none():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        assert store.get_meta("no_such_slug") is None

def test_get_meta_does_not_include_bom_body():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta  = store.save("fw.bin", fake_sbom_result())
        fetched = store.get_meta(meta["slug"])
        # meta should NOT embed the full BOM (keep it lightweight)
        assert "components" not in fetched
        assert "sbom_document" not in fetched


# ── list_all ──────────────────────────────────────────────────────────────

def test_list_all_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        assert store.list_all() == []

def test_list_all_returns_all_records():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("cam_a.bin", fake_sbom_result())
        store.save("cam_b.bin", fake_sbom_result())
        store.save("cam_c.bin", fake_sbom_result())
        records = store.list_all()
        assert len(records) == 3

def test_list_all_sorted_newest_first():
    import time
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("old.bin", fake_sbom_result())
        time.sleep(1.1)   # ensure different saved_at second
        store.save("new.bin", fake_sbom_result())
        records = store.list_all()
        assert records[0]["firmware_filename"] == "new.bin"

def test_list_all_no_bom_body_in_records():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("fw.bin", fake_sbom_result())
        for r in store.list_all():
            assert "components" not in r

def test_list_all_contains_required_fields():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        store.save("fw.bin", fake_sbom_result())
        record = store.list_all()[0]
        for field in ("slug", "firmware_filename", "component_count",
                      "risk_level", "saved_at", "sources"):
            assert field in record, f"missing field: {field}"


# ── delete ────────────────────────────────────────────────────────────────

def test_delete_removes_sbom_and_meta():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta  = store.save("fw.bin", fake_sbom_result())
        slug  = meta["slug"]
        store.delete(slug)
        assert store.get(slug)      is None
        assert store.get_meta(slug) is None

def test_delete_returns_true_when_deleted():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result())
        assert store.delete(meta["slug"]) is True

def test_delete_returns_false_when_not_found():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        assert store.delete("nonexistent") is False

def test_delete_removes_from_list():
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        meta = store.save("fw.bin", fake_sbom_result())
        store.delete(meta["slug"])
        assert store.list_all() == []


# ── failed SBOM result (sbom_success=False) ───────────────────────────────

def test_save_failed_result_still_saves():
    """Even a failed SBOM (no components) should be saveable for audit trail."""
    with tempfile.TemporaryDirectory() as d:
        store = make_store(d)
        result = fake_sbom_result(0)
        result["sbom_success"] = False
        result["sbom_error"]   = "binwalk failed"
        meta = store.save("corrupt.bin", result)
        assert meta["component_count"] == 0
        assert meta["sbom_success"]    is False


# ── import guard ──────────────────────────────────────────────────────────
import re  # used in test_slugify_special_chars above
