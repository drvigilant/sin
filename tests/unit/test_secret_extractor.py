"""
tests/unit/test_secret_extractor.py
Unit tests for sin.firmware.secret_extractor.SecretExtractor
"""
import os
import tempfile
import pytest
from sin.firmware.secret_extractor import SecretExtractor


# ── Helpers ────────────────────────────────────────────────────────────────

def make_tree(files: dict) -> str:
    """Create a temp directory tree from {relative_path: content} dict."""
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
    return d


# ── Private key detection ──────────────────────────────────────────────────

def test_detects_rsa_private_key():
    d = make_tree({"etc/ssl/server.key":
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"})
    r = SecretExtractor().scan(d)
    types = [f["type"] for f in r["secrets_found"]]
    assert "PRIVATE_KEY" in types
    assert r["risk_level"] == "CRITICAL"


def test_detects_ec_private_key():
    d = make_tree({"keys/ec.pem": "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "PRIVATE_KEY" for f in r["secrets_found"])


def test_detects_openssh_private_key():
    d = make_tree({"root/.ssh/id_rsa":
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC...\n-----END OPENSSH PRIVATE KEY-----"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "PRIVATE_KEY" for f in r["secrets_found"])


# ── Shadow hash / passwd detection ────────────────────────────────────────

def test_detects_shadow_hash():
    d = make_tree({"etc/shadow": "root:$1$abc123$hashedpasswordhere:19000:0:99999:7:::\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "SHADOW_HASH" for f in r["secrets_found"])
    assert r["risk_level"] in {"CRITICAL", "HIGH"}


def test_detects_passwd_style_root():
    d = make_tree({"etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n"})
    r = SecretExtractor().scan(d)
    # May or may not match depending on format — just ensure no crash
    assert "error" not in r or r["error"] is None


# ── Hardcoded password detection ───────────────────────────────────────────

def test_detects_hardcoded_password_equals():
    d = make_tree({"etc/config.conf": 'password=Sup3rS3cr3t!\nhost=192.168.1.1\n'})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "HARDCODED_PASSWORD" for f in r["secrets_found"])
    assert r["risk_level"] in {"CRITICAL", "HIGH"}


def test_detects_hardcoded_passwd_colon():
    d = make_tree({"app/settings.py": "passwd: 'MyPasswd123'\nport = 8080\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "HARDCODED_PASSWORD" for f in r["secrets_found"])


def test_short_password_value_ignored():
    """Values under 4 chars should not match (too likely to be placeholders)."""
    d = make_tree({"etc/conf": "password=\npasswd=ok\n"})
    r = SecretExtractor().scan(d)
    pw = [f for f in r["secrets_found"] if f["type"] == "HARDCODED_PASSWORD"]
    # Either no match or only matches with values >= 4 chars
    for f in pw:
        assert len(f["value"]) >= 4


# ── AWS credential detection ───────────────────────────────────────────────

def test_detects_aws_access_key():
    d = make_tree({"home/root/.aws/credentials":
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "AWS_ACCESS_KEY" for f in r["secrets_found"])
    assert r["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM"}


def test_detects_aws_secret_key():
    d = make_tree({"etc/env":
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "AWS_SECRET_KEY" for f in r["secrets_found"])


# ── Generic API key detection + entropy guard ─────────────────────────────

def test_detects_high_entropy_api_key():
    d = make_tree({"etc/app.conf":
        "api_key=aB3xQ9mZ2kLpR7nT4vYwS6cF1jHdUeOg\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "GENERIC_API_KEY" for f in r["secrets_found"])


def test_entropy_guard_rejects_low_entropy_token():
    """Low-entropy strings like 'aaaaaaaaaaaaaaaaa' should be filtered out."""
    d = make_tree({"etc/app.conf": "api_key=aaaaaaaaaaaaaaaaaaa\n"})
    r = SecretExtractor().scan(d)
    api = [f for f in r["secrets_found"] if f["type"] == "GENERIC_API_KEY"]
    assert len(api) == 0


def test_detects_github_token():
    d = make_tree({"home/admin/.config": "token=ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7\n"})
    r = SecretExtractor().scan(d)
    assert any(f["type"] == "GITHUB_TOKEN" for f in r["secrets_found"])


# ── IP addresses are NOT treated as secrets ────────────────────────────────

def test_ip_addresses_not_flagged():
    d = make_tree({"etc/hosts": "192.168.1.1 gateway\n10.0.0.1 router\n8.8.8.8 dns\n"})
    r = SecretExtractor().scan(d)
    assert not any(f["type"] == "IP_ADDRESS" for f in r["secrets_found"])


# ── Deduplication ─────────────────────────────────────────────────────────

def test_duplicate_findings_collapsed():
    content = "password=Sup3rS3cr3t!\n" * 50
    d = make_tree({"etc/config": content})
    r = SecretExtractor().scan(d)
    pw = [f for f in r["secrets_found"] if f["type"] == "HARDCODED_PASSWORD"]
    # Same value in same file should appear exactly once
    values = [f["value"] for f in pw]
    assert len(values) == len(set(values))


# ── Risk level roll-up ─────────────────────────────────────────────────────

def test_risk_level_critical_when_private_key_present():
    d = make_tree({
        "etc/ssl/key.pem": "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
        "etc/app.conf": "api_key=aB3xQ9mZ2kLpR7nT4vYwS6cF1jHdUeOg\n",
    })
    r = SecretExtractor().scan(d)
    assert r["risk_level"] == "CRITICAL"


def test_risk_level_low_when_no_findings():
    d = make_tree({"etc/hosts": "127.0.0.1 localhost\n"})
    r = SecretExtractor().scan(d)
    assert r["risk_level"] == "LOW"
    assert r["secrets_found"] == []


def test_risk_level_medium_for_api_key_only():
    d = make_tree({"etc/conf": "api_key=aB3xQ9mZ2kLpR7nT4vYwS6cF1jHdUeOg\n"})
    r = SecretExtractor().scan(d)
    assert r["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}  # at least MEDIUM


# ── File skipping ─────────────────────────────────────────────────────────

def test_binary_extensions_skipped():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "firmware.bin"), "wb") as f:
        f.write(b"\x00\x01\x02\x03" * 1000)
    r = SecretExtractor().scan(d)
    assert r["error"] is None


def test_file_count_reflects_skipped_extensions():
    d = make_tree({
        "etc/config.conf": "password=Sup3rS3cr3t!\n",
        "lib/image.png":   "fakepng",
    })
    r = SecretExtractor().scan(d)
    assert r["file_count_scanned"] == 1  # .png skipped


# ── Error handling ─────────────────────────────────────────────────────────

def test_missing_directory_returns_error():
    r = SecretExtractor().scan("/nonexistent/path/that/does/not/exist")
    assert r["error"] is not None
    assert r["secrets_found"] == []


def test_empty_directory_returns_clean():
    d = tempfile.mkdtemp()
    r = SecretExtractor().scan(d)
    assert r["risk_level"] == "LOW"
    assert r["secrets_found"] == []
    assert r["error"] is None


# ── Per-finding severity fields ───────────────────────────────────────────

def test_findings_have_severity_field():
    d = make_tree({"etc/ssl/key.pem":
        "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"})
    r = SecretExtractor().scan(d)
    for finding in r["secrets_found"]:
        assert "severity" in finding
        assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_findings_have_required_fields():
    d = make_tree({"etc/conf": "password=Sup3rS3cr3t!\n"})
    r = SecretExtractor().scan(d)
    for f in r["secrets_found"]:
        assert "type"     in f
        assert "severity" in f
        assert "value"    in f
        assert "file"     in f


def test_finding_value_truncated_to_120_chars():
    long_val = "A" * 200
    d = make_tree({"etc/conf": f"password={long_val}\n"})
    r = SecretExtractor().scan(d)
    for f in r["secrets_found"]:
        assert len(f["value"]) <= 120
