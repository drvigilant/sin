# SIN Current State

## Stack
Python 3.12, FastAPI, SQLAlchemy, Celery + Redis, PostgreSQL 15, Docker Compose
Groq API key in .env (used for AI advisory endpoint)
Binwalk v2.4.3 inside sin_api container

## Test Suite
**162 tests passing, 0 failures** (validated on server 2026-06-08)

| Test file                   | Tests | Coverage area                          |
|-----------------------------|-------|----------------------------------------|
| test_baseline_drift.py      | 14    | Risk drift detection, scan-to-scan delta|
| test_cpe_correlator.py      | 37    | CPE builder, seed DB, NVD client        |
| test_decision_engine.py     | 2     | Agent decision / severity verdict       |
| test_phase2_tasks.py        | 17    | Xiongmai SDK, scan-stuck bug, risk score|
| test_sbom_generator.py      | 27    | CycloneDX 1.4, opkg/dpkg/pip/npm/ELF   |
| test_sbom_store.py          | 29    | Persist/retrieve/list/delete SBOMs      |
| test_secret_extractor.py    | 25    | Credential/key detection, entropy guard |
| test_snmp_telemetry.py      | 25    | BER encoder, SNMP probe, normaliser     |

## Validated Working
- API: http://localhost:8000/health ✅
- Dashboard: http://localhost:8501 ✅
- PostgreSQL: 725 devices, 22 columns in device_logs ✅
- Celery: 3 tasks registered ✅
- Binwalk v2.4.3 inside sin_api container ✅
- /var/lib/sin/firmware/ output directory ✅
- /var/lib/sin/firmware/sbom/ SBOM storage directory ✅

## Completed Modules

### firmware/
- src/sin/firmware/__init__.py ✅
- src/sin/firmware/extractor.py ✅ (binwalk-based extraction)
- src/sin/firmware/secret_extractor.py ✅ REWRITTEN
  - Per-finding severity (CRITICAL/HIGH/MEDIUM/LOW)
  - Shannon entropy guard on generic API key patterns
  - Deduplication by (type, value, file)
  - IP addresses removed (were massive false-positive source)
  - Binary file skipping (ELF, images, archives)
- src/sin/firmware/sbom_generator.py ✅ NEW
  - CycloneDX 1.4 JSON output
  - Sources: opkg → dpkg → distinfo → package.json → requirements.txt → ELF SONAME
  - PURL generation for all components
  - Risk: LOW (authoritative DB), MEDIUM (heuristics), HIGH (nothing found)
- src/sin/firmware/sbom_store.py ✅ NEW
  - Filesystem persistence at /var/lib/sin/firmware/sbom/
  - save / get / get_meta / list_all / delete
  - Slug collision resolution
  - Lightweight meta index (no BOM body) for fast listing

### scanner/
- src/sin/scanner/http_fingerprint.py ✅ (35 vendor signatures + Xiongmai SDK probe)
- src/sin/scanner/jarm.py ✅ (TLS fingerprinting)
- src/sin/scanner/audit.py ✅ (evaluate_asset pipeline)
  - Layer 0a: MAC resolution (proc/arp + scapy + OUI vendor backfill)
  - Layer 0b: HTTP fingerprinting
  - Layer 1: ONVIF / ISAPI enrichment
  - Telemetry: ISAPI → SNMP fallback
  - CVE: CPE correlator (replaces vendor-fuzzy hardcoded blocks)
- src/sin/scanner/mac_resolver.py ✅ NEW
  - /proc/net/arp (zero packets)
  - Scapy ARP fallback (requires CAP_NET_RAW)
  - Offline OUI table (50+ IoT/CCTV vendor prefixes)
- src/sin/scanner/snmp_telemetry.py ✅ NEW
  - Raw UDP, zero external dependencies
  - OIDs: sysDescr, sysName, sysUpTime, hrProcessorLoad, hrStorage
  - Configurable: SIN_SNMP_COMMUNITIES, SIN_SNMP_TIMEOUT
  - Fills: cpu_usage, storage_usage, uptime, hostname, sys_descr
- src/sin/scanner/cpe_correlator.py ✅ NEW
  - CPE 2.3 string builder with vendor normalisation table
  - Offline IoT CVE seed DB (Hikvision, Dahua, Xiongmai, Zyxel, Cisco, Fortinet, D-Link, Reolink)
  - Version-aware matching (CVE-2017-7921 only fires on Hikvision < V5.5)
  - NVD API 2.0 live query (additive, Redis-cached 24h)
  - Set SIN_NVD_API_KEY for 50 req/30s (default: 5 req/30s)
- src/sin/scanner/kev_intel.py ✅ (CISA KEV annotation)
- src/sin/scanner/epss_intel.py ✅ (EPSS probability scoring)
- src/sin/scanner/cred_check.py ✅ (default credential testing)
- src/sin/scanner/isapi_intel.py ✅ (Hikvision ISAPI telemetry)
- src/sin/scanner/onvif_intel.py ✅
- src/sin/scanner/onvif_audit.py ✅
- src/sin/scanner/rtsp_probe.py ✅

### agent/
- src/sin/agent/runner.py ✅ (scan-stuck bug fixed: TTL=300, try/finally cleanup)
- src/sin/agent/decision.py ✅
- src/sin/agent/baseline.py ✅ (risk drift detection)
- src/sin/agent/signal_mapper.py ✅
- src/sin/agent/mitigation.py ✅
- src/sin/agent/notify.py ✅

### api/
- src/sin/api/server.py ✅
  - POST /firmware/upload — extract + secrets + SBOM + persist
  - GET  /firmware/sbom/           — list all SBOMs (meta only)
  - GET  /firmware/sbom/{slug}     — retrieve full CycloneDX document
  - DELETE /firmware/sbom/{slug}   — delete SBOM
  - GET  /firmware/results/{filename} — raw extraction file listing
- src/sin/api/auth.py ✅ (JWT + bcrypt + refresh token rotation)

### storage/
- src/sin/storage/models.py ✅ (DeviceLog, SecurityEvent, ScanSession)
- src/sin/storage/registry.py ✅ (DeviceRegistry with whitelist)
- src/sin/storage/database.py ✅
- src/sin/storage/credential_vault.py ✅

## Resolved Gaps
- ~~telemetry column always {}~~ → SNMP fallback covers Dahua/Axis/Uniview/Hanwha/routers
- ~~mac_address Unknown on most devices~~ → proc/arp + scapy ARP + OUI backfill
- ~~No secret_extractor~~ → rewritten with severity, entropy guard, dedup
- ~~No sbom_generator~~ → CycloneDX 1.4, 6 source types, persisted
- ~~CVE matching vendor-fuzzy~~ → CPE 2.3 + version-aware + NVD live query

## Known Remaining Gaps / Deprecation Warnings
- `@app.on_event` deprecated → migrate to FastAPI lifespan (deferred, Phase 6)
- `datetime.utcnow()` deprecated → use `datetime.now(UTC)` (deferred)
- `passlib crypt` warning → Python 3.13 concern, not urgent on 3.12
- No hardware module yet (burn-in / component telemetry — Phase roadmap)
- No React UI yet (Phase 8)
- RBAC / session management not started (Phase 6)

## Next on Roadmap
1. Burn-in telemetry agent — manufacturer use case (Phase 5 hardware)
2. RTSP authentication probing — complete the RTSP probe module
3. Agentic AI multi-step reasoning (Phase 4)
4. Firmware binary analysis pipeline with Ghidra/EMBA (Phase 5)
5. RBAC / session management (Phase 6)
6. React UI rebuild (Phase 8)

## Environment Variables (new since last state)
```
SIN_SNMP_COMMUNITIES=public,private,admin   # default: public
SIN_SNMP_TIMEOUT=2                          # seconds
SIN_NVD_API_KEY=<your_key>                  # optional, raises rate limit to 50/30s
SIN_SBOM_DIR=/var/lib/sin/firmware/sbom     # default path
```

## File Counts
- Source modules: 52 .py files
- Test files: 8 unit test files
- Total tests: 162 passing
