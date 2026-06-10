# Blog Post Outline
## "I Built an AI-Powered IoT Security Platform and Pointed It at 20 IP Cameras. Here's What It Found."

**Target publication:** Dev.to, Medium (Security), personal/portfolio blog  
**Audience:** Security engineers, IoT developers, platform architects, potential acqui-hire evaluators  
**Tone:** Technical first-person; show-don't-tell; let the findings carry the weight  
**Estimated length:** 2,500–3,500 words  
**Strategic goal:** Demonstrate SIN's depth as a research-grade platform, not just a toy scanner

---

## Hook / Lede

Open with the result, not the setup:

> *"Nineteen out of twenty cameras. Every one of them critical. Admin/admin still active on fourteen. CVE-2018-10088 — CISA KEV, EPSS 0.89 — running on all of them. I didn't need to write an exploit. I just had to look."*

Frame the post as: what happens when you build a serious platform and then actually use it.

---

## Section 1 — What Is SIN, and Why Did I Build It?

- One-paragraph origin story: the gap between enterprise IoT security tooling and real-world small fleet assessment
- Architecture overview (keep it high-level here — details in later sections):
  - FastAPI + Celery + Redis + PostgreSQL
  - Five major capability modules
  - 335-test suite; RBAC; JWT enforcement
- Acqui-hire positioning context (optional — depends on publication context)
- Thesis sentence: *"I wanted to know if a platform I built myself could surface real findings on real hardware. The answer was uncomfortable."*

---

## Section 2 — The Target: Securus CRIMSON (a.k.a. Xiongmai, a.k.a. "Every OEM Camera You've Ever Seen")

- What these cameras are: consumer/prosumer IP cameras sold under dozens of brand names
- The Xiongmai OEM supply chain problem — one firmware, infinite SKUs
- HiSilicon SoC family (Hi3516/Hi3518): the hardware that powers half the world's cheap IP cameras
- XMEye P2P cloud service: why "behind NAT" doesn't mean "not exposed"
- Brief history: Mirai (2016) → Satori → Okiru → Masuta; this platform is the recurring target
- *Why this matters beyond my 20 cameras*: millions of units globally, same firmware, same CVEs

---

## Section 3 — How SIN Assessed the Fleet

Walk through each module that touched these cameras:

### 3a. CPE Correlator → CVE Match
- Fingerprinting: how SIN identifies make/model from RTSP banners, ONVIF probes, HTTP headers
- CPE string construction → NVD API lookup
- Hit: CVE-2018-10088 matched on all 19 cameras
- What EPSS 0.89 means in plain language (not "score," but "89% of vulnerabilities with this score get exploited in the wild")

### 3b. RTSP Authentication Probe (Phase 3)
- SIN's dual-mode Basic + Digest auth tester
- The test: send authenticated DESCRIBE request, parse response code + SDP
- Finding: 14/19 returned 200 with valid SDP on `admin:admin`
- Code snippet (sanitized): the auth probe logic

### 3c. Unauthenticated Streams
- No-auth DESCRIBE → valid SDP = camera is streaming to anyone on the network
- What an attacker can do with a raw RTSP URL (vlc, ffmpeg, cv2 — zero barrier)

### 3d. ONVIF User Enumeration
- What ONVIF is, why it exists, why it's a problem when unauthenticated
- `GetUsers` SOAP call → list of usernames and roles returned without auth
- Eliminating the reconnaissance phase for an attacker

### 3e. AI Investigator (Phase 4)
- The agentic loop: plan → execute → synthesize (3 rounds, Groq `llama-3.3-70b-versatile`)
- How the investigator chains findings into a coherent threat narrative
- Example: investigator output for one camera (show a snippet of the synthesized report)
- Why LLM synthesis adds value over raw CVE dumps: context, chaining, prioritization

---

## Section 4 — The Findings, Plainly Stated

- CVE-2018-10088: what it does, how it's triggered, what an attacker gets
- Default creds: `admin:admin` in 2026. Not hypothetical. Confirmed.
- Unauthenticated streams: zero-click surveillance for anyone on the subnet
- ONVIF enumeration: free recon, delivered by the device itself
- Aggregate: these aren't isolated issues — they layer. RCE + default creds + no-auth streams = total compromise with one network hop

---

## Section 5 — What the Numbers Mean (Risk Context)

- CISA KEV: what it means to be listed (not theoretical — active exploitation confirmed by CISA)
- EPSS 0.89: brief explainer on the scoring model; why 0.89 is alarming
- CVSS 9.8: note that CVSS measures severity, not likelihood — EPSS fills that gap
- Real-world exposure: XMEye P2P means these cameras can be reached from the internet even if they're "internal"
- Mirai precedent: how fast unpatched Xiongmai devices are compromised when exposed

---

## Section 6 — What I Did About It

Remediation steps taken (brief — this isn't the focus):
- VLAN isolation
- RTSP 554 egress blocked
- P2P disabled where possible
- Credential rotation queued

*Honest note:* Firmware patching on Xiongmai devices is painful. Upstream patches exist; OEM rebadges often don't receive them. Long-term path: replacement.

---

## Section 7 — What Building SIN Taught Me

Shift from findings to platform reflection — this is the differentiating section:

- The hardest bugs weren't security bugs: they were the CORS/middleware/scoping bugs that made my own platform silently fail (brief allusion to the firmware upload bug resolution)
- Why a 335-test suite matters when you're doing agentic security work: you can't trust a platform that has no tests to run unattended assessments
- RBAC on a security platform: the irony of building a tool to find auth failures while shipping it without auth enforcement on your own destructive endpoints (and fixing it)
- The EPSS/KEV combination as a triage model: CVSS is not enough
- What "agentic" security actually means in practice vs. the hype

---

## Section 8 — What's Next for SIN

Frame the roadmap:
1. Real CPU/memory telemetry via SNMP inside Docker containers
2. CVE validation against the actual camera fleet (not just CPE matching)
3. Firmware upload + secrets extraction on real Xiongmai binary — SBOM output
4. Continuous monitoring mode: scheduled re-assessment with drift detection

*Closing line suggestion:* "The platform found what I hoped it would find. The cameras had what I feared they would have. The gap between 'assessed' and 'fixed' is still a human problem — but at least now the assessment doesn't require one."

---

## Appendix: Code Snippets to Include

- [ ] RTSP auth probe (Python, ~20 lines, sanitized)
- [ ] CPE correlator NVD lookup (Python, ~15 lines)
- [ ] ONVIF `GetUsers` SOAP request (XML template)
- [ ] AI Investigator prompt structure (pseudocode / template)
- [ ] SIN scan trigger (curl example against the API)

---

## SEO / Discoverability Tags

`iot-security`, `cve`, `ip-camera`, `xiongmai`, `rtsp`, `onvif`, `fastapi`, `python`, `security-research`, `vulnerability-assessment`, `mirai`, `cisa-kev`, `epss`

---

## Publication Checklist

- [ ] No live IPs or credentials in code snippets
- [ ] CVE numbers verified against NVD before publish
- [ ] CISA KEV listing confirmed current
- [ ] Responsible disclosure note (these are personally-owned devices on an isolated network)
- [ ] SIN GitHub link / README ready for traffic
- [ ] Screenshots of SIN UI showing findings (optional but high impact)

---

*Outline version 1.0 — SIN platform documentation series*
