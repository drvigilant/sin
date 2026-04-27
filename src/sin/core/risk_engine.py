def calculate_risk(device: dict) -> dict:
    score = 0
    reasons = []

    # ── Vulnerabilities ─────────────────────────
    for v in device.get("vulnerabilities", []):
        sev = v.get("severity", "").upper()

        if sev == "CRITICAL":
            score += 40
            reasons.append("Critical vulnerability detected")
        elif sev == "HIGH":
            score += 25
            reasons.append("High severity vulnerability")
        elif sev == "MEDIUM":
            score += 15
        elif sev == "LOW":
            score += 5

    # ── Ports ───────────────────────────────────
    ports = device.get("open_ports", [])

    if 23 in ports:
        score += 30
        reasons.append("Telnet exposed (port 23)")
    if 21 in ports:
        score += 20
        reasons.append("FTP exposed (port 21)")
    if 554 in ports:
        score += 20
        reasons.append("RTSP camera stream exposed")
    if 1883 in ports:
        score += 15
        reasons.append("MQTT exposed")

    # ── Device Type ─────────────────────────────
    vendor = (device.get("vendor") or "").lower()

    if any(v in vendor for v in ["hikvision", "dahua", "axis"]):
        score += 15
        reasons.append("CCTV device (high-risk target)")
    elif any(v in vendor for v in ["mikrotik", "ubiquiti", "cisco"]):
        score += 10
        reasons.append("Network infrastructure device")

    # ── Normalize ───────────────────────────────
    score = min(score, 100)

    # ── Risk Level ──────────────────────────────
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_reasons": list(set(reasons))  # remove duplicates
    }
