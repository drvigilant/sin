# src/sin/firmware/secret_extractor.py
import os
import re
from typing import Dict, List

from sin.utils.logger import get_logger

logger = get_logger(__name__)

class SecretExtractor:
    def scan(self, extracted_path: str) -> Dict[str, List[str] | str | int | None]:
        result = {
            "secrets_found": [],
            "risk_level": "LOW",
            "file_count_scanned": 0,
            "error": None
        }

        try:
            secrets_pattern = {
                "private_key": [
                    r"^-{5,}BEGIN PRIVATE KEY-{5,}$",
                    r"^-{5,}BEGIN RSA PRIVATE KEY-{5,}$",
                ],
                "hardcoded_passwords": [
                    r"password\s*[=\:]\s*['\"]?[^'\"]*",
                    r"passwd\s*[=\:]\s*['\"]?[^'\"]*",
                    r"pwd\s*[=\:]\s*['\"]?[^'\"]*",
                ],
                "api_tokens": [
  		   r"AKIA[0-9A-Z]{16}",
	           r"(token|api_key|secret)\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}['\"]?",
		],
		"ip_addresses": [
		    r"(?<!\d)\b(?!127\.)(?!255\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?!\.\d)",
		],
            }
            found_secrets = []

            if not os.path.isdir(extracted_path):
                raise Exception(f"Directory not found: {extracted_path}")

            file_count = 0

            for root, _, files in os.walk(extracted_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        for key, patterns in secrets_pattern.items():
                            for pattern in patterns:
                                matches = re.findall(pattern, content, flags=re.MULTILINE)
                                if matches:
                                    for match in matches:
                                        clean_match = match.strip()
                                        if "BEGIN PRIVATE KEY" in clean_match:
                                            clean_match = clean_match.replace("-----", "").strip()
                                            clean_match_type = "PRIVATE_KEY"
                                        elif "password" in key.lower():
                                            clean_match_type = "PASSWORD"
                                        elif "token" in key.lower():
                                            clean_match_type = "TOKEN"
                                        elif "ip" in key.lower():
                                            clean_match_type = "IP_ADDRESS"
                                        else:
                                            clean_match_type = key
                                        found_secrets.append({
                                            "type": clean_match_type.upper(),
                                            "value": clean_match,
                                            "file": file_path
                                        })
                    except Exception as e:
                        continue
                    file_count += 1

            result["secrets_found"] = found_secrets
            result["file_count_scanned"] = file_count

            if len(found_secrets) > 10:
                result["risk_level"] = "HIGH"
            elif len(found_secrets) > 0:
                result["risk_level"] = "MEDIUM"
            else:
                result["risk_level"] = "LOW"

        except Exception as e:
            logger.error(f"Error scanning directory {extracted_path}: {e}")
            result["error"] = str(e)

        return result
