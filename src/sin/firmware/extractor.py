# src/sin/firmware/extractor.py
import os
import shutil
import subprocess
import platform
from datetime import datetime
from typing import Dict

from sin.utils.logger import get_logger

logger = get_logger(__name__)

class FirmwareExtractor:
    BINWALK_PATH = "/usr/bin/binwalk"
    EXTRACT_DIR = "/var/lib/sin/firmware"

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def extract(self, firmware_path: str) -> Dict[str, str | int | bool | dict | None]:
        result = {
            "success": False,
            "extracted_path": None,
            "file_count": 0,
            "file_types": {},
            "raw_output": "",
            "error": None
        }

        extract_path = None

        try:
            filename = os.path.basename(firmware_path)
            extract_path = os.path.join(self.EXTRACT_DIR, filename)
            os.makedirs(extract_path, exist_ok=True)

            logger.info(f"Extracting firmware: {firmware_path}")
            logger.info(f"Saving extracted files to: {extract_path}")

            cmd = [
                self.BINWALK_PATH,
                "-e", "--run-as=root", firmware_path,
                "-v", "-C", extract_path
            ]

            result["raw_output"] = subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT,
                timeout=self.timeout,
                text=True
            )

            files_found = []

            for root, _, files in os.walk(extract_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path == firmware_path:  # Skip original firmware
                        continue
                    files_found.append(file_path)
                    ext = os.path.splitext(file)[1] or "no_extension"
                    result["file_types"][ext] = result["file_types"].get(ext, 0) + 1

            result["file_count"] = len(files_found)
            result["success"] = True
            result["extracted_path"] = extract_path

            logger.info(f"Extraction complete. Found {result['file_count']} files.")

        except FileNotFoundError:
            result["error"] = "Binwalk is not installed or executable path is invalid."
            logger.error(result["error"])
        except subprocess.CalledProcessError as e:
            result["raw_output"] = e.output
            result["error"] = "Binwalk failed with error code: {}".format(e.returncode)
            logger.error(result["error"], exc_info=True)
        except subprocess.TimeoutExpired:
            result["error"] = "Extraction timed out after {} seconds".format(self.timeout)
            if extract_path:
                shutil.rmtree(extract_path, ignore_errors=True)
            logger.error(result["error"])
        except Exception as e:
            result["error"] = str(e)
            if extract_path:
                shutil.rmtree(extract_path, ignore_errors=True)
            logger.error(f"Unexpected error: {e}", exc_info=True)

        return result

