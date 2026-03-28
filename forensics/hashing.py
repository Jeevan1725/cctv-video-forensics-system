"""
Cryptographic Integrity Verification Module.

Implements SHA-256 hashing for CCTV video evidence preservation,
as described in the Cyber Forensics report methodology (Step 2).

Usage:
    hash_val = calculate_sha256("cctv_video.mp4")
    record   = save_hash_record("cctv_video.mp4", hash_val, "outputs/")
    match    = compare_hashes(hash_val, other_hash)
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


def calculate_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute SHA-256 cryptographic hash of a video file.

    Reads the file in chunks to handle large video files efficiently.

    Args:
        file_path:  Path to the video file.
        chunk_size: Read chunk size in bytes (default 64 KB).

    Returns:
        Lowercase hex-encoded SHA-256 digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError:           If the file cannot be read.

    Example (from report):
        >>> hash_value = calculate_sha256("cctv_video.mp4")
        >>> print(hash_value)
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Video file not found: {file_path}")

    sha256 = hashlib.sha256()
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_md5(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute MD5 hash of a video file (secondary verification).

    Note: MD5 is NOT collision-resistant — use SHA-256 for evidence.
    MD5 is included here for legacy compatibility checks.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Video file not found: {file_path}")

    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)

    return md5.hexdigest()


def compare_hashes(hash1: str, hash2: str) -> Dict:
    """
    Compare two hash values to determine if a video has been tampered.

    Args:
        hash1: Reference hash (original video).
        hash2: Evidence hash (video under examination).

    Returns:
        Dictionary with comparison result:
        {
            "match": bool,
            "verdict": str,       # "INTACT" or "TAMPERED"
            "reference_hash": str,
            "evidence_hash":  str,
        }
    """
    # Use constant-time comparison to avoid timing attacks
    import hmac
    match = hmac.compare_digest(hash1.lower(), hash2.lower())

    return {
        "match": match,
        "verdict": "INTACT" if match else "TAMPERED",
        "reference_hash": hash1.lower(),
        "evidence_hash": hash2.lower(),
    }


def save_hash_record(
    file_path: str,
    hash_value: str,
    output_dir: str = "outputs",
    case_id: Optional[str] = None,
    analyst: Optional[str] = None,
) -> Dict:
    """
    Persist hash record to JSON — establishes chain of custody.

    Args:
        file_path:  Path to the video file that was hashed.
        hash_value: SHA-256 hash of the file.
        output_dir: Directory to save the hash record JSON.
        case_id:    Optional forensic case identifier.
        analyst:    Optional analyst name.

    Returns:
        Dictionary containing the full hash record.
    """
    os.makedirs(output_dir, exist_ok=True)

    file_path = Path(file_path)
    stat = file_path.stat() if file_path.exists() else None

    record = {
        "schema_version": "1.0",
        "type": "sha256_hash_record",
        "case_id": case_id or f"CASE-{int(time.time())}",
        "analyst": analyst or "System",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "filename": file_path.name,
            "file_path": str(file_path.resolve()),
            "file_size_bytes": stat.st_size if stat else 0,
            "sha256": hash_value,
            "md5": calculate_md5(str(file_path)) if file_path.exists() else None,
        },
        "algorithm": "SHA-256",
        "notes": "Hash generated per forensic evidence preservation protocol.",
    }

    record_file = Path(output_dir) / f"hash_record_{file_path.stem}_{int(time.time())}.json"
    with open(record_file, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    record["_saved_to"] = str(record_file)
    return record


def verify_file_integrity(file_path: str, reference_hash: str) -> Dict:
    """
    Full integrity check against a stored reference hash.

    Args:
        file_path:       Path to the video file to verify.
        reference_hash:  Known-good SHA-256 hash of the original.

    Returns:
        Detailed verification result dictionary.
    """
    start = time.perf_counter()
    current_hash = calculate_sha256(file_path)
    elapsed = time.perf_counter() - start

    comparison = compare_hashes(reference_hash, current_hash)

    return {
        **comparison,
        "file_path": file_path,
        "file_size_bytes": os.path.getsize(file_path),
        "hash_computation_sec": round(elapsed, 4),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
