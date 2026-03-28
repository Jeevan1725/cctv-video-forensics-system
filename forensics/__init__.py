"""
Forensics package — CCTV Video Forensic Analysis Tools.

Implements the methodology from:
  "Analog CCTV Video Forensics: Acquisition, Integrity Verification & Tamper Detection"
  Rajkushal Guduru & Jeevan, B.Tech CSE Cybersecurity, Amrita Vishwa Vidyapeetham

Modules:
    hashing           — SHA-256 cryptographic integrity verification
    frame_analysis    — Frame-level continuity, gap, and abrupt-change detection
    tampering_sim     — Tampering simulation (frame delete, cut, re-encode)
    metadata_inspector— Video metadata extraction and anomaly detection
    report_generator  — Structured forensic report generation
"""

from .hashing import calculate_sha256, compare_hashes, save_hash_record
from .frame_analysis import (
    extract_video_metadata,
    detect_frame_gaps,
    detect_frame_duplicates,
    detect_abrupt_changes,
    check_frame_continuity,
)
from .metadata_inspector import extract_metadata, detect_metadata_anomalies
from .report_generator import generate_forensic_report

__all__ = [
    "calculate_sha256",
    "compare_hashes",
    "save_hash_record",
    "extract_video_metadata",
    "detect_frame_gaps",
    "detect_frame_duplicates",
    "detect_abrupt_changes",
    "check_frame_continuity",
    "extract_metadata",
    "detect_metadata_anomalies",
    "generate_forensic_report",
]
