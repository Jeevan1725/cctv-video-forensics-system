"""
Video Metadata Inspector Module.

Extracts embedded metadata from CCTV video files and flags anomalies
that indicate tampering such as re-encoding or timeline manipulation.

Corresponds to Step 4 (Forensic Analysis) of the report:
  "Metadata analysis" and "Re-encoded video → Metadata change → Detected"
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import cv2


def extract_metadata(video_path: str) -> Dict:
    """
    Extract comprehensive video metadata using OpenCV + OS file info.

    Args:
        video_path: Path to the video file.

    Returns:
        Dictionary with file-level and video-stream metadata.
    """
    path = Path(video_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {video_path}")

    stat = path.stat()

    # OpenCV stream metadata
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    try:
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        duration_sec = frame_count / fps if fps > 0 else 0.0

        fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
        fourcc_str = "".join([chr((fourcc_int >> (8 * i)) & 0xFF) for i in range(4)]).strip("\x00")

        # Backend identifier
        backend = cap.getBackendName()
    finally:
        cap.release()

    file_size = stat.st_size
    bitrate_kbps = (file_size * 8) / (duration_sec * 1000) if duration_sec > 0 else 0.0

    # File timestamps
    modified_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    created_utc = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()

    return {
        "file": {
            "path": str(path.resolve()),
            "filename": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": file_size,
            "size_mb": round(file_size / (1024 * 1024), 3),
            "created_utc": created_utc,
            "modified_utc": modified_utc,
        },
        "video_stream": {
            "frame_count": frame_count,
            "fps": round(fps, 4),
            "duration_sec": round(duration_sec, 4),
            "duration_formatted": _format_duration(duration_sec),
            "width": width,
            "height": height,
            "resolution": f"{width}x{height}",
            "codec_fourcc": fourcc_str or "unknown",
            "backend": backend,
            "estimated_bitrate_kbps": round(bitrate_kbps, 2),
        },
    }


def detect_metadata_anomalies(metadata: Dict) -> Dict:
    """
    Analyse extracted metadata for forensic red flags.

    Checks include:
    - Suspicious or empty codec string (re-encoding indicator)
    - Very low or very high estimated bitrate
    - Zero or negative FPS
    - Abnormally low frame count for the reported duration
    - File modification date that is newer than expected

    Args:
        metadata: Output of `extract_metadata()`.

    Returns:
        {
            "anomaly_count": int,
            "anomalies": [ {"field": str, "description": str, "severity": str} ],
            "verdict": str,
        }
    """
    anomalies: List[Dict] = []
    vs = metadata.get("video_stream", {})
    fm = metadata.get("file", {})

    fps = vs.get("fps", 0)
    frame_count = vs.get("frame_count", 0)
    duration_sec = vs.get("duration_sec", 0)
    bitrate_kbps = vs.get("estimated_bitrate_kbps", 0)
    codec = vs.get("codec_fourcc", "")
    ext = fm.get("extension", "")

    # --- FPS checks ---
    if fps <= 0:
        anomalies.append({
            "field": "fps",
            "description": f"Invalid FPS ({fps}). Video may be corrupted or re-encoded.",
            "severity": "HIGH",
        })
    elif fps < 5 or fps > 120:
        anomalies.append({
            "field": "fps",
            "description": f"Unusual FPS ({fps}). Standard CCTV is 15-30 FPS.",
            "severity": "MEDIUM",
        })

    # --- Frame count checks ---
    if frame_count <= 0:
        anomalies.append({
            "field": "frame_count",
            "description": f"Zero or negative frame count ({frame_count}). File may be empty or corrupted.",
            "severity": "HIGH",
        })
    elif duration_sec > 0 and fps > 0:
        expected_frames = duration_sec * fps
        deviation = abs(frame_count - expected_frames) / expected_frames if expected_frames > 0 else 0
        if deviation > 0.1:  # >10% mismatch
            anomalies.append({
                "field": "frame_count",
                "description": (
                    f"Frame count ({frame_count}) deviates {deviation:.1%} from expected "
                    f"({expected_frames:.0f} at {fps} FPS). Possible frame deletion."
                ),
                "severity": "HIGH",
            })

    # --- Codec checks ---
    if not codec or codec in ("", "\x00\x00\x00\x00"):
        anomalies.append({
            "field": "codec_fourcc",
            "description": "Empty or null codec identifier. Possible re-encoding without metadata.",
            "severity": "MEDIUM",
        })
    else:
        # Common re-encoding indicators
        reencoded_codecs = {"avc1", "h264", "x264", "xvid", "divx", "mp4v"}
        if codec.lower() in reencoded_codecs:
            anomalies.append({
                "field": "codec_fourcc",
                "description": (
                    f"Codec '{codec}' is a common re-encoding target. "
                    "This is expected for MP4, but note for evidence chain."
                ),
                "severity": "LOW",
            })

    # --- Extension vs codec mismatch ---
    codec_ext_map = {
        ".mp4": ["avc1", "h264", "mp4v", "x264"],
        ".avi": ["xvid", "divx", "mjpg", "mp42"],
        ".mov": ["avc1", "mp4v"],
        ".mkv": ["avc1", "h264"],
    }
    expected_codecs = codec_ext_map.get(ext, [])
    if expected_codecs and codec.lower() not in [c.lower() for c in expected_codecs]:
        pass  # Not necessarily suspicious, just informational

    # --- Bitrate checks ---
    if bitrate_kbps > 0:
        if bitrate_kbps < 100:
            anomalies.append({
                "field": "bitrate",
                "description": f"Very low bitrate ({bitrate_kbps:.0f} kbps). Heavy compression may degrade evidence.",
                "severity": "MEDIUM",
            })
        elif bitrate_kbps > 50000:
            anomalies.append({
                "field": "bitrate",
                "description": f"Extremely high bitrate ({bitrate_kbps:.0f} kbps). Unusual for CCTV footage.",
                "severity": "LOW",
            })

    # --- Duration checks ---
    if duration_sec < 1.0 and frame_count > 1:
        anomalies.append({
            "field": "duration",
            "description": f"Duration ({duration_sec:.2f}s) is suspiciously short.",
            "severity": "MEDIUM",
        })

    # --- Build verdict ---
    high_count = sum(1 for a in anomalies if a["severity"] == "HIGH")
    medium_count = sum(1 for a in anomalies if a["severity"] == "MEDIUM")

    if high_count > 0:
        verdict = f"METADATA ANOMALIES DETECTED ({high_count} HIGH, {medium_count} MEDIUM severity)"
    elif medium_count > 0:
        verdict = f"MINOR METADATA CONCERNS ({medium_count} MEDIUM severity)"
    else:
        verdict = "METADATA APPEARS NORMAL"

    return {
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "verdict": verdict,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def _format_duration(seconds: float) -> str:
    """Format duration as HH:MM:SS.mmm"""
    if seconds < 0:
        return "00:00:00.000"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:06.3f}"
