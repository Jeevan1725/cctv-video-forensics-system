"""
Frame-Level Forensic Analysis Module.

Implements frame continuity, gap detection, duplicate detection, and
abrupt change detection for CCTV video tamper analysis.

Corresponds to Step 4 (Forensic Analysis) of the report methodology:
  "Frame analysis helps detect missing frames, edited segments,
   and timeline inconsistencies"
"""

import time
from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np


# ---------------------------------------------------------------------------
# Metadata Extraction
# ---------------------------------------------------------------------------

def extract_video_metadata(video_path: str) -> Dict:
    """
    Extract core video metadata using OpenCV.

    Matches the report's Frame Analysis code example:
        cap = cv2.VideoCapture("cctv_video.mp4")
        frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        duration = frames / fps

    Returns:
        {
            "frame_count": int,
            "fps": float,
            "duration_sec": float,
            "width": int,
            "height": int,
            "resolution": str,       # e.g. "1920x1080"
            "fourcc": str,           # codec identifier
            "estimated_bitrate_kbps": float,
        }
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    try:
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        duration_sec = frame_count / fps if fps > 0 else 0.0

        # Codec FourCC code
        fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
        fourcc_str = "".join([chr((fourcc_int >> (8 * i)) & 0xFF) for i in range(4)]).strip("\x00")

        # Rough bitrate estimate from file size
        import os
        try:
            file_size_bytes = os.path.getsize(video_path)
            bitrate_kbps = (file_size_bytes * 8) / (duration_sec * 1000) if duration_sec > 0 else 0
        except Exception:
            bitrate_kbps = 0.0

        return {
            "frame_count": frame_count,
            "fps": round(fps, 4),
            "duration_sec": round(duration_sec, 4),
            "width": width,
            "height": height,
            "resolution": f"{width}x{height}",
            "fourcc": fourcc_str or "unknown",
            "estimated_bitrate_kbps": round(bitrate_kbps, 2),
        }
    finally:
        cap.release()


# ---------------------------------------------------------------------------
# Frame Gap Detection
# ---------------------------------------------------------------------------

def detect_frame_gaps(
    video_path: str,
    expected_fps: Optional[float] = None,
    tolerance_factor: float = 2.0,
    max_frames_to_scan: int = 5000,
) -> Dict:
    """
    Detect sudden jumps or gaps in frame timestamps.

    Reads actual timestamps (CAP_PROP_POS_MSEC) and compares the delta
    between consecutive frames against the expected inter-frame interval.
    Large deviations indicate frame deletion or timeline cuts.

    Args:
        video_path:          Path to video.
        expected_fps:        Expected FPS (auto-detected if None).
        tolerance_factor:    Flag gaps > tolerance_factor × expected_interval.
        max_frames_to_scan:  Cap scan for performance on long videos.

    Returns:
        {
            "gap_count": int,
            "gaps": [ {"frame_index": int, "gap_ms": float}, ... ],
            "expected_interval_ms": float,
            "verdict": str,          # "NO GAPS DETECTED" | "GAPS DETECTED"
            "frames_scanned": int,
        }
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    detected_fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    fps = expected_fps or detected_fps
    expected_interval_ms = 1000.0 / fps

    timestamps_ms = []
    frame_idx = 0

    try:
        while frame_idx < max_frames_to_scan:
            ret, _ = cap.read()
            if not ret:
                break
            ts = cap.get(cv2.CAP_PROP_POS_MSEC)
            timestamps_ms.append((frame_idx, ts))
            frame_idx += 1
    finally:
        cap.release()

    if len(timestamps_ms) < 2:
        return {
            "gap_count": 0,
            "gaps": [],
            "expected_interval_ms": round(expected_interval_ms, 2),
            "verdict": "INSUFFICIENT FRAMES",
            "frames_scanned": len(timestamps_ms),
        }

    gaps = []
    threshold_ms = expected_interval_ms * tolerance_factor

    for i in range(1, len(timestamps_ms)):
        idx, ts_curr = timestamps_ms[i]
        _, ts_prev = timestamps_ms[i - 1]
        delta = ts_curr - ts_prev

        if delta > threshold_ms:
            gaps.append({
                "frame_index": idx,
                "gap_ms": round(delta, 2),
                "expected_ms": round(expected_interval_ms, 2),
                "excess_ms": round(delta - expected_interval_ms, 2),
            })

    return {
        "gap_count": len(gaps),
        "gaps": gaps,
        "expected_interval_ms": round(expected_interval_ms, 2),
        "verdict": "GAPS DETECTED — Possible Frame Deletion" if gaps else "NO GAPS DETECTED",
        "frames_scanned": len(timestamps_ms),
    }


# ---------------------------------------------------------------------------
# Duplicate Frame Detection
# ---------------------------------------------------------------------------

def detect_frame_duplicates(
    video_path: str,
    similarity_threshold: float = 0.999,
    max_frames_to_scan: int = 3000,
    sample_step: int = 1,
) -> Dict:
    """
    Detect duplicate (repeated) frames — possible loop or freeze insertion.

    Computes normalised cross-correlation between consecutive grayscale frames.
    Score = 1.0 means pixel-perfect duplicate.

    Args:
        video_path:           Path to video.
        similarity_threshold: Score >= this → duplicate.
        max_frames_to_scan:   Cap scan count.
        sample_step:          Check every Nth frame pair.

    Returns:
        {
            "duplicate_count": int,
            "duplicates": [ {"frame_index": int, "similarity": float}, ... ],
            "verdict": str,
        }
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    duplicates = []
    prev_gray = None
    frame_idx = 0

    try:
        while frame_idx < max_frames_to_scan:
            ret, frame = cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            resized = cv2.resize(gray, (64, 64))  # Fast comparison

            if prev_gray is not None and frame_idx % sample_step == 0:
                # Normalized cross-correlation
                result = cv2.matchTemplate(
                    resized.astype(np.float32),
                    prev_gray.astype(np.float32),
                    cv2.TM_CCOEFF_NORMED,
                )
                score = float(result[0][0])
                if score >= similarity_threshold:
                    duplicates.append({
                        "frame_index": frame_idx,
                        "similarity": round(score, 6),
                    })

            prev_gray = resized
            frame_idx += 1
    finally:
        cap.release()

    return {
        "duplicate_count": len(duplicates),
        "duplicates": duplicates[:50],  # Cap output list
        "verdict": "DUPLICATE FRAMES FOUND — Possible Freeze/Loop" if duplicates else "NO DUPLICATES DETECTED",
        "frames_scanned": frame_idx,
    }


# ---------------------------------------------------------------------------
# Abrupt Change / Splice Detection
# ---------------------------------------------------------------------------

def detect_abrupt_changes(
    video_path: str,
    threshold: float = 0.35,
    max_frames_to_scan: int = 5000,
) -> Dict:
    """
    Detect sudden large pixel differences between consecutive frames.

    These indicate video splicing, cuts, or sudden scene insertions.

    Args:
        video_path:          Path to video.
        threshold:           Mean absolute difference (0-1) to flag as abrupt.
        max_frames_to_scan:  Cap scan count.

    Returns:
        {
            "change_count": int,
            "changes": [ {"frame_index": int, "diff_score": float}, ... ],
            "mean_diff": float,
            "verdict": str,
        }
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    changes = []
    prev_gray = None
    diffs = []
    frame_idx = 0

    try:
        while frame_idx < max_frames_to_scan:
            ret, frame = cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float32) / 255.0
            resized = cv2.resize(gray, (128, 128))

            if prev_gray is not None:
                diff = np.mean(np.abs(resized - prev_gray))
                diffs.append(diff)

                if diff > threshold:
                    changes.append({
                        "frame_index": frame_idx,
                        "diff_score": round(float(diff), 6),
                    })

            prev_gray = resized
            frame_idx += 1
    finally:
        cap.release()

    mean_diff = float(np.mean(diffs)) if diffs else 0.0

    return {
        "change_count": len(changes),
        "changes": changes[:50],
        "mean_diff": round(mean_diff, 6),
        "threshold_used": threshold,
        "verdict": "ABRUPT CHANGES DETECTED — Possible Splice/Cut" if changes else "NO ABRUPT CHANGES",
        "frames_scanned": frame_idx,
    }


# ---------------------------------------------------------------------------
# Frame Continuity Check (combined)
# ---------------------------------------------------------------------------

def check_frame_continuity(
    video_path: str,
    gap_tolerance_factor: float = 2.0,
    abrupt_threshold: float = 0.35,
    duplicate_similarity: float = 0.999,
    max_frames: int = 3000,
) -> Dict:
    """
    Run all frame-level continuity checks and return a combined summary.

    Args:
        video_path:            Path to video.
        gap_tolerance_factor:  Multiplier for timestamp gap detection.
        abrupt_threshold:      Pixel diff threshold for splice detection.
        duplicate_similarity:  Correlation threshold for duplicate frames.
        max_frames:            Max frames to process.

    Returns:
        Combined dictionary with metadata, gaps, duplicates, abrupt changes,
        and an overall verdict.
    """
    start = time.perf_counter()

    metadata = extract_video_metadata(video_path)
    gaps = detect_frame_gaps(video_path, tolerance_factor=gap_tolerance_factor, max_frames_to_scan=max_frames)
    duplicates = detect_frame_duplicates(video_path, similarity_threshold=duplicate_similarity, max_frames_to_scan=max_frames)
    changes = detect_abrupt_changes(video_path, threshold=abrupt_threshold, max_frames_to_scan=max_frames)

    # Overall verdict
    issues = []
    if gaps["gap_count"] > 0:
        issues.append(f"{gaps['gap_count']} frame gap(s)")
    if duplicates["duplicate_count"] > 0:
        issues.append(f"{duplicates['duplicate_count']} duplicate frame(s)")
    if changes["change_count"] > 0:
        issues.append(f"{changes['change_count']} abrupt change(s)")

    overall_verdict = "TAMPERING INDICATORS FOUND: " + "; ".join(issues) if issues else "VIDEO APPEARS INTACT"

    return {
        "analysis_time_sec": round(time.perf_counter() - start, 3),
        "metadata": metadata,
        "frame_gaps": gaps,
        "duplicate_frames": duplicates,
        "abrupt_changes": changes,
        "issues_found": issues,
        "overall_verdict": overall_verdict,
    }
