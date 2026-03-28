"""
Tampering Simulation Module.

Implements the three tampering techniques described in the report (Step 3):
  1. Frame Deletion  — removing frames to hide specific events
  2. Video Cutting   — removing portions of the timeline
  3. Re-Encoding     — re-saving video with different compression

All operations use OpenCV only (no FFmpeg dependency required),
keeping the low-cost spirit of the report (~₹1000 framework).

Example from report:
    ffmpeg -i original.mp4 -ss 00:00:00 -t 00:00:30 cut_video.mp4
    (implemented here via OpenCV VideoWriter instead)
"""

import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import cv2
import numpy as np


# ---------------------------------------------------------------------------
# 1. Frame Deletion
# ---------------------------------------------------------------------------

def delete_frames(
    input_path: str,
    output_path: str,
    start_frame: int,
    end_frame: int,
) -> Dict:
    """
    Remove frames [start_frame, end_frame) from a video.

    Simulates hiding an event by deleting those frames, which changes the
    file hash and produces a frame count mismatch detectable in forensics.

    Args:
        input_path:   Path to the original video.
        output_path:  Path to write the tampered video.
        start_frame:  First frame index to delete (inclusive).
        end_frame:    Last frame index to delete (exclusive).

    Returns:
        {
            "technique": "frame_deletion",
            "original_frame_count": int,
            "deleted_frames":       int,
            "output_frame_count":   int,
            "output_path":          str,
            "processing_time_sec":  float,
        }
    """
    start_time = time.perf_counter()

    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {input_path}")

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    start_frame = max(0, start_frame)
    end_frame = min(total_frames, end_frame)
    deleted = end_frame - start_frame

    os.makedirs(Path(output_path).parent, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    frame_idx = 0
    written = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            if not (start_frame <= frame_idx < end_frame):
                writer.write(frame)
                written += 1
            frame_idx += 1
    finally:
        cap.release()
        writer.release()

    return {
        "technique": "frame_deletion",
        "original_frame_count": total_frames,
        "deleted_frames": deleted,
        "output_frame_count": written,
        "output_path": output_path,
        "processing_time_sec": round(time.perf_counter() - start_time, 3),
        "description": (
            f"Deleted frames {start_frame}–{end_frame - 1} "
            f"({deleted} frames, {deleted / fps:.2f}s of footage hidden)."
        ),
    }


# ---------------------------------------------------------------------------
# 2. Video Cutting (Timeline Removal)
# ---------------------------------------------------------------------------

def cut_video(
    input_path: str,
    output_path: str,
    cut_start_sec: float,
    cut_end_sec: float,
) -> Dict:
    """
    Remove a time range [cut_start_sec, cut_end_sec) from the video.

    Equivalent to the FFmpeg command from the report:
        ffmpeg -i original.mp4 -ss 00:00:00 -t 00:00:30 cut_video.mp4

    Implemented with OpenCV VideoWriter for no-FFmpeg dependency.

    Args:
        input_path:     Path to the original video.
        output_path:    Path to write the tampered video.
        cut_start_sec:  Start of the segment to remove (in seconds).
        cut_end_sec:    End of the segment to remove (in seconds).

    Returns:
        Dictionary with tampering details.
    """
    start_time = time.perf_counter()

    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {input_path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_sec = total_frames / fps

    cut_start_frame = int(cut_start_sec * fps)
    cut_end_frame = int(cut_end_sec * fps)
    cut_start_frame = max(0, cut_start_frame)
    cut_end_frame = min(total_frames, cut_end_frame)
    removed_frames = cut_end_frame - cut_start_frame

    os.makedirs(Path(output_path).parent, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    frame_idx = 0
    written = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            if not (cut_start_frame <= frame_idx < cut_end_frame):
                writer.write(frame)
                written += 1
            frame_idx += 1
    finally:
        cap.release()
        writer.release()

    return {
        "technique": "video_cutting",
        "original_duration_sec": round(duration_sec, 3),
        "cut_range_sec": [round(cut_start_sec, 3), round(cut_end_sec, 3)],
        "removed_frames": removed_frames,
        "removed_duration_sec": round(removed_frames / fps, 3),
        "output_frame_count": written,
        "output_duration_sec": round(written / fps, 3),
        "output_path": output_path,
        "processing_time_sec": round(time.perf_counter() - start_time, 3),
        "description": (
            f"Cut segment {cut_start_sec:.2f}s – {cut_end_sec:.2f}s "
            f"({removed_frames} frames / {removed_frames/fps:.2f}s removed)."
        ),
    }


# ---------------------------------------------------------------------------
# 3. Re-Encoding
# ---------------------------------------------------------------------------

def reencode_video(
    input_path: str,
    output_path: str,
    codec: str = "XVID",
    quality_factor: float = 0.5,
) -> Dict:
    """
    Re-encode the video with a different codec or compression level.

    This changes the file hash and encoder metadata — detectable by
    metadata inspection and hash comparison.

    Args:
        input_path:      Path to the original video.
        output_path:     Path to write the re-encoded video.
        codec:           FourCC codec string ('XVID', 'MJPG', 'mp4v').
        quality_factor:  JPEG quality factor 0.0–1.0 (for MJPG codec).

    Returns:
        Dictionary with re-encoding details.
    """
    start_time = time.perf_counter()

    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {input_path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

    # Resolve codec
    codec_map = {
        "XVID": "mp4",
        "MJPG": "avi",
        "mp4v": "mp4",
        "DIVX": "avi",
    }
    out_ext = codec_map.get(codec.upper(), "mp4")
    if not output_path.lower().endswith(f".{out_ext}"):
        output_path = str(Path(output_path).with_suffix(f".{out_ext}"))

    os.makedirs(Path(output_path).parent, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*codec.upper()[:4].ljust(4))
    writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    frame_idx = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            # Apply quality degradation for MJPG-style simulation
            if quality_factor < 1.0:
                encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), int(quality_factor * 100)]
                _, buffer = cv2.imencode(".jpg", frame, encode_param)
                frame = cv2.imdecode(buffer, cv2.IMREAD_COLOR)

            writer.write(frame)
            frame_idx += 1
    finally:
        cap.release()
        writer.release()

    import os as _os
    original_size = _os.path.getsize(input_path)
    output_size = _os.path.getsize(output_path) if _os.path.exists(output_path) else 0

    return {
        "technique": "re_encoding",
        "original_codec": _get_codec_str(input_path),
        "new_codec": codec.upper(),
        "frames_reencoded": frame_idx,
        "original_size_bytes": original_size,
        "output_size_bytes": output_size,
        "size_change_percent": round((output_size - original_size) / original_size * 100, 2) if original_size else 0,
        "output_path": output_path,
        "processing_time_sec": round(time.perf_counter() - start_time, 3),
        "description": (
            f"Re-encoded from {_get_codec_str(input_path)} to {codec.upper()}. "
            f"File hash and metadata will differ from original."
        ),
    }


def _get_codec_str(video_path: str) -> str:
    """Get codec FourCC string from a video file."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return "unknown"
    fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
    cap.release()
    return "".join([chr((fourcc_int >> (8 * i)) & 0xFF) for i in range(4)]).strip("\x00") or "unknown"
