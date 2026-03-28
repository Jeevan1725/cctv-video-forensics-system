"""
Forensic Report Generator Module.

Produces structured forensic analysis reports in JSON and plain-text formats.

Corresponds to Steps 2 and 5 of the report methodology:
  Step 2 — Evidence Preservation (chain of custody)
  Step 5 — Result Generation (forensic report output)

Report sections follow the structure from the report's Preliminary Results:
  Test Case | Detection Method | Result
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_forensic_report(
    video_path: str,
    case_id: Optional[str] = None,
    analyst: Optional[str] = None,
    hash_result: Optional[Dict] = None,
    frame_analysis: Optional[Dict] = None,
    ai_result: Optional[Dict] = None,
    tampering_sim: Optional[Dict] = None,
    output_dir: str = "outputs",
    save_json: bool = True,
    save_text: bool = True,
) -> Dict:
    """
    Generate a complete forensic analysis report.

    Args:
        video_path:    Path to the video file being analysed.
        case_id:       Forensic case identifier.
        analyst:       Name of the analyst.
        hash_result:   Output of hashing.verify_file_integrity() or compare_hashes().
        frame_analysis:Output of frame_analysis.check_frame_continuity().
        ai_result:     Output of the anomaly detection API (/analyze-video response).
        tampering_sim: Output of tampering_simulator functions.
        output_dir:    Directory to save report files.
        save_json:     Save machine-readable JSON report.
        save_text:     Save human-readable text report.

    Returns:
        Dictionary containing the complete report and file paths.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp_utc = datetime.now(timezone.utc).isoformat()
    case_id = case_id or f"CF-{int(time.time())}"
    analyst = analyst or "Automated System"
    video_name = Path(video_path).name

    # ---- Build report sections ----
    report = {
        "report_metadata": {
            "title": "CCTV Video Forensic Analysis Report",
            "subtitle": "Acquisition, Integrity Verification & Tamper Detection",
            "project": "Analog CCTV Video Forensics",
            "institution": "Amrita Vishwa Vidyapeetham — B.Tech CSE Cybersecurity",
            "course": "Cyber Forensics",
            "case_id": case_id,
            "analyst": analyst,
            "generated_at_utc": timestamp_utc,
            "report_version": "1.0",
        },
        "evidence_details": {
            "filename": video_name,
            "full_path": str(Path(video_path).resolve()),
            "acquired_at_utc": timestamp_utc,
        },
        "step1_acquisition": {
            "status": "COMPLETE",
            "description": "CCTV video footage acquired for forensic analysis.",
            "source": video_name,
        },
        "step2_integrity_verification": _build_hash_section(hash_result),
        "step3_frame_analysis": _build_frame_section(frame_analysis),
        "step4_ai_detection": _build_ai_section(ai_result),
        "step5_tampering_simulation": _build_tampering_section(tampering_sim),
        "overall_verdict": _compute_overall_verdict(hash_result, frame_analysis, ai_result),
        "preliminary_results_table": _build_results_table(hash_result, frame_analysis, ai_result),
    }

    # ---- Save files ----
    saved_files = []

    if save_json:
        json_path = Path(output_dir) / f"forensic_report_{case_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        saved_files.append(str(json_path))

    if save_text:
        text_path = Path(output_dir) / f"forensic_report_{case_id}.txt"
        text_content = _render_text_report(report)
        with open(text_path, "w", encoding="utf-8") as f:
            f.write(text_content)
        saved_files.append(str(text_path))

    report["_saved_files"] = saved_files
    return report


# ---------------------------------------------------------------------------
# Section Builders
# ---------------------------------------------------------------------------

def _build_hash_section(hash_result: Optional[Dict]) -> Dict:
    if not hash_result:
        return {"status": "NOT PERFORMED", "description": "Hash verification was not run."}

    match = hash_result.get("match")

    # match=None means hash was recorded but no reference was provided for comparison
    if match is None:
        description = "SHA-256 hash recorded for chain of custody. No reference hash provided for comparison."
        verdict = hash_result.get("verdict", "HASH RECORDED")
    elif match is True:
        description = "Hash values match. Video file is INTACT."
        verdict = "INTACT"
    else:
        description = "Hash values DO NOT match. Video file has been MODIFIED."
        verdict = "TAMPERED"

    return {
        "status": "COMPLETE",
        "method": "SHA-256 Cryptographic Hashing",
        "verdict": verdict,
        "reference_hash": hash_result.get("reference_hash", "N/A"),
        "evidence_hash": hash_result.get("evidence_hash", "N/A"),
        "match": match,
        "description": description,
    }


def _build_frame_section(frame_analysis: Optional[Dict]) -> Dict:
    if not frame_analysis:
        return {"status": "NOT PERFORMED", "description": "Frame analysis was not run."}

    meta = frame_analysis.get("metadata", {})
    gaps = frame_analysis.get("frame_gaps", {})
    dups = frame_analysis.get("duplicate_frames", {})
    changes = frame_analysis.get("abrupt_changes", {})
    issues = frame_analysis.get("issues_found", [])

    return {
        "status": "COMPLETE",
        "method": "Frame Count, FPS, Duration & Continuity Analysis",
        "video_metadata": {
            "frame_count":    meta.get("frame_count"),
            "fps":            meta.get("fps"),
            "duration_sec":   meta.get("duration_sec"),
            "resolution":     meta.get("resolution"),
            "codec":          meta.get("fourcc"),
        },
        "gap_detection": {
            "verdict":    gaps.get("verdict"),
            "gaps_found": gaps.get("gap_count", 0),
        },
        "duplicate_detection": {
            "verdict":          dups.get("verdict"),
            "duplicates_found": dups.get("duplicate_count", 0),
        },
        "abrupt_change_detection": {
            "verdict":       changes.get("verdict"),
            "changes_found": changes.get("change_count", 0),
        },
        "overall_verdict": frame_analysis.get("overall_verdict", "UNKNOWN"),
        "issues": issues,
    }


def _build_ai_section(ai_result: Optional[Dict]) -> Dict:
    if not ai_result:
        return {"status": "NOT PERFORMED", "description": "AI anomaly detection was not run."}
    return {
        "status": "COMPLETE",
        "method": "Convolutional Autoencoder — Reconstruction Error Analysis",
        "model": "ConvolutionalAutoencoder (256-dim latent, trained on UCSD Ped2)",
        "frame_count":    ai_result.get("frame_count"),
        "anomaly_count":  ai_result.get("anomaly_count"),
        "anomaly_rate":   ai_result.get("anomaly_rate"),
        "threshold":      ai_result.get("model_info", {}).get("threshold"),
        "device":         ai_result.get("model_info", {}).get("device"),
        "processing_sec": ai_result.get("processing_time"),
        "_scores":        ai_result.get("anomaly_scores", []),
        "_flags":         ai_result.get("anomaly_flags", []),
        "verdict": (
            f"AI detected {ai_result.get('anomaly_count', 0)} anomalous frames "
            f"({ai_result.get('anomaly_rate', 0) * 100:.1f}% anomaly rate)."
        ),
    }


def _build_tampering_section(tampering_sim: Optional[Dict]) -> Dict:
    if not tampering_sim:
        return {"status": "NOT PERFORMED", "description": "Tampering simulation was not run."}
    return {
        "status": "COMPLETE",
        "technique": tampering_sim.get("technique", "unknown"),
        "description": tampering_sim.get("description", ""),
        "details": tampering_sim,
    }


def _compute_overall_verdict(
    hash_result: Optional[Dict],
    frame_analysis: Optional[Dict],
    ai_result: Optional[Dict],
) -> Dict:
    indicators = []
    confidence = "LOW"

    # Only flag hash mismatch when match is explicitly False (not None/unknown)
    if hash_result and hash_result.get("match") is False:
        indicators.append("Hash mismatch — file was modified")
        confidence = "HIGH"

    if frame_analysis:
        issues = frame_analysis.get("issues_found", [])
        if issues:
            indicators.extend(issues)
            if confidence != "HIGH":
                confidence = "MEDIUM"

    if ai_result:
        rate = ai_result.get("anomaly_rate", 0)
        if rate > 0.30:
            indicators.append(f"High AI anomaly rate ({rate * 100:.1f}%)")
            if confidence == "LOW":
                confidence = "MEDIUM"

    if indicators:
        verdict = "⚠️  TAMPERING LIKELY"
        summary = "Forensic analysis found the following indicators of tampering: " + "; ".join(indicators) + "."
    else:
        verdict = "✅  VIDEO APPEARS INTACT"
        summary = "No significant tampering indicators were found."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "indicators": indicators,
        "summary": summary,
    }


def _build_results_table(
    hash_result: Optional[Dict],
    frame_analysis: Optional[Dict],
    ai_result: Optional[Dict],
) -> List[Dict]:
    """Build the results table matching the report format."""
    rows = []

    if hash_result is not None:
        match = hash_result.get("match")
        if match is True:
            rows.append({
                "test_case": "Original video",
                "detection_method": "Hash verification (SHA-256)",
                "result": "Valid — Hashes Match",
            })
        elif match is False:
            rows.append({
                "test_case": "Modified video",
                "detection_method": "Hash verification (SHA-256)",
                "result": "Detected — Hash Mismatch",
            })
        else:
            rows.append({
                "test_case": "Evidence video",
                "detection_method": "Hash verification (SHA-256)",
                "result": "Hash Recorded (no reference provided)",
            })

    if frame_analysis:
        gaps = frame_analysis.get("frame_gaps", {})
        dups = frame_analysis.get("duplicate_frames", {})
        changes = frame_analysis.get("abrupt_changes", {})

        if gaps.get("gap_count", 0) > 0:
            rows.append({
                "test_case": "Frame deleted video",
                "detection_method": "Frame count mismatch",
                "result": f"Detected — {gaps['gap_count']} gap(s) found",
            })

        if changes.get("change_count", 0) > 0:
            rows.append({
                "test_case": "Edited video",
                "detection_method": "Abrupt scene change detection",
                "result": f"Detected — {changes['change_count']} abrupt change(s)",
            })

        if dups.get("duplicate_count", 0) > 0:
            rows.append({
                "test_case": "Loop-inserted video",
                "detection_method": "Duplicate frame detection",
                "result": f"Detected — {dups['duplicate_count']} duplicate(s)",
            })

        if not rows or all(r.get("detection_method") == "Hash verification (SHA-256)" for r in rows):
            fa_verdict = frame_analysis.get("overall_verdict", "")
            if "INTACT" in fa_verdict:
                rows.append({
                    "test_case": "Original video",
                    "detection_method": "Frame continuity analysis",
                    "result": "Valid — No frame anomalies",
                })

    if ai_result and ai_result.get("anomaly_count", 0) > 0:
        rows.append({
            "test_case": "Video with anomalous content",
            "detection_method": "AI reconstruction error (autoencoder)",
            "result": f"Detected — {ai_result['anomaly_count']} anomalous frame(s)",
        })
    elif ai_result and ai_result.get("anomaly_count", 0) == 0:
        rows.append({
            "test_case": "Original video",
            "detection_method": "AI reconstruction error (autoencoder)",
            "result": "Valid — No anomalies detected",
        })

    if not rows:
        rows.append({
            "test_case": "Video under examination",
            "detection_method": "All methods",
            "result": "No tampering detected",
        })

    return rows


# ---------------------------------------------------------------------------
# Text Report Renderer
# ---------------------------------------------------------------------------

def _render_text_report(report: Dict) -> str:
    lines = []
    meta = report.get("report_metadata", {})
    verdict = report.get("overall_verdict", {})
    table = report.get("preliminary_results_table", [])

    lines.append("=" * 70)
    lines.append(meta.get("title", "FORENSIC REPORT").upper())
    lines.append(meta.get("subtitle", ""))
    lines.append("=" * 70)
    lines.append(f"Case ID    : {meta.get('case_id')}")
    lines.append(f"Analyst    : {meta.get('analyst')}")
    lines.append(f"Generated  : {meta.get('generated_at_utc')}")
    lines.append(f"Project    : {meta.get('project')}")
    lines.append(f"Institution: {meta.get('institution')}")
    lines.append(f"Course     : {meta.get('course')}")
    lines.append("")

    # Evidence
    ev = report.get("evidence_details", {})
    lines.append("EVIDENCE DETAILS")
    lines.append("-" * 40)
    lines.append(f"File   : {ev.get('filename')}")
    lines.append(f"Path   : {ev.get('full_path')}")
    lines.append("")

    # Step 2 — Hash
    h = report.get("step2_integrity_verification", {})
    lines.append("STEP 2: INTEGRITY VERIFICATION (SHA-256 Hashing)")
    lines.append("-" * 50)
    lines.append(f"Status  : {h.get('status')}")
    lines.append(f"Verdict : {h.get('verdict', 'N/A')}")
    if h.get("reference_hash") and h.get("reference_hash") != "N/A":
        lines.append(f"Ref Hash: {h.get('reference_hash')}")
        lines.append(f"Evi Hash: {h.get('evidence_hash')}")
    elif h.get("evidence_hash") and h.get("evidence_hash") != "N/A":
        lines.append(f"Hash    : {h.get('evidence_hash')}")
    lines.append(f"Note    : {h.get('description', '')}")
    lines.append("")

    # Step 3 — Frame Analysis
    fa = report.get("step3_frame_analysis", {})
    lines.append("STEP 3: FRAME ANALYSIS")
    lines.append("-" * 50)
    lines.append(f"Status  : {fa.get('status')}")
    vm = fa.get("video_metadata", {})
    if vm:
        lines.append(f"Frames  : {vm.get('frame_count')}  FPS: {vm.get('fps')}  Duration: {vm.get('duration_sec')}s")
        lines.append(f"Res     : {vm.get('resolution')}  Codec: {vm.get('codec')}")
    lines.append(f"Gap Det : {fa.get('gap_detection', {}).get('verdict', 'N/A')}")
    lines.append(f"Dup Det : {fa.get('duplicate_detection', {}).get('verdict', 'N/A')}")
    lines.append(f"Change  : {fa.get('abrupt_change_detection', {}).get('verdict', 'N/A')}")
    lines.append(f"Verdict : {fa.get('overall_verdict', 'N/A')}")
    lines.append("")

    # Step 4 — AI
    ai = report.get("step4_ai_detection", {})
    lines.append("STEP 4: AI-BASED TAMPERING DETECTION")
    lines.append("-" * 50)
    lines.append(f"Status   : {ai.get('status')}")
    if ai.get("frame_count"):
        lines.append(f"Frames   : {ai.get('frame_count')}  Anomalies: {ai.get('anomaly_count')}  Rate: {ai.get('anomaly_rate', 0) * 100:.1f}%")
    lines.append(f"Verdict  : {ai.get('verdict', 'N/A')}")
    lines.append("")

    # Preliminary Results Table
    lines.append("PRELIMINARY RESULTS TABLE")
    lines.append("-" * 70)
    lines.append(f"{'Test Case':<30} {'Detection Method':<30} {'Result'}")
    lines.append("-" * 70)
    for row in table:
        tc = row.get("test_case", "")[:28]
        dm = row.get("detection_method", "")[:28]
        res = row.get("result", "")
        lines.append(f"{tc:<30} {dm:<30} {res}")
    lines.append("")

    # Overall Verdict
    lines.append("=" * 70)
    lines.append("OVERALL VERDICT")
    lines.append("=" * 70)
    lines.append(f"  {verdict.get('verdict', 'UNKNOWN')}")
    lines.append(f"  Confidence: {verdict.get('confidence', 'LOW')}")
    lines.append(f"  {verdict.get('summary', '')}")
    lines.append("")
    lines.append("This report was generated automatically by the CCTV Forensics System.")
    lines.append("For legal proceedings, results must be verified by a certified forensic analyst.")
    lines.append("=" * 70)

    return "\n".join(lines)
