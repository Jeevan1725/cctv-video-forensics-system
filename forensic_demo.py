"""
Demo script: Run complete 5-step forensic analysis via the API.
"""
import requests
import json

video_path = "test_videos/realistic_anomaly.mp4"
base = "http://127.0.0.1:8000"

print("=" * 60)
print("CCTV VIDEO FORENSICS - COMPLETE WORKFLOW DEMO")
print("Cyber Forensics | B.Tech CSE | Amrita Vishwa Vidyapeetham")
print("=" * 60)

# Check API health
print("\n[API Health Check]")
r = requests.get(f"{base}/health", timeout=5)
health = r.json()
print(f"Status: {health.get('status')}")
print(f"Model Loaded: {health.get('model_loaded')}")
print(f"Device: {health.get('device')}")
print(f"Version: {health.get('version')}")

# STEP 2: Generate SHA-256 Hash
print("\n" + "=" * 60)
print("STEP 2: EVIDENCE PRESERVATION — SHA-256 HASHING")
print("=" * 60)
with open(video_path, "rb") as f:
    r = requests.post(
        f"{base}/generate-hash",
        files={"file": ("realistic_anomaly.mp4", f, "video/mp4")},
        timeout=30
    )
hash_data = r.json()
print(f"Case ID    : {hash_data.get('case_id')}")
print(f"Filename   : {hash_data.get('filename')}")
print(f"File Size  : {hash_data.get('file_size_bytes')} bytes")
print(f"SHA-256    : {hash_data.get('sha256')}")
print(f"Hash saved : {hash_data.get('record_saved')}")

sha256_hash = hash_data.get("sha256")

# STEP 2b: Verify integrity (same video should match)
print("\n[Integrity Check - Same Video]")
with open(video_path, "rb") as f:
    r = requests.post(
        f"{base}/verify-integrity",
        params={"reference_hash": sha256_hash},
        files={"file": ("realistic_anomaly.mp4", f, "video/mp4")},
        timeout=30
    )
verify = r.json()
print(f"Match   : {verify.get('match')}")
print(f"Verdict : {verify.get('verdict')}")

# STEP 3: Simulate Tampering — Frame Deletion
print("\n" + "=" * 60)
print("STEP 3: TAMPERING SIMULATION — FRAME DELETION")
print("=" * 60)
with open(video_path, "rb") as f:
    r = requests.post(
        f"{base}/simulate-tampering",
        params={"technique": "frame_deletion", "start_param": 10, "end_param": 60},
        files={"file": ("realistic_anomaly.mp4", f, "video/mp4")},
        timeout=60
    )
sim = r.json()
sim_result = sim.get("simulation_result", {})
print(f"Technique        : {sim_result.get('technique')}")
print(f"Original Frames  : {sim_result.get('original_frame_count')}")
print(f"Deleted Frames   : {sim_result.get('deleted_frames')}")
print(f"Output Frames    : {sim_result.get('output_frame_count')}")
print(f"Original Hash    : {sim.get('original_hash', '')[:32]}...")
print(f"Tampered Hash    : {sim.get('tampered_hash', '')[:32]}...")
hash_comp = sim.get("hash_comparison", {})
print(f"Hash Match       : {hash_comp.get('match')}")
print(f"Verdict          : {hash_comp.get('verdict')}")
print(f"Forensic Note    : {sim.get('forensic_note')}")

# STEP 3b: Simulate Tampering — Video Cutting
print("\n[Tampering Simulation — Video Cutting]")
with open(video_path, "rb") as f:
    r = requests.post(
        f"{base}/simulate-tampering",
        params={"technique": "video_cutting", "start_param": 1.0, "end_param": 3.0},
        files={"file": ("realistic_anomaly.mp4", f, "video/mp4")},
        timeout=60
    )
sim2 = r.json()
sim2_result = sim2.get("simulation_result", {})
print(f"Original Duration: {sim2_result.get('original_duration_sec')}s")
print(f"Removed Duration : {sim2_result.get('removed_duration_sec')}s")
print(f"Output Duration  : {sim2_result.get('output_duration_sec')}s")
print(f"Hash Match       : {sim2.get('hash_comparison', {}).get('match')}")
print(f"Verdict          : {sim2.get('hash_comparison', {}).get('verdict')}")

# STEPS 4+5: Full Forensic Analysis
print("\n" + "=" * 60)
print("STEPS 4+5: FORENSIC ANALYSIS + REPORT GENERATION")
print("=" * 60)
with open(video_path, "rb") as f:
    r = requests.post(
        f"{base}/forensic-analyze",
        params={"case_id": "CF-DEMO001", "analyst": "Jeevan"},
        files={"file": ("realistic_anomaly.mp4", f, "video/mp4")},
        timeout=180
    )
report = r.json()

meta = report.get("report_metadata", {})
print(f"Case ID    : {meta.get('case_id')}")
print(f"Analyst    : {meta.get('analyst')}")
print(f"Generated  : {meta.get('generated_at_utc')}")

print("\n--- Step 2: Integrity Verification ---")
h = report.get("step2_integrity_verification", {})
print(f"Status  : {h.get('status')}")
print(f"Verdict : {h.get('verdict')}")

print("\n--- Step 3: Frame Analysis ---")
fa = report.get("step3_frame_analysis", {})
vm = fa.get("video_metadata", {})
print(f"Frames   : {vm.get('frame_count')}")
print(f"FPS      : {vm.get('fps')}")
print(f"Duration : {vm.get('duration_sec')}s")
print(f"Res      : {vm.get('resolution')}")
print(f"Codec    : {vm.get('codec')}")
print(f"Gap Det  : {fa.get('gap_detection', {}).get('verdict')}")
print(f"Dup Det  : {fa.get('duplicate_detection', {}).get('verdict')}")
print(f"Change   : {fa.get('abrupt_change_detection', {}).get('verdict')}")
print(f"FA Verdict: {fa.get('overall_verdict')}")

print("\n--- Step 4: AI Detection ---")
ai = report.get("step4_ai_detection", {})
print(f"Status   : {ai.get('status')}")
print(f"Frames   : {ai.get('frame_count')}")
print(f"Anomalies: {ai.get('anomaly_count')}")
rate = ai.get("anomaly_rate", 0)
print(f"Rate     : {rate * 100:.1f}%")
print(f"Threshold: {ai.get('threshold')}")
print(f"Verdict  : {ai.get('verdict')}")

print("\n--- PRELIMINARY RESULTS TABLE ---")
table = report.get("preliminary_results_table", [])
print(f"{'Test Case':<30} {'Detection Method':<32} Result")
print("-" * 80)
for row in table:
    tc = row.get("test_case", "")[:28]
    dm = row.get("detection_method", "")[:30]
    res = row.get("result", "")
    print(f"{tc:<30} {dm:<32} {res}")

print("\n--- OVERALL VERDICT ---")
verdict = report.get("overall_verdict", {})
print(f"VERDICT    : {verdict.get('verdict')}")
print(f"Confidence : {verdict.get('confidence')}")
print(f"Summary    : {verdict.get('summary')}")
print(f"Indicators : {verdict.get('indicators')}")

saved = report.get("_saved_files", [])
print(f"\nReport files saved:")
for f_path in saved:
    print(f"  -> {f_path}")

print("\n" + "=" * 60)
print("FORENSIC ANALYSIS COMPLETE")
print("=" * 60)
