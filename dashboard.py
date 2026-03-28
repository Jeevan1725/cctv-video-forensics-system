"""
CCTV Video Forensics Dashboard
Acquisition, Integrity Verification & Tamper Detection

Implements the complete forensic workflow from the Cyber Forensics report:
  Step 1 — Evidence Acquisition
  Step 2 — Integrity Verification (SHA-256 Hashing)
  Step 3 — Tampering Simulation
  Step 4 — Forensic Analysis (Frame · Metadata · AI)
  Step 5 — Report Generation

Authors: Rajkushal Guduru & Jeevan
Course : Cyber Forensics — B.Tech CSE Cybersecurity
         Amrita Vishwa Vidyapeetham, Semester VI
"""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

import cv2
import numpy as np
import plotly.graph_objects as go
import requests
import streamlit as st
from PIL import Image

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CCTV Video Forensics",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* Dark forensic theme */
.stApp { background: #0d1117; color: #e6edf3; }
[data-testid="stSidebar"] { background: #161b22; border-right: 1px solid #30363d; }
[data-testid="stSidebar"] * { color: #e6edf3 !important; }

/* Metric cards */
[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px;
}

/* Tab styling */
[data-testid="stTabs"] button {
    background: #161b22;
    border: 1px solid #30363d;
    color: #8b949e;
    border-radius: 6px 6px 0 0;
    font-weight: 500;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    background: #1f6feb;
    color: #ffffff;
    border-color: #1f6feb;
}

/* Status verdict badges */
.verdict-intact {
    background: #0d4429;
    border: 1px solid #2ea043;
    color: #3fb950;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    display: inline-block;
    margin: 4px 0;
}
.verdict-tampered {
    background: #4a0d0d;
    border: 1px solid #f85149;
    color: #ff7b72;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    display: inline-block;
    margin: 4px 0;
}
.verdict-unknown {
    background: #2d2a00;
    border: 1px solid #d29922;
    color: #e3b341;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    display: inline-block;
    margin: 4px 0;
}

/* Hash display */
.hash-box {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #58a6ff;
    word-break: break-all;
    margin: 6px 0;
}

/* Section cards */
.forensic-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
}

/* Step header */
.step-header {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 12px;
    color: #58a6ff;
}

/* Results table */
.results-table {
    width: 100%;
    border-collapse: collapse;
}
.results-table th {
    background: #1f6feb;
    color: white;
    padding: 8px 12px;
    text-align: left;
    font-weight: 600;
}
.results-table td {
    padding: 8px 12px;
    border-bottom: 1px solid #30363d;
    color: #e6edf3;
}
.results-table tr:hover td { background: #1c2128; }

/* Header banner */
.forensic-header {
    background: linear-gradient(135deg, #1f6feb 0%, #0d419d 50%, #161b22 100%);
    border-radius: 12px;
    padding: 24px 32px;
    margin-bottom: 24px;
    border: 1px solid #30363d;
}
</style>
""",
    unsafe_allow_html=True,
)

# ── API Config ────────────────────────────────────────────────────────────────
try:
    API_BASE_URL = st.secrets["API_URL"]
except (FileNotFoundError, KeyError):
    API_BASE_URL = os.getenv("API_URL", "http://localhost:8000")


# ── Session State ─────────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "case_id": None,
        "sha256_hash": None,
        "forensic_report": None,
        "video_path": None,
        "video_frames": None,
        "current_frame": 0,
        "ai_result": None,
        "frame_analysis": None,
        "current_threshold": None,
        "sim_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_state()


# ── API Helpers ───────────────────────────────────────────────────────────────
def check_api_health() -> Dict:
    try:
        r = requests.get(f"{API_BASE_URL}/health", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"⚠️ API unreachable: {e}")
        st.info(f"Make sure the FastAPI backend is running at **{API_BASE_URL}**\n\n`python app.py`")
        st.stop()


def api_generate_hash(video_path: str) -> Dict:
    with open(video_path, "rb") as f:
        r = requests.post(f"{API_BASE_URL}/generate-hash", files={"file": f}, timeout=120)
    r.raise_for_status()
    return r.json()


def api_verify_integrity(video_path: str, ref_hash: str) -> Dict:
    with open(video_path, "rb") as f:
        r = requests.post(
            f"{API_BASE_URL}/verify-integrity",
            params={"reference_hash": ref_hash},
            files={"file": f},
            timeout=120,
        )
    r.raise_for_status()
    return r.json()


def api_forensic_analyze(video_path: str, case_id: str = None, analyst: str = None, ref_hash: str = None) -> Dict:
    with open(video_path, "rb") as f:
        params = {}
        if case_id:
            params["case_id"] = case_id
        if analyst:
            params["analyst"] = analyst
        if ref_hash:
            params["reference_hash"] = ref_hash
        r = requests.post(
            f"{API_BASE_URL}/forensic-analyze",
            params=params,
            files={"file": f},
            timeout=300,
        )
    r.raise_for_status()
    return r.json()


def api_simulate_tampering(video_path: str, technique: str, start: float, end: float, codec: str = "XVID") -> Dict:
    with open(video_path, "rb") as f:
        r = requests.post(
            f"{API_BASE_URL}/simulate-tampering",
            params={"technique": technique, "start_param": start, "end_param": end, "codec": codec},
            files={"file": f},
            timeout=180,
        )
    r.raise_for_status()
    return r.json()


def save_temp_video(uploaded_file) -> str:
    suffix = Path(uploaded_file.name).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.read())
        return tmp.name


def extract_frames(video_path: str, max_frames: int = 300) -> List[np.ndarray]:
    frames = []
    cap = cv2.VideoCapture(video_path)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    step = max(1, total // max_frames)
    idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        if idx % step == 0:
            frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        idx += 1
    cap.release()
    return frames


def verdict_badge(text: str, kind: str = "unknown") -> str:
    css_class = {
        "intact": "verdict-intact",
        "tampered": "verdict-tampered",
        "unknown": "verdict-unknown",
    }.get(kind, "verdict-unknown")
    return f'<div class="{css_class}">{text}</div>'


def score_timeline(scores: List[float], threshold: float, flags: List[bool], current_frame: int = 0) -> go.Figure:
    frames = list(range(len(scores)))
    anomaly_frames = [i for i, f in enumerate(flags) if f]
    anomaly_scores = [scores[i] for i in anomaly_frames]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=frames, y=scores, mode="lines",
        name="Reconstruction Error",
        line=dict(color="#58a6ff", width=1.5),
        hovertemplate="Frame %{x}<br>Score: %{y:.6f}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=anomaly_frames, y=anomaly_scores, mode="markers",
        name="Anomaly", marker=dict(color="#ff7b72", size=7, symbol="circle"),
        hovertemplate="⚠️ Anomaly at frame %{x}<br>Score: %{y:.6f}<extra></extra>",
    ))
    fig.add_hline(
        y=threshold, line_dash="dash", line_color="#e3b341",
        annotation_text=f"Threshold: {threshold:.6f}",
        annotation_font_color="#e3b341",
    )
    if 0 <= current_frame < len(scores):
        fig.add_vline(x=current_frame, line_dash="dot", line_color="#3fb950",
                      annotation_text=f"Frame {current_frame}", annotation_font_color="#3fb950")
    fig.update_layout(
        plot_bgcolor="#0d1117", paper_bgcolor="#161b22",
        font_color="#e6edf3",
        title=dict(text="AI Anomaly Score Timeline", font=dict(color="#58a6ff")),
        xaxis=dict(title="Frame Number", gridcolor="#30363d", zerolinecolor="#30363d"),
        yaxis=dict(title="Reconstruction Error", gridcolor="#30363d", zerolinecolor="#30363d"),
        legend=dict(bgcolor="#161b22", bordercolor="#30363d"),
        height=380,
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
health = check_api_health()

with st.sidebar:
    st.markdown(
        """
<div style="text-align:center; padding: 8px 0 16px;">
  <div style="font-size:2rem;">🔬</div>
  <div style="font-weight:700; font-size:1.1rem; color:#58a6ff;">CCTV Forensics</div>
  <div style="font-size:0.72rem; color:#8b949e;">Acquisition · Integrity · Tamper Detection</div>
  <div style="font-size:0.65rem; color:#6e7681; margin-top:4px;">
    Cyber Forensics · B.Tech CSE · Amrita Vishwa Vidyapeetham
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    # API Status
    device = health.get("device", "unknown")
    model_ok = health.get("model_loaded", False)
    status_icon = "🟢" if model_ok else "🟡"
    st.markdown(f"**{status_icon} API:** `{device.upper()}` · Model {'Loaded' if model_ok else 'Not Loaded'}")

    st.divider()

    # Upload
    st.markdown("### 📁 Evidence Upload")
    uploaded = st.file_uploader(
        "Upload CCTV Video",
        type=["mp4", "avi", "mov", "mkv"],
        help="Upload the CCTV video evidence for forensic analysis",
    )
    if uploaded:
        if st.button("📥 Load Evidence", use_container_width=True, type="primary"):
            tmp_path = save_temp_video(uploaded)
            st.session_state.video_path = tmp_path
            st.session_state.case_id = None
            st.session_state.sha256_hash = None
            st.session_state.forensic_report = None
            st.session_state.ai_result = None
            st.session_state.frame_analysis = None
            st.session_state.sim_result = None
            with st.spinner("Extracting frames…"):
                st.session_state.video_frames = extract_frames(tmp_path)
            st.success(f"✓ Loaded: **{uploaded.name}**  ({len(st.session_state.video_frames)} frames)")

    st.divider()

    # Case metadata
    st.markdown("### 🗂️ Case Details")
    analyst_name = st.text_input("Analyst Name", placeholder="Enter your name")
    custom_case_id = st.text_input("Case ID (optional)", placeholder="Auto-generated if blank")

    st.divider()

    # Download report (sidebar quick-download)
    if st.session_state.forensic_report:
        report = st.session_state.forensic_report
        st.markdown("### 📄 Download Report")
        st.download_button(
            "⬇️ Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"forensic_report_{report.get('report_metadata', {}).get('case_id', 'CF')}.json",
            mime="application/json",
            use_container_width=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN CONTENT
# ══════════════════════════════════════════════════════════════════════════════

# Header banner
st.markdown(
    """
<div class="forensic-header">
  <div style="font-size:1.6rem; font-weight:700; color:white; margin-bottom:4px;">
    🔬 CCTV Video Forensics System
  </div>
  <div style="color:#a5d6ff; font-size:0.95rem;">
    Analog CCTV Video Forensics: Acquisition, Integrity Verification &amp; Tamper Detection
  </div>
  <div style="color:#8b949e; font-size:0.78rem; margin-top:8px;">
    Rajkushal Guduru &amp; Jeevan · Cyber Forensics · B.Tech CSE Cybersecurity · Amrita Vishwa Vidyapeetham · Semester VI
  </div>
</div>
""",
    unsafe_allow_html=True,
)

if not st.session_state.video_path:
    # Welcome screen
    st.markdown("## Welcome — Upload a CCTV video in the sidebar to begin")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""
**🔐 Step 1–2: Acquisition & Hashing**
- Upload CCTV footage
- Compute SHA-256 hash
- Establish chain of custody
""")
    with col2:
        st.markdown("""
**🔬 Step 4: Forensic Analysis**
- Frame gap detection
- Duplicate frame check
- Abrupt change detection
- Video metadata inspection
""")
    with col3:
        st.markdown("""
**🤖 AI Detection**
- Convolutional autoencoder
- Per-frame reconstruction error
- Interactive score timeline
- Adjustable threshold
""")
    with col4:
        st.markdown("""
**⚡ Step 3: Tampering Sim**
- Frame deletion
- Video cutting
- Re-encoding
- Hash verification proof
""")

    st.divider()
    st.markdown("### Methodology (from Cyber Forensics Report)")
    steps = [
        ("01", "Video Acquisition", "Capture or obtain CCTV video footage for analysis"),
        ("02", "Hash Generation", "Generate SHA-256 cryptographic hash to ensure video integrity"),
        ("03", "Tampering Simulation", "Simulate frame deletion, cutting, and re-encoding"),
        ("04", "Forensic Analysis", "Frame analysis, metadata inspection, and AI detection"),
        ("05", "Result Generation", "Generate structured forensic report with all findings"),
    ]
    cols = st.columns(5)
    for col, (num, title, desc) in zip(cols, steps):
        with col:
            st.markdown(
                f"""
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center;height:160px;">
  <div style="font-size:1.8rem;font-weight:700;color:#1f6feb;">{num}</div>
  <div style="font-weight:600;color:#58a6ff;font-size:0.85rem;margin:4px 0;">{title}</div>
  <div style="font-size:0.75rem;color:#8b949e;">{desc}</div>
</div>
""",
                unsafe_allow_html=True,
            )
    st.stop()

# ── Video is loaded — show tab interface ──────────────────────────────────────
video_path = st.session_state.video_path

tab1, tab2, tab3, tab4 = st.tabs([
    "🔐 Step 1–2: Acquisition & Hashing",
    "🔬 Step 4: Forensic Analysis",
    "⚡ Step 3: Tampering Simulator",
    "📄 Step 5: Forensic Report",
])

# ════════════════════════════════════════════════════════════════════════
#  TAB 1 — ACQUISITION & HASHING
# ════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### 🔐 Evidence Acquisition & Integrity Verification")
    st.markdown(
        "> Cryptographic hashing is used to verify video integrity. "
        "If a video is modified, the hash value changes."
    )

    # Step 1: Video info
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("#### 📹 Step 1: Video Acquisition")
        frames = st.session_state.video_frames or []
        if frames:
            # Show first frame as evidence thumbnail
            thumb = Image.fromarray(frames[0])
            thumb.thumbnail((320, 240))
            st.image(thumb, caption="First frame of evidence video", use_container_width=False)

        # Get video metadata
        try:
            cap = cv2.VideoCapture(video_path)
            total_f = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
            w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            dur = total_f / fps
            cap.release()
            st.markdown(
                f"""
<div class="forensic-card">
  <b>Frame Count:</b> {total_f}<br>
  <b>FPS:</b> {fps:.2f}<br>
  <b>Duration:</b> {dur:.2f} seconds<br>
  <b>Resolution:</b> {w}×{h}
</div>
""",
                unsafe_allow_html=True,
            )
        except Exception as e:
            st.error(f"Could not read video metadata: {e}")

    with col2:
        st.markdown("#### 🔑 Step 2: Hash Generation")
        st.code(
            """import hashlib

def calculate_hash(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()

hash_value = calculate_hash("cctv_video.mp4")
print(hash_value)""",
            language="python",
        )

        if st.button("🔑 Generate SHA-256 Hash", use_container_width=True, type="primary"):
            with st.spinner("Computing SHA-256 hash (Evidence Preservation)…"):
                try:
                    result = api_generate_hash(video_path)
                    st.session_state.sha256_hash = result["sha256"]
                    st.session_state.case_id = result["case_id"]
                    st.success(f"✅ Hash generated — Case ID: `{result['case_id']}`")
                except Exception as e:
                    st.error(f"Hash generation failed: {e}")

        if st.session_state.sha256_hash:
            st.markdown("**SHA-256 Hash (Evidence Fingerprint):**")
            st.markdown(
                f'<div class="hash-box">{st.session_state.sha256_hash}</div>',
                unsafe_allow_html=True,
            )
            st.markdown(f'**Case ID:** `{st.session_state.case_id}`')
            st.info("💡 Save this hash as your reference. Any modification to the video will change it.")

    st.divider()

    # Step 2b: Integrity verification
    st.markdown("#### 🔍 Integrity Verification — Compare Against Reference Hash")
    col_a, col_b = st.columns([2, 1])
    with col_a:
        ref_hash_input = st.text_input(
            "Reference Hash (paste the original SHA-256 hash here)",
            value=st.session_state.sha256_hash or "",
            help="Paste the hash of the original unmodified video",
        )
    with col_b:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔍 Verify Integrity", use_container_width=True, type="primary", disabled=not ref_hash_input):
            with st.spinner("Verifying video integrity…"):
                try:
                    verify_result = api_verify_integrity(video_path, ref_hash_input)
                    match = verify_result.get("match")
                    verdict = verify_result.get("verdict", "UNKNOWN")
                    if match is True:
                        st.markdown(verdict_badge("✅  INTACT — Hashes Match", "intact"), unsafe_allow_html=True)
                    elif match is False:
                        st.markdown(verdict_badge("⚠️  TAMPERED — Hash Mismatch", "tampered"), unsafe_allow_html=True)
                    else:
                        st.markdown(verdict_badge(verdict, "unknown"), unsafe_allow_html=True)
                    st.json(verify_result)
                except Exception as e:
                    st.error(f"Verification failed: {e}")


# ════════════════════════════════════════════════════════════════════════
#  TAB 2 — FORENSIC ANALYSIS
# ════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 🔬 Forensic Analysis")
    st.markdown(
        "> Frame analysis helps detect **missing frames**, **edited segments**, "
        "and **timeline inconsistencies**. Combined with AI reconstruction error analysis."
    )

    col_run, col_opts = st.columns([1, 2])
    with col_run:
        case_label = custom_case_id.strip() or st.session_state.case_id or None
        # Pass stored SHA-256 hash as reference so comparison is done correctly
        ref_hash_for_analysis = st.session_state.sha256_hash
        if st.button("▶️ Run Full Forensic Analysis", use_container_width=True, type="primary"):
            with st.spinner("Running 5-step forensic analysis… (this may take a moment)"):
                try:
                    report = api_forensic_analyze(
                        video_path,
                        case_id=case_label,
                        analyst=analyst_name or None,
                        ref_hash=ref_hash_for_analysis,  # Pass stored reference hash
                    )
                    st.session_state.forensic_report = report
                    st.session_state.frame_analysis = report.get("step3_frame_analysis", {})
                    ai_sec = report.get("step4_ai_detection", {})
                    if ai_sec.get("frame_count"):
                        st.session_state.ai_result = {
                            "frame_count": ai_sec.get("frame_count"),
                            "anomaly_count": ai_sec.get("anomaly_count"),
                            "anomaly_rate": ai_sec.get("anomaly_rate"),
                            "anomaly_scores": ai_sec.get("_scores", []),
                            "anomaly_flags": ai_sec.get("_flags", []),
                            "model_info": {"threshold": ai_sec.get("threshold")},
                        }
                    st.session_state.case_id = report.get("report_metadata", {}).get("case_id")
                    if ref_hash_for_analysis:
                        st.success(f"✅ Analysis complete — Case `{st.session_state.case_id}` (with hash comparison)")
                    else:
                        st.success(f"✅ Analysis complete — Case `{st.session_state.case_id}` (generate SHA-256 hash first for hash comparison)")
                except Exception as e:
                    st.error(f"Analysis failed: {e}")

    if not st.session_state.forensic_report:
        st.info("👆 Click **Run Full Forensic Analysis** to analyze the loaded video.")
        st.stop()

    report = st.session_state.forensic_report

    # ── Overall verdict banner ────────────────────────────────────────
    overall = report.get("overall_verdict", {})
    verdict_text = overall.get("verdict", "UNKNOWN")
    verdict_kind = "intact" if "INTACT" in verdict_text else ("tampered" if "TAMPERED" in verdict_text or "LIKELY" in verdict_text else "unknown")
    st.markdown(verdict_badge(verdict_text, verdict_kind), unsafe_allow_html=True)
    st.markdown(f"*{overall.get('summary', '')}*")

    st.divider()

    # ── Results in columns ────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)

    # Hash verification
    hash_sec = report.get("step2_integrity_verification", {})
    with col1:
        st.markdown("#### 🔑 Hash Verification")
        h_verdict = hash_sec.get("verdict", "NOT PERFORMED")
        h_kind = "intact" if h_verdict == "INTACT" else ("tampered" if h_verdict == "TAMPERED" else "unknown")
        st.markdown(verdict_badge(h_verdict, h_kind), unsafe_allow_html=True)
        st.caption(hash_sec.get("description", ""))
        if hash_sec.get("evidence_hash") and hash_sec["evidence_hash"] != "N/A":
            st.markdown(
                f'<div class="hash-box">{hash_sec["evidence_hash"]}</div>',
                unsafe_allow_html=True,
            )

    # Frame analysis
    fa_sec = report.get("step3_frame_analysis", {})
    with col2:
        st.markdown("#### 🎞️ Frame Analysis")
        vm = fa_sec.get("video_metadata", {})
        if vm:
            st.metric("Frame Count", vm.get("frame_count", "—"))
            scol1, scol2 = st.columns(2)
            with scol1:
                st.metric("FPS", f"{vm.get('fps', 0):.2f}")
            with scol2:
                st.metric("Duration", f"{vm.get('duration_sec', 0):.1f}s")
        gd = fa_sec.get("gap_detection", {})
        dd = fa_sec.get("duplicate_detection", {})
        cd = fa_sec.get("abrupt_change_detection", {})
        fa_verdict = fa_sec.get("overall_verdict", "NOT PERFORMED")
        fa_kind = "intact" if "INTACT" in fa_verdict else ("tampered" if "Possible" in fa_verdict or "FOUND" in fa_verdict else "unknown")
        st.markdown(verdict_badge(fa_verdict[:60], fa_kind), unsafe_allow_html=True)
        st.caption(f"Gaps: {gd.get('gaps_found', 0)}  |  Duplicates: {dd.get('duplicates_found', 0)}  |  Changes: {cd.get('changes_found', 0)}")

    # Metadata analysis
    meta_sec = report.get("_metadata_analysis", {})
    with col3:
        st.markdown("#### 📋 Metadata Analysis")
        if meta_sec:
            m_verdict = meta_sec.get("verdict", "NOT PERFORMED")
            m_kind = "intact" if "NORMAL" in m_verdict else ("tampered" if "ANOMALIES" in m_verdict else "unknown")
            st.markdown(verdict_badge(m_verdict[:60], m_kind), unsafe_allow_html=True)
            anomalies = meta_sec.get("anomalies", [])
            if anomalies:
                for a in anomalies[:3]:
                    sev = a.get("severity", "LOW")
                    icon = "🔴" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🟢")
                    st.caption(f"{icon} {a.get('description', '')}")
        else:
            st.markdown(verdict_badge("NOT PERFORMED", "unknown"), unsafe_allow_html=True)

    st.divider()

    # ── AI Detection results ──────────────────────────────────────────
    ai_sec = report.get("step4_ai_detection", {})
    if ai_sec.get("status") == "COMPLETE":
        st.markdown("#### 🤖 AI-Based Tampering Detection (Convolutional Autoencoder)")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Frames Analyzed", ai_sec.get("frame_count", 0))
        with c2:
            st.metric("Anomalies Detected", ai_sec.get("anomaly_count", 0))
        with c3:
            rate = ai_sec.get("anomaly_rate", 0)
            st.metric("Anomaly Rate", f"{rate * 100:.1f}%")
        with c4:
            st.metric("Processing Time", f"{ai_sec.get('processing_sec', 0):.2f}s")

        st.caption(ai_sec.get("verdict", ""))

        # ── AI Score Timeline chart ───────────────────────────────────
        scores = ai_sec.get("_scores", [])
        flags = ai_sec.get("_flags", [])
        threshold = ai_sec.get("threshold")
        if scores and flags and threshold is not None:
            st.markdown("#### 📈 AI Anomaly Score Timeline")
            fig = score_timeline(scores, threshold, flags)
            st.plotly_chart(fig, use_container_width=True)

    # ── Preliminary Results Table ─────────────────────────────────────
    st.divider()
    st.markdown("#### 📊 Preliminary Results Table")
    st.caption("Matching the detection results table from the Cyber Forensics report")

    results_table = report.get("preliminary_results_table", [])
    if results_table:
        rows_html = ""
        for row in results_table:
            res = row.get("result", "")
            if any(w in res for w in ("Valid", "No tampering", "Hashes Match", "No anomalies", "No frame")):
                color = "#3fb950"  # green
            elif "Detected" in res or "Mismatch" in res:
                color = "#ff7b72"  # red
            else:
                color = "#e3b341"  # yellow
            rows_html += f"""
<tr>
  <td>{row.get('test_case', '')}</td>
  <td>{row.get('detection_method', '')}</td>
  <td style="color:{color};font-weight:600;">{res}</td>
</tr>"""
        st.markdown(
            f"""
<table class="results-table">
  <thead>
    <tr><th>Test Case</th><th>Detection Method</th><th>Result</th></tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>
""",
            unsafe_allow_html=True,
        )


# ════════════════════════════════════════════════════════════════════════
#  TAB 3 — TAMPERING SIMULATOR
# ════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### ⚡ Tampering Simulation (Step 3)")
    st.markdown(
        "> Simulates the tampering techniques from the report to demonstrate how each method "
        "is detected by forensic analysis. **Changes the file hash — proving forensic detection works.**"
    )

    # Show the FFmpeg example from report
    st.code(
        "ffmpeg -i original.mp4 -ss 00:00:00 -t 00:00:30 cut_video.mp4",
        language="bash",
    )
    st.caption("↑ The report example — implemented here via OpenCV (no FFmpeg dependency needed)")

    st.divider()

    technique = st.selectbox(
        "Select Tampering Technique",
        options=["frame_deletion", "video_cutting", "re_encoding"],
        format_func=lambda x: {
            "frame_deletion": "1️⃣  Frame Deletion — Remove frames to hide events",
            "video_cutting": "2️⃣  Video Cutting — Remove a timeline segment",
            "re_encoding": "3️⃣  Re-Encoding — Re-save with different codec/compression",
        }[x],
    )

    col_params, col_info = st.columns([1, 1])

    # Get video info for parameter ranges
    try:
        cap = cv2.VideoCapture(video_path)
        v_total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        v_fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
        v_dur = v_total_frames / v_fps
        cap.release()
    except Exception:
        v_total_frames, v_fps, v_dur = 300, 30.0, 10.0

    with col_params:
        if technique == "frame_deletion":
            st.markdown("**Select frame range to delete:**")
            del_range = st.slider(
                "Frame range",
                0, v_total_frames,
                (0, min(30, v_total_frames // 4)),
                help="Frames in this range will be removed from the output video",
            )
            start_p, end_p = float(del_range[0]), float(del_range[1])
            codec_p = "XVID"
            st.markdown(
                f'<div class="forensic-card">Deleting frames **{del_range[0]}** to **{del_range[1]}** '
                f'({del_range[1] - del_range[0]} frames / {(del_range[1] - del_range[0]) / v_fps:.2f}s)</div>',
                unsafe_allow_html=True,
            )

        elif technique == "video_cutting":
            st.markdown("**Select time range to cut out:**")
            cut_range = st.slider(
                "Time range (seconds)",
                0.0, float(v_dur),
                (0.0, min(3.0, v_dur * 0.25)),
                step=0.1,
            )
            start_p, end_p = cut_range
            codec_p = "XVID"
            st.markdown(
                f'<div class="forensic-card">Removing segment **{start_p:.1f}s** to **{end_p:.1f}s** '
                f'({end_p - start_p:.1f}s of footage)</div>',
                unsafe_allow_html=True,
            )

        else:  # re_encoding
            codec_p = st.selectbox("Target Codec", ["XVID", "MJPG", "mp4v"], index=0)
            start_p, end_p = 0.0, 0.0
            st.markdown(
                f'<div class="forensic-card">Re-encoding entire video to **{codec_p}** codec. '
                "This changes the file hash and encoder metadata.</div>",
                unsafe_allow_html=True,
            )

    with col_info:
        technique_info = {
            "frame_deletion": {
                "title": "Frame Deletion",
                "description": "Removing frames to hide specific events.",
                "detected_by": "Frame count mismatch, timestamp gaps",
                "report_result": "Detected",
            },
            "video_cutting": {
                "title": "Video Cutting",
                "description": "Removing parts of the video timeline.",
                "detected_by": "Duration mismatch, frame gaps",
                "report_result": "Detected",
            },
            "re_encoding": {
                "title": "Re-Encoding",
                "description": "Saving the video with different compression.",
                "detected_by": "Hash mismatch, metadata change",
                "report_result": "Detected",
            },
        }[technique]
        st.markdown(
            f"""
<div class="forensic-card">
  <b>Technique:</b> {technique_info['title']}<br>
  <b>Description:</b> {technique_info['description']}<br>
  <b>Detected by:</b> {technique_info['detected_by']}<br>
  <b>Report result:</b> <span style="color:#3fb950;font-weight:600;">{technique_info['report_result']}</span>
</div>
""",
            unsafe_allow_html=True,
        )

    st.divider()

    if st.button("⚡ Simulate Tampering", use_container_width=True, type="primary"):
        with st.spinner(f"Simulating {technique.replace('_', ' ')}…"):
            try:
                sim = api_simulate_tampering(video_path, technique, start_p, end_p, codec_p)
                st.session_state.sim_result = sim
            except Exception as e:
                st.error(f"Simulation failed: {e}")

    if st.session_state.sim_result:
        sim = st.session_state.sim_result
        hc = sim.get("hash_comparison", {})
        match = hc.get("match")

        st.markdown("#### Simulation Results")
        if match is False:
            st.markdown(
                verdict_badge("⚠️  HASH CHANGED — Tampering Detectable by Hash Verification", "tampered"),
                unsafe_allow_html=True,
            )
            st.success("✅ Forensic verification WORKS — the tampered file produces a different hash.")
        elif match is True:
            st.markdown(
                verdict_badge("⚠️  Hash Unchanged — Re-encoding needs frame analysis", "unknown"),
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                verdict_badge("ℹ️  Simulation Complete — see hashes below", "unknown"),
                unsafe_allow_html=True,
            )

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Original Hash:**")
            st.markdown(f'<div class="hash-box">{sim.get("original_hash", "N/A")}</div>', unsafe_allow_html=True)
        with c2:
            st.markdown("**Tampered Hash:**")
            orig = sim.get("original_hash", "")
            tamp = sim.get("tampered_hash", "N/A")
            color = "#ff7b72" if orig != tamp else "#3fb950"
            st.markdown(
                f'<div class="hash-box" style="color:{color};">{tamp}</div>',
                unsafe_allow_html=True,
            )

        # Show diff count
        orig_h = sim.get("original_hash", "")
        tamp_h = sim.get("tampered_hash", "")
        if orig_h and tamp_h and orig_h != tamp_h:
            diff_chars = sum(a != b for a, b in zip(orig_h, tamp_h))
            st.markdown(f"🔍 **{diff_chars}/64 hex characters differ** between original and tampered hash")

        st.info(f"📌 {sim.get('forensic_note', '')}")
        with st.expander("📋 Simulation Details (JSON)"):
            st.json(sim.get("simulation_result", {}))


# ════════════════════════════════════════════════════════════════════════
#  TAB 4 — FORENSIC REPORT
# ════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 📄 Forensic Report (Step 5)")
    st.markdown("> Structured forensic analysis report — can be downloaded for case proceedings.")

    if not st.session_state.forensic_report:
        st.info("Run the **Full Forensic Analysis** in the Forensic Analysis tab to generate a report.")
        st.stop()

    report = st.session_state.forensic_report
    meta = report.get("report_metadata", {})
    overall = report.get("overall_verdict", {})

    # Report header
    st.markdown(
        f"""
<div class="forensic-card">
  <div style="font-size:1.2rem;font-weight:700;color:#58a6ff;margin-bottom:8px;">
    {meta.get('title', 'CCTV Video Forensic Analysis Report')}
  </div>
  <div style="color:#8b949e;font-size:0.85rem;margin-bottom:12px;">
    {meta.get('subtitle', '')}
  </div>
  <table style="width:100%;font-size:0.85rem;">
    <tr><td style="color:#8b949e;width:120px;">Case ID</td><td style="color:#e6edf3;font-family:'JetBrains Mono',monospace;font-weight:600;">{meta.get('case_id', 'N/A')}</td></tr>
    <tr><td style="color:#8b949e;">Analyst</td><td style="color:#e6edf3;">{meta.get('analyst', 'N/A')}</td></tr>
    <tr><td style="color:#8b949e;">Generated</td><td style="color:#e6edf3;">{meta.get('generated_at_utc', 'N/A')}</td></tr>
    <tr><td style="color:#8b949e;">Institution</td><td style="color:#e6edf3;">{meta.get('institution', 'N/A')}</td></tr>
    <tr><td style="color:#8b949e;">Course</td><td style="color:#e6edf3;">{meta.get('course', 'N/A')}</td></tr>
  </table>
</div>
""",
        unsafe_allow_html=True,
    )

    st.divider()

    # Overall verdict
    verdict_text = overall.get("verdict", "UNKNOWN")
    verdict_kind = "intact" if "INTACT" in verdict_text else ("tampered" if "LIKELY" in verdict_text or "TAMPERED" in verdict_text else "unknown")
    st.markdown("#### Overall Forensic Verdict")
    st.markdown(verdict_badge(verdict_text, verdict_kind), unsafe_allow_html=True)
    st.markdown(f"**Confidence:** `{overall.get('confidence', 'LOW')}`")
    st.markdown(overall.get("summary", ""))

    indicators = overall.get("indicators", [])
    if indicators:
        st.markdown("**Tampering Indicators Found:**")
        for ind in indicators:
            st.markdown(f"- ⚠️ {ind}")

    st.divider()

    # Section details
    with st.expander("🔑 Step 2: Integrity Verification", expanded=True):
        h = report.get("step2_integrity_verification", {})
        st.markdown(f"**Status:** {h.get('status')}")
        st.markdown(f"**Verdict:** {h.get('verdict', 'N/A')}")
        st.markdown(f"**Method:** {h.get('method', 'SHA-256')}")
        if h.get("evidence_hash") and h["evidence_hash"] != "N/A":
            st.markdown("**Evidence Hash:**")
            st.markdown(f'<div class="hash-box">{h["evidence_hash"]}</div>', unsafe_allow_html=True)

    with st.expander("🎞️ Step 4a: Frame Analysis", expanded=True):
        fa = report.get("step3_frame_analysis", {})
        vm = fa.get("video_metadata", {})
        if vm:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Frames", vm.get("frame_count"))
            c2.metric("FPS", f"{vm.get('fps', 0):.2f}")
            c3.metric("Duration", f"{vm.get('duration_sec', 0):.1f}s")
            c4.metric("Resolution", vm.get("resolution", "—"))
        st.markdown(f"**Gap Detection:** {fa.get('gap_detection', {}).get('verdict', 'N/A')}")
        st.markdown(f"**Duplicate Frames:** {fa.get('duplicate_detection', {}).get('verdict', 'N/A')}")
        st.markdown(f"**Abrupt Changes:** {fa.get('abrupt_change_detection', {}).get('verdict', 'N/A')}")

    with st.expander("🤖 Step 4c: AI Detection"):
        ai = report.get("step4_ai_detection", {})
        st.markdown(f"**Status:** {ai.get('status')}")
        st.markdown(f"**Method:** {ai.get('method', 'Convolutional Autoencoder')}")
        if ai.get("frame_count"):
            c1, c2, c3 = st.columns(3)
            c1.metric("Frames", ai.get("frame_count"))
            c2.metric("Anomalies", ai.get("anomaly_count"))
            c3.metric("Rate", f"{(ai.get('anomaly_rate', 0)) * 100:.1f}%")
        st.markdown(f"**Verdict:** {ai.get('verdict', 'N/A')}")

    with st.expander("📊 Preliminary Results Table", expanded=True):
        table = report.get("preliminary_results_table", [])
        if table:
            rows_html = ""
            for row in table:
                res = row.get("result", "")
                color = "#3fb950" if res in ("Valid", "No tampering detected") else "#ff7b72" if "Detected" in res else "#e3b341"
                rows_html += f'<tr><td>{row.get("test_case", "")}</td><td>{row.get("detection_method", "")}</td><td style="color:{color};font-weight:600;">{res}</td></tr>'
            st.markdown(
                f'<table class="results-table"><thead><tr><th>Test Case</th><th>Detection Method</th><th>Result</th></tr></thead><tbody>{rows_html}</tbody></table>',
                unsafe_allow_html=True,
            )

    st.divider()

    # Download buttons
    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            "⬇️ Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"forensic_report_{meta.get('case_id', 'CF')}.json",
            mime="application/json",
            use_container_width=True,
        )
    with c2:
        # Build text report on the fly
        text_lines = [
            "=" * 70,
            "CCTV VIDEO FORENSIC ANALYSIS REPORT",
            "Analog CCTV Video Forensics: Acquisition, Integrity Verification & Tamper Detection",
            "=" * 70,
            f"Case ID   : {meta.get('case_id')}",
            f"Analyst   : {meta.get('analyst')}",
            f"Generated : {meta.get('generated_at_utc')}",
            f"Institution: {meta.get('institution')}",
            f"Course    : {meta.get('course')}",
            "",
            "OVERALL VERDICT",
            "=" * 70,
            f"  {verdict_text}",
            f"  Confidence: {overall.get('confidence')}",
            f"  {overall.get('summary', '')}",
            "",
        ]
        if indicators:
            text_lines.append("INDICATORS:")
            for ind in indicators:
                text_lines.append(f"  - {ind}")
        text_lines += [
            "",
            "PRELIMINARY RESULTS TABLE",
            "-" * 70,
            f"{'Test Case':<30} {'Detection Method':<30} Result",
            "-" * 70,
        ]
        for row in table:
            text_lines.append(f"{row.get('test_case', '')[:28]:<30} {row.get('detection_method', '')[:28]:<30} {row.get('result', '')}")
        text_lines += [
            "",
            "=" * 70,
            "This report was generated by the CCTV Video Forensics System.",
            "For legal proceedings, results must be verified by a certified forensic analyst.",
            "=" * 70,
        ]
        st.download_button(
            "⬇️ Download TXT Report",
            data="\n".join(text_lines),
            file_name=f"forensic_report_{meta.get('case_id', 'CF')}.txt",
            mime="text/plain",
            use_container_width=True,
        )
