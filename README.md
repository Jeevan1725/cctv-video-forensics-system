# CCTV Video Forensics System
### Analog CCTV Video Forensics: Acquisition, Integrity Verification & Tamper Detection

> **Rajkushal Guduru & Jeevan** · B.Tech CSE – Cybersecurity · Amrita Vishwa Vidyapeetham  
> Course: Cyber Forensics · Semester VI

A complete forensic framework for verifying the authenticity of CCTV surveillance footage — implementing cryptographic integrity verification, frame-level tamper detection, and AI-based anomaly analysis.

**AI Model Performance:** 92.47% precision · 83.78% recall · 87.91% F1 · 0.7438 AUC (UCSD Ped2)

---

## 🔬 Forensic Methodology (5-Step Pipeline)

This project implements the complete forensic workflow from the Cyber Forensics course report:

| Step | Name | Description |
|------|------|-------------|
| **01** | Video Acquisition | Capture or obtain CCTV video footage for analysis |
| **02** | Evidence Preservation | SHA-256 cryptographic hashing to ensure video integrity |
| **03** | Tampering Simulation | Simulate frame deletion, video cutting, and re-encoding |
| **04** | Forensic Analysis | Frame continuity, metadata inspection, and AI detection |
| **05** | Result Generation | Structured forensic report with preliminary results table |

### Tampering Techniques Detected

| Test Case | Detection Method | Result |
|-----------|-----------------|--------|
| Original video | Hash verification | ✅ Valid |
| Frame deleted video | Frame count mismatch | ⚠️ Detected |
| Re-encoded video | Metadata change | ⚠️ Detected |
| Edited video | Hash mismatch | ⚠️ Detected |

---

---

## 🚀 Quick Start

### Run Locally

**Requirements:**
- Python 3.10+
- 2GB disk space

**Setup:**

```bash
# Clone the repository
git clone https://github.com/Jeevan1725/cctv-video-forensics-system.git
cd cctv-video-forensics-system

# Install dependencies
pip install -r requirements.txt

# Start API backend (Terminal 1)
python app.py
# API available at http://localhost:8000

# Launch dashboard (Terminal 2)
streamlit run dashboard.py
# Dashboard opens at http://localhost:8501
```

**Forensic Workflow:**
1. **Upload** a CCTV video (MP4, AVI) to the dashboard.
2. **Generate** SHA-256 hash (Step 2 — Evidence Preservation).
3. **Run** Full Forensic Analysis to check frame continuity, metadata, and AI anomalies.
4. **Simulate** Tampering (Step 3) to test the detection system.
5. **Download** the generated forensic report (JSON/TXT).

---

## 📊 Features

### Interactive Dashboard
- **Drag-and-drop** video upload
- **Interactive timeline** showing reconstruction errors
- **Real-time threshold adjustment** - change sensitivity without reprocessing
- **Frame viewer** - inspect specific anomalies
- **Export results** to JSON or CSV for reporting

### REST API
- **Simple POST request** for video analysis
- **JSON response** with per-frame anomaly scores
- **Adjustable thresholds** via API endpoints
- **Swagger documentation** at `/docs`

### Threshold Presets

Adjust sensitivity to match your needs:

| Preset | Anomaly Rate | Best For |
|--------|--------------|----------|
| **Conservative** | 5% | Minimizing false alarms |
| **Balanced** | 10% | General surveillance (default) |
| **Moderate** | 25% | High-sensitivity monitoring |
| **Sensitive** | 40% | Maximum detection (more alerts) |

---

## 💡 Use Cases

### Legal Evidence Authentication
- Ensure CCTV footage has not been modified before presenting in court.
- Maintain chain of custody with SHA-256 cryptographic hashing.

### Security & Investigations
- Detect deliberate frame deletions intended to hide incidents.
- Identify video cuts and re-encoding attempts.
- Use convolutional autoencoders to spot anomalous timeline events automatically.

---

## 🎛️ API Reference

### Analyze Video

```http
POST /forensic-analyze
Content-Type: multipart/form-data
```

**Example:**
```bash
curl -X POST "http://localhost:8000/forensic-analyze?analyst=Jeevan" \
  -F "file=@test_videos/realistic_anomaly.mp4"
```

### Set Threshold Preset

```http
POST /set-threshold-preset
Content-Type: application/json

{
  "preset": "balanced"  // conservative, balanced, moderate, sensitive
}
```

### Calibrate Threshold

```http
POST /calibrate-threshold
Content-Type: application/json

{
  "target_anomaly_rate": 0.10  // Target 10% anomaly rate
}
```

### Prometheus Metrics (Production Monitoring)

For DevOps/infrastructure monitoring, the API exposes Prometheus-compatible metrics:

```http
GET /metrics/prometheus
```

**Metrics exposed:**
- `anomaly_detection_requests_total` - Request counts by endpoint and status
- `anomaly_detection_request_latency_seconds` - Request latency histogram
- `anomaly_detection_frames_processed_total` - Total frames processed
- `anomaly_detection_anomalies_total` - Total anomalies detected
- `anomaly_detection_active_jobs` - Active background jobs
- `anomaly_detection_gpu_memory_bytes` - GPU memory usage (if available)
- `anomaly_detection_inference_latency_seconds` - Model inference latency per batch

**Usage with Prometheus:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'anomaly-detection'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics/prometheus'
```

**Full API documentation:** Visit `/docs` endpoint for interactive Swagger UI

---

---

## 🏗️ System Architecture

The system uses a **convolutional autoencoder**—a neural network trained to reconstruct normal surveillance footage. Here's how it detects anomalies:

```
Video Upload
    ↓
Frame Extraction (OpenCV)
    ↓
Preprocessing (Grayscale, 64×64 resize)
    ↓
AI Model (Autoencoder)
    ↓
Reconstruction Error Calculation
    ↓
Threshold Comparison
    ↓
Anomaly Flags + Scores
```

**Key Concept:** The model learns to recreate "normal" frames accurately. When it encounters something unusual, the reconstruction quality drops—this error spike indicates an anomaly.

**Technical Details:**
- **Input:** 64×64 grayscale frames
- **Architecture:** Encoder (compress) → Latent space (256-dim) → Decoder (reconstruct)
- **Output:** Per-frame reconstruction error (0.0-1.0 scale)
- **Threshold:** Statistical cutoff (typically 95th percentile of validation set errors)

---

## 📂 Project Structure

```text
├── app.py                    # FastAPI backend & forensic endpoints
├── dashboard.py              # Streamlit forensic analysis dashboard
├── settings.py               # Configuration management
├── forensics/                # Core forensic modules
│   ├── hashing.py            # SHA-256 integrity verification
│   ├── frame_analysis.py     # Frame gap/duplicate detection
│   ├── tampering_simulator.py# Simulate deletion, cuts, re-encoding
│   ├── metadata_inspector.py # Inspect video file metadata
│   └── report_generator.py   # Generate JSON/TXT forensic reports
├── models/                   # AI Detection Models
│   ├── autoencoder.py        # Convolutional neural network architecture
│   └── detector.py           # Anomaly inference logic
├── outputs/                  # Saved hashes, reports, and AI models
└── test_videos/              # Sample footage for forensic testing
```

---

## 🔧 Configuration

Default settings work for most cases. Customize via environment variables or `.env` file:

```bash
# File size limits
APP_MAX_FILE_SIZE_MB=100              # Max video file size
APP_MAX_VIDEO_DURATION_SEC=300        # Max 5 minutes

# Processing
APP_BATCH_SIZE=64                     # Frames processed per batch
APP_DEVICE=cuda                       # Use 'cpu' to force CPU processing

# Thresholds
APP_THRESHOLD=0.005069                # Anomaly detection threshold
```

**When to adjust:**
- **Large videos:** Reduce `APP_BATCH_SIZE` if running out of memory
- **No GPU:** Set `APP_DEVICE=cpu` (expect slower processing)
- **Too many alerts:** Increase `APP_THRESHOLD` value
- **Missing anomalies:** Decrease `APP_THRESHOLD` value

---

## 🎓 Model Performance

**Training Dataset:** UCSD Ped2 (outdoor pedestrian surveillance)

**Metrics:**
- **Precision:** 92.47% - When system flags an anomaly, it's usually correct
- **Recall:** 83.78% - Catches most real anomalies
- **F1 Score:** 87.91% - Balanced performance
- **AUC:** 0.7438 - Good discrimination between normal and anomalous

**What this means:**
- **Low false positives:** Reliable alerts
- **Good detection:** Catches most unusual events
- **Best for:** General surveillance, unusual activity detection
- **Limitations:** Performance degrades on footage very different from training data

---

## 🛠️ Advanced Usage

### ONNX Export (Optional - Advanced Deployments Only)

**What is ONNX?** A cross-platform model format for specialized deployments.

**When to use:**
- Deploying to edge devices (Raspberry Pi, Jetson Nano)
- Platforms requiring ONNX (Azure ML, AWS SageMaker)
- Hardware-specific optimizations (TensorRT for NVIDIA, OpenVINO for Intel)

**When NOT to use:**
- Regular deployments (PyTorch model is already fast)
- Cloud hosting (Render, AWS Lambda) - PyTorch works fine
- Local usage - no benefit

**Important:** ONNX export does NOT improve accuracy (same model, different format). Speed improvement only occurs with specialized hardware accelerators.

**Export Command:**
```bash
# Basic export
python export_model.py --output outputs/model.onnx

# With optimizations and validation
python export_model.py --output outputs/model.onnx --optimize --validate --benchmark
```

**Use the ONNX model:**
```python
import onnxruntime as ort
session = ort.InferenceSession("outputs/model.onnx")
output = session.run(None, {"input": preprocessed_frames})
```

### Retraining on Your Data

**Why retrain?**
- Current model is trained on outdoor pedestrian footage (UCSD Ped2)
- Your cameras may be indoors, retail, parking lots, etc.
- Retraining on your footage improves accuracy for your specific environment

**Step 1: Get Training Data**

**Option A: Use UCSD Ped2 Dataset (Original Training Data)**
```bash
# Download from official source
# Visit: http://www.svcl.ucsd.edu/projects/anomaly/dataset.htm
# Download: UCSD Anomaly Detection Dataset - Ped2

# Extract to project directory
# Expected structure:
# data/UCSD_Anomaly_Dataset.v1p2/UCSDped2/Train/
# data/UCSD_Anomaly_Dataset.v1p2/UCSDped2/Test/
```

**Option B: Use Your Own Camera Footage**
```bash
# Create data directory
mkdir -p data/my_cameras/normal_behavior/

# Add your videos (normal behavior only, no anomalies)
# - At least 10-20 videos, 30-60 seconds each
# - Typical daily operations, normal foot traffic
# - Consistent lighting and camera angles
# - MP4, AVI, or MOV format

# Example structure:
# data/my_cameras/normal_behavior/
#   ├── camera1_morning_20250113.mp4
#   ├── camera1_afternoon_20250113.mp4
#   ├── camera2_evening_20250113.mp4
#   └── ...
```

**Step 2: Train the Model**

**Using UCSD Ped2 (Original Dataset):**
```bash
python main.py --mode ucsd --dataset_name ped2 \
    --data_path data/UCSD_Anomaly_Dataset.v1p2/UCSDped2/ \
    --epochs 50
```

**Using Your Own Footage:**
```bash
python main.py --mode custom \
    --data_path data/my_cameras/normal_behavior/ \
    --epochs 50 \
    --batch_size 64
```

**Training Output:**
```
Epoch 1/50: Loss=0.0234 (2m 15s)
Epoch 2/50: Loss=0.0187 (2m 12s)
...
✓ Training complete!
✓ Model saved to: outputs/trained_model.pth
✓ Threshold calibrated: 0.005234
```

**Step 3: Test the New Model**

```bash
# Restart API to load new model
python app.py

# Test with your videos via dashboard
streamlit run dashboard.py
```

**Training Tips:**
- **More data = better accuracy** (aim for 30+ minutes of footage)
- **Consistent conditions:** Similar lighting, weather, time of day
- **Normal behavior only:** Don't include anomalies in training data
- **GPU recommended:** Training takes 10-30 minutes with GPU vs 2-4 hours on CPU
- **Monitor loss:** Should decrease steadily; if it plateaus early, add more data

### Quick Testing (Synthetic Data)

Don't have real footage yet? Generate test videos:

```bash
python create_realistic_test_videos.py
# Creates 5 test videos in test_videos/
# Mix of normal pedestrian motion + anomalies

# Analyze them
streamlit run dashboard.py
# Upload videos from test_videos/
```

### Batch Processing

Process multiple videos programmatically:

```python
import requests
import os

api_url = "https://video-anomaly-detection-api.onrender.com/analyze-video"

video_dir = "surveillance_footage/"
for filename in os.listdir(video_dir):
    if filename.endswith((".mp4", ".avi", ".mov")):
        with open(os.path.join(video_dir, filename), "rb") as video:
            response = requests.post(api_url, files={"file": video})
            result = response.json()
            
            # Log high-anomaly videos
            if result["anomaly_rate"] > 0.20:
                print(f"⚠️  {filename}: {result['anomaly_count']} anomalies")
```

### Docker Deployment

Run the system in a container:

```bash
# Build image
docker build -t anomaly-detector .

# Run container
docker run -p 8000:8000 anomaly-detector

# API available at http://localhost:8000
```

---

## 📚 Documentation

- **[DASHBOARD_GUIDE.md](DASHBOARD_GUIDE.md)** - Complete dashboard feature guide
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Setup and deployment instructions
- **[deployment/README.md](deployment/README.md)** - Information about live services
- **API Docs:** Visit `/docs` on any running API instance

---

## ❓ Troubleshooting

**High false positive rate:**
- Increase threshold using dashboard slider or API
- Switch to "Conservative" preset
- Consider retraining on your specific footage

**Missing obvious anomalies:**
- Decrease threshold using dashboard slider
- Switch to "Sensitive" preset
- Verify anomaly type matches training data

**Slow processing:**
- **Cloud:** First request takes 30-60s (service wake-up), then faster
- **Local without GPU:** Expected 2-5s per video
- **Local with GPU:** Should be ~0.2s per video

**API connection failed:**
- **Cloud:** Wait 60 seconds for service to wake up
- **Local:** Verify `python app.py` is running

**Video upload fails:**
- Check file format (MP4, AVI, MOV supported)
- Verify file size < 100MB
- Try converting to MP4 with H.264 codec

---

## ❓ Frequently Asked Questions

**Q: Do I need to train the model before using the system?**  
**A:** No! The system includes a pre-trained model (`outputs/trained_model.pth`) ready to use. Just run `python app.py` and start analyzing videos.

**Q: When should I retrain the model?**  
**A:** Retrain if:
- Your cameras show very different scenes (indoor vs outdoor, retail vs parking lot)
- You're getting many false positives or missing real anomalies
- You need to adapt to your specific environment

**Q: Will ONNX export make my results better?**  
**A:** No. ONNX export does NOT change accuracy—it's the same model in a different format. Use ONNX only for:
- Edge device deployment (Raspberry Pi, Jetson Nano)
- Platforms requiring ONNX format (specific cloud services)
- Hardware-specific optimizations (TensorRT, OpenVINO)

For normal cloud hosting or local use, stick with the PyTorch model.

**Q: Where do I get the UCSD Ped2 dataset?**  
**A:** Download from the official source: http://www.svcl.ucsd.edu/projects/anomaly/dataset.htm  
The current model is already trained on this dataset, so you only need it if retraining.

**Q: How much data do I need to retrain?**  
**A:** Minimum 10-20 videos (30-60 seconds each) of normal behavior. More is better—aim for 30+ minutes total.

**Q: Can I use videos WITH anomalies for training?**  
**A:** No! Training data should only contain normal behavior. The model learns what "normal" looks like, then flags anything different.

**Q: How long does training take?**  
**A:** 
- With GPU (RTX 3050): 10-30 minutes
- Without GPU (CPU): 2-4 hours
- Depends on dataset size and epochs

**Q: The system flags too many normal frames as anomalies. What do I do?**  
**A:**
1. Increase threshold using dashboard slider
2. Switch to "Conservative" preset
3. If still bad, retrain on your specific camera footage

**Q: The system misses obvious anomalies. What do I do?**  
**A:**
1. Decrease threshold using dashboard slider
2. Switch to "Sensitive" preset
3. Verify your anomalies match what the model was trained on (pedestrian behavior)

---

## 🔗 Additional Resources

**How Autoencoders Work:**
- [Understanding Autoencoders](https://towardsdatascience.com/applied-deep-learning-part-3-autoencoders-1c083af4d798)
- [Anomaly Detection with Autoencoders](https://arxiv.org/abs/1807.02108)

**UCSD Ped2 Dataset:**
- [Dataset Information](http://www.svcl.ucsd.edu/projects/anomaly/dataset.htm)
- Used for training and evaluation

**Technologies Used:**
- **PyTorch** - Deep learning framework
- **FastAPI** - REST API framework
- **Streamlit** - Dashboard framework
- **OpenCV** - Video processing

---

## 📄 License

[Apache License](LICENSE)

UCSD Ped2 dataset used under academic license for training.

---

## 🤝 Contributing

Found a bug? Have a suggestion? Open an issue on [GitHub](https://github.com/Jeevan1725/cctv-video-forensics-system/issues).

---

**Built with ❤️ for Cyber Forensics**
