# WPE-Framework-Crash-Analyzer
This Web application that provides automated crash analysis for WPE Framework/Thunder

This is a Python web application that provides automated crash analysis for WPE Framework/Thunder with the following phases:

Phase 1: Crash Discovery & Process Identification
Phase 2: Thunder vs Plugin Responsibility Analysis

## 🚀 Features

### Phase 1: Crash Discovery & Process Identification
- ✅ **Automated Device Info Extraction**: MAC addresses and image versions
- ✅ **Smart Process Identification**: WPEFramework, Thunder, Plugin, COMRPC detection
- ✅ **Signal Analysis**: SIGSEGV, SIGABRT, SIGKILL and custom signal mapping
- ✅ **Precise Timestamp Extraction**: Crash-specific timestamp correlation
- ✅ **Context-Aware Log Analysis**: ±10 lines around crash signals with highlighting

### Phase 2: Thunder vs Plugin Responsibility Analysis
- ✅ **Ownership Determination**: Thunder Core vs Plugin responsibility scoring
- ✅ **Pattern-Based Evidence**: Thunder-specific log pattern heuristics
- ✅ **Percentage Confidence**: Quantified ownership confidence (0-100%)
- ✅ **Plugin Activation Analysis**: Special detection for plugin lifecycle crashes
- ✅ **Escalation Recommendations**: Clear team assignment based on analysis

## 📊 Analysis Capabilities

| Component | Detection Patterns | Confidence Scoring |
|-----------|-------------------|-------------------|
| **Thunder Plugin** | Plugin activation crashes, pure virtual method calls, lifecycle issues | 70%+ High confidence |
| **Thunder Core** | WorkerPool threads, MessageDispatcher, framework assertions | Pattern-weighted scoring |
| **COMRPC Layer** | RPC boundary issues, invoke errors, timeout patterns | Evidence-based analysis |
| **Framework Startup** | Configuration errors, JSON parsing, startup sequence | Multi-pattern detection |

## 🛠 Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Setup
```bash
# Clone the repository
git clone <your-repo-url>
cd Co-pilot-WPE-Virtual-Warrior

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Docker Setup (Optional)
```bash
# Build image
docker build -t wpe-crash-analyzer .

# Run container
docker run -p 5000:5000 wpe-crash-analyzer
```

## 🌐 Usage

### Web Interface
1. Navigate to `http://localhost:5000`
2. Go to **Upload Logs** page
3. Upload required files:
   - **Required**: `core_log.txt` (crash dump file)
   - **Optional**: `wpeframework.log` (application log)
4. Enable **Phase 2 Analysis** for ownership determination
5. Click **Analyze Crash Logs**

### REST API
```bash
# Analyze crash logs via API
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "core_log": "your core log content...",
    "wpe_log": "your wpe log content...",
    "include_phase2": true
  }'
```

### API Response Format
```json
{
  "device_info": {
    "mac_address": "D452EED948E4",
    "image_version": "4.9.119"
  },
  "crash_details": {
    "crashed_process": ["WPEFramework"],
    "signal": "SIGABRT",
    "timestamp": "2026-01-29T16:31:20.962Z",
    "crash_context": {
      "crash_pid": "4029",
      "crashed_process": "WPEFramework"
    }
  },
  "ownership_analysis": {
    "primary_ownership": "Thunder Plugin",
    "confidence_percentage": 75,
    "confidence": "High",
    "hypothesis": "The crash likely originates from a Thunder plugin during activation...",
    "recommendation": "Escalate to Thunder Plugin Development Team"
  }
}
```

## 📈 Analysis Phases Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Crash Discovery & Process Identification |
| **Phase 2** | ✅ Complete | Thunder vs Plugin Responsibility |
| **Phase 3** | 🚧 Planned | Framework → Plugin Boundary Analysis |
| **Phase 4** | 🚧 Planned | Scenario Inference & Pattern Detection |
| **Phase 5** | 🚧 Planned | Categorization & Advanced Analysis |
| **Phase 6** | 🚧 Planned | Defensive Gap Assessment |
| **Phase 7** | 🚧 Planned | Final Ownership Summary & Reporting |

**Status**: Phase 1 & 2 Complete ✅ | Next: Phase 3 Boundary Analysis 🚧

For support or questions, please open an issue in this repository.
