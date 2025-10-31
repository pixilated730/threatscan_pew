# ThreatScan UI

A comprehensive web-based security reconnaissance tool for automated subdomain enumeration, live detection, IP resolution, port scanning, and vulnerability assessment.

## Features

- Subdomain enumeration using multiple tools (subfinder, findomain, assetfinder)
- Live subdomain detection with httpx
- IP resolution and cloud provider detection
- Port scanning with nmap
- WAF detection using wafw00f
- Git exposure detection with subgit
- Vulnerability scanning with nuclei
- Web-based UI for managing scans
- Bulk scanning support
- Real-time progress tracking
- Comprehensive reporting

## Prerequisites

- Python 3.8 or higher
- Go 1.17 or higher (for security tools)
- Linux/Unix-based system (Ubuntu/Debian recommended)
- sudo privileges (for some tools installation)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/ThreatScanUI.git
cd ThreatScanUI
```

### 2. Set up Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Go (if not already installed)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go

# Or download from https://golang.org/dl/
```

### 5. Set up Go environment

```bash
# Add to ~/.bashrc or ~/.zshrc
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Reload shell configuration
source ~/.bashrc
```

### 6. Install security tools

You can either use the auto-setup feature in the web UI or install manually:

#### Option A: Auto-setup via UI
1. Start the application
2. Click "Auto Setup Environment" button in the UI
3. Wait for installation to complete

#### Option B: Manual installation

```bash
# Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hahwul/subgit@latest

# System packages
sudo apt install nmap

# Python tools
pip install wafw00f

# Findomain (download binary)
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O findomain
chmod +x findomain
sudo mv findomain /usr/local/bin/
```

## Usage

### Starting the application

```bash
# Activate virtual environment
source venv/bin/activate

# Run the Flask application
python backend/app.py

# Or using Flask CLI
export FLASK_APP=backend/app.py
flask run --host=0.0.0.0 --port=5000
```

Access the web interface at `http://localhost:5000`

### Running a scan

1. Enter target domain in the scan form
2. Configure scan options:
   - Timeout (seconds)
   - Max workers for threading
   - Enable/disable specific scan modules
3. Click "Start Scan"
4. Monitor progress in real-time
5. View and download results when complete

### Bulk scanning

1. Select "Multiple Targets" from scan mode dropdown
2. Enter domains (one per line)
3. Configure options and start scan
4. Each domain will be scanned separately

## Project Structure

```
ThreatScanUI/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── threatscan.py          # Core scanning engine
│   └── os_utils.py            # OS detection utilities
├── frontend/
│   ├── templates/
│   │   └── index.html         # Main HTML template
│   └── static/
│       ├── css/
│       │   └── style.css      # Application styles
│       └── js/
│           └── app.js         # Frontend JavaScript
├── config/
│   └── settings.py            # Configuration settings
├── results/                   # Scan results directory
├── logs/                      # Application logs
├── requirements.txt           # Python dependencies
└── README.md
```

### File Descriptions

#### Backend

- **app.py**: Flask application with API endpoints for:
  - Tool management (`/api/tools/*`)
  - Scan operations (`/api/scan/*`)
  - System configuration (`/api/system/*`)
  
- **threatscan.py**: Core reconnaissance engine featuring:
  - Asynchronous tool execution
  - Subdomain enumeration
  - Live detection
  - IP resolution with cloud provider detection
  - Port scanning
  - WAF detection
  - Vulnerability scanning
  - Report generation

- **os_utils.py**: Operating system detection and platform-specific configurations

#### Frontend

- **index.html**: Single-page application interface with:
  - Scan configuration form
  - Tool status dashboard
  - Active scans monitoring
  - Results viewer

- **app.js**: Client-side JavaScript handling:
  - API communication
  - Real-time updates
  - Tool installation progress
  - Scan management
  - Results display

- **style.css**: Dark theme styling with cybersecurity aesthetic

## API Endpoints

### Tools Management
- `GET /api/tools/check` - Check installed tools status
- `POST /api/tools/install/<tool_name>` - Install specific tool
- `GET /api/tools/install-progress/<id>` - Get installation progress

### Scanning
- `POST /api/scan/start` - Start single scan
- `POST /api/scan/bulk` - Start multiple scans
- `GET /api/scan/status/<scan_id>` - Get scan status
- `GET /api/scan/list` - List all scans
- `GET /api/scan/results/<scan_id>` - Get scan results
- `GET /api/scan/logs/<scan_id>` - View scan logs
- `GET /api/scan/download/<scan_id>/<type>` - Download results

### System
- `GET /api/system/check` - Check system requirements
- `POST /api/system/setup-environment` - Auto-setup environment
- `POST /api/system/fix-path` - Fix PATH configuration

## Output Structure

Each scan creates a timestamped directory containing:

```
results/
└── example_com_20240101_120000/
    ├── subdomains/             # Subdomain enumeration results
    ├── live_domains/           # Live detection results
    ├── ip_resolution/          # IP addresses and mappings
    ├── ports/                  # Port scan results
    ├── waf_detection/          # WAF detection results
    ├── git_detection/          # Git exposure findings
    ├── vulnerabilities/        # Vulnerability scan results
    ├── reports/                # Comprehensive reports
    └── recon_summary.json      # JSON summary
```

## Security Considerations

- Run in isolated environment for production use
- Some tools require sudo privileges
- Be mindful of rate limits when scanning
- Respect target authorization and scope
- Review tool configurations for your environment

## Troubleshooting

### Tools not detected
- Verify Go installation: `go version`
- Check GOPATH: `go env GOPATH`
- Ensure PATH includes Go bin: `echo $PATH`
- Try manual tool installation

### Scan failures
- Check tool availability in Tools Status
- Verify network connectivity
- Review logs in `logs/` directory
- Ensure sufficient permissions

### PATH issues
- Click "Fix PATH" button in UI
- Or manually add to shell config:
  ```bash
  export PATH=$PATH:~/go/bin
  source ~/.bashrc
  ```

## License

MIT License