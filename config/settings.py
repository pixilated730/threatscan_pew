# /mnt/e/development/work/Google/ThreatScanUI/config/settings.py

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

FLASK_CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': True,
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
}

SCAN_CONFIG = {
    'DEFAULT_TIMEOUT': 300,
    'DEFAULT_MAX_WORKERS': 50,
    'MAX_CONCURRENT_SCANS': 5,
    'RESULTS_RETENTION_DAYS': 30
}

PATHS = {
    'RESULTS_DIR': BASE_DIR / 'results',
    'LOGS_DIR': BASE_DIR / 'logs',
    'SCAN_SCRIPT': BASE_DIR / 'backend' / 'threatscan.py'
}

TOOL_URLS = {
    'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'findomain': 'https://github.com/Findomain/Findomain#installation',
    'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
    'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'nmap': 'sudo apt install nmap',
    'wafw00f': 'pip install wafw00f',
    'subgit': 'go install github.com/hahwul/subgit@latest',
    'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
}