# ThreatScanUI/backend/app.py

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import json
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime
import logging
import platform
import sys
import shutil
import tempfile

try:
    from .os_utils import detect_os, get_install_hint_for_os
except ImportError:
    from os_utils import detect_os, get_install_hint_for_os

app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OS_INFO = detect_os()

BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / 'results'
LOGS_DIR = BASE_DIR / 'logs'
TOOLS_DIR = BASE_DIR / 'tools'
SCAN_SCRIPT = BASE_DIR / 'backend' / 'threatscan.py'

RESULTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
TOOLS_DIR.mkdir(exist_ok=True)

active_scans = {}
installation_progress = {}

# Extended tool definitions with proper installation methods
TOOL_DEFINITIONS = {
    # Go-based tools
    'subfinder': {
        'type': 'go',
        'description': 'Fast passive subdomain enumeration tool',
        'install': {
            'go_package': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'verify': 'subfinder -version'
        }
    },
    'httpx': {
        'type': 'go',
        'description': 'Fast HTTP toolkit',
        'install': {
            'go_package': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'verify': 'httpx -version'
        }
    },
    'nuclei': {
        'type': 'go',
        'description': 'Fast vulnerability scanner',
        'install': {
            'go_package': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'verify': 'nuclei -version'
        }
    },
    'assetfinder': {
        'type': 'go',
        'description': 'Find domains and subdomains',
        'install': {
            'go_package': 'github.com/tomnomnom/assetfinder@latest',
            'verify': 'assetfinder --help'
        }
    },
    'waybackurls': {
        'type': 'go',
        'description': 'Fetch URLs from Wayback Machine',
        'install': {
            'go_package': 'github.com/tomnomnom/waybackurls@latest',
            'verify': 'waybackurls -h'
        }
    },
    'gau': {
        'type': 'go',
        'description': 'Get All URLs from multiple sources',
        'install': {
            'go_package': 'github.com/lc/gau/v2/cmd/gau@latest',
            'verify': 'gau --version'
        }
    },
    'hakrawler': {
        'type': 'go',
        'description': 'Web crawler for gathering URLs',
        'install': {
            'go_package': 'github.com/hakluke/hakrawler@latest',
            'verify': 'hakrawler -h'
        }
    },
    'dnsx': {
        'type': 'go',
        'description': 'Fast DNS toolkit',
        'install': {
            'go_package': 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
            'verify': 'dnsx -version'
        }
    },
    'katana': {
        'type': 'go',
        'description': 'Next-generation crawling framework',
        'install': {
            'go_package': 'github.com/projectdiscovery/katana/cmd/katana@latest',
            'verify': 'katana -version'
        }
    },
    
    # Binary downloads
    'findomain': {
        'type': 'binary',
        'description': 'Fast subdomain enumeration tool',
        'install': {
            'linux': {
                'url': 'https://github.com/findomain/findomain/releases/latest/download/findomain-linux',
                'filename': 'findomain',
                'verify': 'findomain --version'
            }
        }
    },
    'amass': {
        'type': 'binary',
        'description': 'In-depth attack surface mapping',
        'install': {
            'linux': {
                'url': 'https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip',
                'filename': 'amass',
                'extract': True,
                'verify': 'amass version'
            }
        }
    },
    
    # Git clone tools
    'subgit': {
        'type': 'git',
        'description': 'Git repository scanner for exposed .git',
        'install': {
            'repo': 'https://github.com/kevzy/subgit.git',
            'script': 'subgit',
            'verify': 'subgit --help || echo "subgit installed"'
        }
    },
    'crtsh': {
        'type': 'git',
        'description': 'Certificate transparency subdomain enum',
        'install': {
            'repo': 'https://github.com/YashGoti/crtsh.git',
            'script': 'crtsh.py',
            'verify': 'python3 $(which crtsh) -h || echo "crtsh installed"'
        }
    },
    
    # Python tools
    'wafw00f': {
        'type': 'pip',
        'description': 'Web Application Firewall detector',
        'install': {
            'package': 'wafw00f',
            'verify': 'wafw00f -h'
        }
    },
    'sublist3r': {
        'type': 'pip',
        'description': 'Fast subdomain enumeration using search engines',
        'install': {
            'package': 'sublist3r',
            'verify': 'sublist3r -h'
        }
    },
    'dnsrecon': {
        'type': 'pip',
        'description': 'DNS enumeration and scanning tool',
        'install': {
            'package': 'dnsrecon',
            'verify': 'dnsrecon -h'
        }
    },
    
    # System packages
    'nmap': {
        'type': 'system',
        'description': 'Network mapper and port scanner',
        'install': {
            'apt': 'nmap',
            'yum': 'nmap',
            'pacman': 'nmap',
            'brew': 'nmap',
            'verify': 'nmap --version'
        }
    },
    'masscan': {
        'type': 'system',
        'description': 'Fast port scanner',
        'install': {
            'apt': 'masscan',
            'yum': 'masscan',
            'pacman': 'masscan',
            'brew': 'masscan',
            'verify': 'masscan --version'
        }
    },
    'whois': {
        'type': 'system',
        'description': 'WHOIS lookup tool',
        'install': {
            'apt': 'whois',
            'yum': 'whois',
            'pacman': 'whois',
            'brew': 'whois',
            'verify': 'whois --version'
        }
    },
    'dig': {
        'type': 'system',
        'description': 'DNS lookup tool',
        'install': {
            'apt': 'dnsutils',
            'yum': 'bind-utils',
            'pacman': 'bind-tools',
            'brew': 'bind',
            'verify': 'dig -v'
        }
    }
}

def find_tool_in_common_paths(tool_name):
    """Check common installation paths for a tool"""
    common_paths = [
        os.path.expanduser('~/go/bin'),
        os.path.expanduser('~/.local/bin'),
        '/usr/local/bin',
        '/usr/bin',
        '/bin',
        '/usr/local/go/bin',
        os.path.expanduser('~/bin'),
        str(TOOLS_DIR),
    ]
    
    try:
        gopath_result = subprocess.run(['go', 'env', 'GOPATH'], 
                                     capture_output=True, text=True, timeout=2)
        if gopath_result.returncode == 0:
            gopath = gopath_result.stdout.strip()
            if gopath:
                common_paths.insert(0, os.path.join(gopath, 'bin'))
    except:
        pass
    
    for path in common_paths:
        tool_path = os.path.join(path, tool_name)
        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
            return tool_path
        
        # Also check with .py extension for Python scripts
        tool_path_py = os.path.join(path, f"{tool_name}.py")
        if os.path.exists(tool_path_py):
            return tool_path_py
    
    tool_location = shutil.which(tool_name)
    if tool_location:
        return tool_location
    
    return None

def install_go_tool(tool_name, package, progress_callback):
    """Install a Go-based tool"""
    progress_callback(f"Installing Go package: {package}")
    
    env = os.environ.copy()
    gopath = subprocess.run(['go', 'env', 'GOPATH'], 
                          capture_output=True, text=True).stdout.strip()
    if gopath:
        gobin = os.path.join(gopath, 'bin')
        env['PATH'] = f"{gobin}:{env.get('PATH', '')}"
        env['GOPATH'] = gopath
    
    cmd = f'go install -v {package}'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, timeout=300)
    
    if result.returncode == 0:
        progress_callback(f"Successfully installed {tool_name}")
        return True
    else:
        progress_callback(f"Failed to install {tool_name}: {result.stderr}")
        return False

def install_binary_tool(tool_name, config, progress_callback):
    """Download and install a binary tool"""
    os_type = 'linux' if OS_INFO['system'] == 'linux' else OS_INFO['system']
    
    if os_type not in config:
        progress_callback(f"No installation config for {os_type}")
        return False
    
    install_config = config[os_type]
    url = install_config['url']
    filename = install_config.get('filename', tool_name)
    
    progress_callback(f"Downloading {tool_name} from {url}")
    
    try:
        # Download to temp directory
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, filename)
        
        cmd = f'curl -L -o {temp_file} {url}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            progress_callback(f"Download failed: {result.stderr}")
            return False
        
        # Handle extraction if needed
        if install_config.get('extract'):
            progress_callback(f"Extracting {filename}")
            if url.endswith('.zip'):
                subprocess.run(f'unzip -o {temp_file} -d {temp_dir}', shell=True)
                # Find the actual binary
                for root, dirs, files in os.walk(temp_dir):
                    if filename in files:
                        temp_file = os.path.join(root, filename)
                        break
        
        # Make executable
        os.chmod(temp_file, 0o755)
        
        # Move to /usr/local/bin
        target = f'/usr/local/bin/{filename}'
        if os.geteuid() == 0:  # Running as root
            shutil.move(temp_file, target)
        else:
            cmd = f'sudo mv {temp_file} {target}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                # Fallback to user directory
                user_bin = os.path.expanduser('~/.local/bin')
                os.makedirs(user_bin, exist_ok=True)
                target = os.path.join(user_bin, filename)
                shutil.move(temp_file, target)
                progress_callback(f"Installed to {target}")
        
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        progress_callback(f"Successfully installed {tool_name}")
        return True
        
    except Exception as e:
        progress_callback(f"Installation error: {str(e)}")
        return False

def install_git_tool(tool_name, config, progress_callback):
    """Clone and install a git-based tool"""
    repo = config['repo']
    script = config.get('script', tool_name)
    
    progress_callback(f"Cloning {repo}")
    
    try:
        # Clone to tools directory
        tool_dir = TOOLS_DIR / tool_name
        if tool_dir.exists():
            shutil.rmtree(tool_dir)
        
        cmd = f'git clone {repo} {tool_dir}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            progress_callback(f"Clone failed: {result.stderr}")
            return False
        
        # Find the script
        script_path = tool_dir / script
        if not script_path.exists():
            # Try to find it
            for file in tool_dir.glob('*'):
                if file.name == script or file.name == f"{script}.sh" or file.name == f"{script}.py":
                    script_path = file
                    break
        
        if not script_path.exists():
            progress_callback(f"Script {script} not found in repository")
            return False
        
        # Make executable
        os.chmod(script_path, 0o755)
        
        # Create symlink in /usr/local/bin or ~/.local/bin
        link_name = tool_name
        if os.geteuid() == 0:
            link_target = f'/usr/local/bin/{link_name}'
        else:
            user_bin = os.path.expanduser('~/.local/bin')
            os.makedirs(user_bin, exist_ok=True)
            link_target = os.path.join(user_bin, link_name)
        
        # Remove existing link if present
        if os.path.exists(link_target):
            os.remove(link_target)
        
        # Create symlink
        os.symlink(script_path, link_target)
        
        progress_callback(f"Successfully installed {tool_name}")
        return True
        
    except Exception as e:
        progress_callback(f"Installation error: {str(e)}")
        return False

def install_pip_tool(tool_name, package, progress_callback):
    """Install a Python pip package"""
    progress_callback(f"Installing Python package: {package}")
    
    # Determine pip command
    pip_cmd = 'pip3' if shutil.which('pip3') else 'pip'
    
    cmd = f'{pip_cmd} install --user {package}'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    
    if result.returncode == 0:
        progress_callback(f"Successfully installed {tool_name}")
        return True
    else:
        progress_callback(f"Failed to install {tool_name}: {result.stderr}")
        return False

def install_system_tool(tool_name, config, progress_callback):
    """Install a system package"""
    pkg_manager = OS_INFO['package_manager']
    
    if pkg_manager not in config:
        progress_callback(f"No package config for {pkg_manager}")
        return False
    
    package = config[pkg_manager]
    progress_callback(f"Installing system package: {package}")
    
    if pkg_manager == 'apt':
        cmds = [
            f'sudo apt update',
            f'sudo apt install -y {package}'
        ]
    elif pkg_manager == 'yum':
        cmds = [f'sudo yum install -y {package}']
    elif pkg_manager == 'pacman':
        cmds = [f'sudo pacman -S --noconfirm {package}']
    elif pkg_manager == 'brew':
        cmds = [f'brew install {package}']
    else:
        progress_callback(f"Unknown package manager: {pkg_manager}")
        return False
    
    for cmd in cmds:
        progress_callback(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            progress_callback(f"Command failed: {result.stderr}")
            return False
    
    progress_callback(f"Successfully installed {tool_name}")
    return True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tools/install/<tool_name>', methods=['POST'])
def install_tool(tool_name):
    if tool_name not in TOOL_DEFINITIONS:
        return jsonify({'error': f'Unknown tool: {tool_name}'}), 400
    
    installation_id = f"{tool_name}_{int(time.time())}"
    installation_progress[installation_id] = {
        'status': 'starting',
        'progress': 0,
        'logs': [],
        'tool': tool_name
    }
    
    thread = threading.Thread(target=run_installation, args=(tool_name, installation_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'status': 'started',
        'installation_id': installation_id,
        'message': f'Installing {tool_name}...'
    })

def run_installation(tool_name, installation_id):
    def log(message):
        installation_progress[installation_id]['logs'].append({
            'time': time.strftime('%H:%M:%S'),
            'message': message
        })
        logger.info(f"[{tool_name}] {message}")
    
    try:
        log(f"Starting installation of {tool_name}")
        tool_def = TOOL_DEFINITIONS[tool_name]
        tool_type = tool_def['type']
        install_config = tool_def['install']
        
        installation_progress[installation_id]['progress'] = 20
        
        success = False
        
        if tool_type == 'go':
            # Check Go installation
            if not shutil.which('go'):
                log("ERROR: Go is not installed. Please run 'Auto Setup Environment' first")
                installation_progress[installation_id]['status'] = 'error'
                return
            
            success = install_go_tool(tool_name, install_config['go_package'], log)
            
        elif tool_type == 'binary':
            success = install_binary_tool(tool_name, install_config, log)
            
        elif tool_type == 'git':
            success = install_git_tool(tool_name, install_config, log)
            
        elif tool_type == 'pip':
            success = install_pip_tool(tool_name, install_config['package'], log)
            
        elif tool_type == 'system':
            success = install_system_tool(tool_name, install_config, log)
        
        installation_progress[installation_id]['progress'] = 80
        
        # Verify installation
        if 'verify' in install_config:
            log("Verifying installation...")
            verify_cmd = install_config.get('verify') or install_config.get('linux', {}).get('verify')
            
            if verify_cmd:
                env = os.environ.copy()
                env['PATH'] = f"{os.path.expanduser('~/.local/bin')}:{os.path.expanduser('~/go/bin')}:{env['PATH']}"
                
                result = subprocess.run(verify_cmd, shell=True, capture_output=True, 
                                      text=True, env=env, timeout=10)
                
                if result.returncode == 0 or 'installed' in result.stdout:
                    log("Verification successful!")
                    success = True
        
        installation_progress[installation_id]['progress'] = 100
        installation_progress[installation_id]['status'] = 'success' if success else 'error'
        
    except Exception as e:
        log(f"ERROR: {str(e)}")
        installation_progress[installation_id]['status'] = 'error'

@app.route('/api/tools/install-progress/<installation_id>')
def get_install_progress(installation_id):
    if installation_id not in installation_progress:
        return jsonify({'error': 'Installation not found'}), 404
    
    return jsonify(installation_progress[installation_id])

@app.route('/api/tools/check')
def check_tools():
    status = {}
    
    for tool_name in TOOL_DEFINITIONS.keys():
        tool_path = find_tool_in_common_paths(tool_name)
        status[tool_name] = tool_path is not None
        if tool_path:
            logger.info(f"Found {tool_name} at: {tool_path}")
    
    gopath = None
    try:
        result = subprocess.run(['go', 'env', 'GOPATH'], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            gopath = result.stdout.strip()
    except:
        pass
    
    path_configured = False
    if gopath:
        gobin = os.path.join(gopath, 'bin')
        path_configured = gobin in os.environ.get('PATH', '')
    
    return jsonify({
        'tools': status,
        'gopath': gopath,
        'path_configured': path_configured,
        'tool_descriptions': {name: info['description'] for name, info in TOOL_DEFINITIONS.items()}
    })

@app.route('/api/tools/list')
def list_tools():
    """List all available tools with their details"""
    tools = []
    for name, info in TOOL_DEFINITIONS.items():
        tool_path = find_tool_in_common_paths(name)
        tools.append({
            'name': name,
            'type': info['type'],
            'description': info['description'],
            'installed': tool_path is not None,
            'path': tool_path
        })
    
    return jsonify({'tools': tools})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target domain is required'}), 400
    
    scan_id = f"scan_{int(time.time())}"
    output_dir = RESULTS_DIR / scan_id
    output_dir.mkdir(exist_ok=True)
    
    config = {
        'target': target,
        'scan_id': scan_id,
        'output_dir': str(output_dir),
        'timeout': data.get('timeout', 300),
        'max_workers': data.get('max_workers', 50),
        'enable_port_scan': data.get('enable_port_scan', True),
        'enable_waf_detection': data.get('enable_waf_detection', True),
        'enable_git_detection': data.get('enable_git_detection', True),
        'enable_vuln_scan': data.get('enable_vuln_scan', True),
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'progress': 0
    }
    
    active_scans[scan_id] = config
    
    with open(output_dir / 'config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    thread = threading.Thread(target=run_scan, args=(scan_id, config))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': f'Scan initiated for {target}'
    })

def run_scan(scan_id, config):
    try:
        cmd = [
            sys.executable,
            str(SCAN_SCRIPT),
            config['target'],
            '-o', config['output_dir'],
            '--timeout', str(config['timeout']),
            '--max-workers', str(config['max_workers'])
        ]
        
        active_scans[scan_id]['status'] = 'running'
        active_scans[scan_id]['progress'] = 10
        
        log_file = LOGS_DIR / f"{scan_id}.log"
        with open(log_file, 'w') as f:
            process = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            while process.poll() is None:
                time.sleep(5)
                if active_scans[scan_id]['progress'] < 90:
                    active_scans[scan_id]['progress'] += 10
            
            if process.returncode == 0:
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['progress'] = 100
                parse_results(scan_id, config)
            else:
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = f'Scan failed with code {process.returncode}'
        
        active_scans[scan_id]['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {e}")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)

def parse_results(scan_id, config):
    try:
        output_dir = Path(config['output_dir'])
        results = {
            'subdomains': [],
            'live_subdomains': [],
            'ips': [],
            'ports': [],
            'vulnerabilities': []
        }
        
        subdomains_file = output_dir / 'subdomains.txt'
        if subdomains_file.exists():
            results['subdomains'] = subdomains_file.read_text().strip().split('\n')
        
        live_file = output_dir / 'live_domains' / 'live_subdomains.txt'
        if live_file.exists():
            results['live_subdomains'] = live_file.read_text().strip().split('\n')
        
        ips_file = output_dir / 'ip_resolution' / 'all_ips.txt'
        if ips_file.exists():
            results['ips'] = ips_file.read_text().strip().split('\n')
        
        summary_file = output_dir / 'recon_summary.json'
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
                active_scans[scan_id]['summary'] = summary
        
        active_scans[scan_id]['results'] = results
        
    except Exception as e:
        logger.error(f"Error parsing results for {scan_id}: {e}")

@app.route('/api/scan/status/<scan_id>')
def scan_status(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = active_scans[scan_id].copy()
    return jsonify(scan_data)

@app.route('/api/scan/list')
def list_scans():
    scans = []
    for scan_id, data in active_scans.items():
        scans.append({
            'scan_id': scan_id,
            'target': data['target'],
            'status': data['status'],
            'start_time': data.get('start_time', ''),
            'progress': data.get('progress', 0)
        })
    return jsonify({'scans': scans})

@app.route('/api/scan/results/<scan_id>')
def get_results(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = active_scans[scan_id]
    if scan_data['status'] != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    return jsonify({
        'scan_id': scan_id,
        'target': scan_data['target'],
        'results': scan_data.get('results', {}),
        'summary': scan_data.get('summary', {})
    })

@app.route('/api/scan/download/<scan_id>/<file_type>')
def download_results(scan_id, file_type):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    output_dir = Path(active_scans[scan_id]['output_dir'])
    
    file_map = {
        'subdomains': output_dir / 'subdomains.txt',
        'live': output_dir / 'live_domains' / 'live_subdomains.txt',
        'ips': output_dir / 'ip_resolution' / 'all_ips.txt',
        'report': output_dir / 'reports' / 'final_recon_report.txt',
        'summary': output_dir / 'recon_summary.json'
    }
    
    if file_type not in file_map:
        return jsonify({'error': 'Invalid file type'}), 400
    
    file_path = file_map[file_type]
    if not file_path.exists():
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(file_path, as_attachment=True)

@app.route('/api/scan/logs/<scan_id>')
def get_logs(scan_id):
    log_file = LOGS_DIR / f"{scan_id}.log"
    if not log_file.exists():
        return jsonify({'error': 'Log file not found'}), 404
    
    logs = log_file.read_text()
    return jsonify({'logs': logs})

@app.route('/api/system/setup-environment', methods=['POST'])
def setup_environment():
    setup_log = []
    
    try:
        go_check = shutil.which('go')
        
        if not go_check:
            setup_log.append("Go not found, installing...")
            
            install_commands = [
                'sudo apt update',
                'sudo apt install -y golang-go'
            ]
            
            for cmd in install_commands:
                setup_log.append(f"Executing: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    setup_log.append(f"Failed: {result.stderr}")
                    return jsonify({
                        'status': 'error',
                        'message': 'Failed to install Go',
                        'log': setup_log
                    }), 500
        else:
            setup_log.append("Go is already installed")
        
        gopath_result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
        gopath = gopath_result.stdout.strip() if gopath_result.returncode == 0 else os.path.expanduser('~/go')
        setup_log.append(f"GOPATH: {gopath}")
        
        os.makedirs(os.path.join(gopath, 'bin'), exist_ok=True)
        os.makedirs(os.path.join(gopath, 'src'), exist_ok=True)
        os.makedirs(os.path.join(gopath, 'pkg'), exist_ok=True)
        
        gobin = os.path.join(gopath, 'bin')
        os.environ['PATH'] = f"{gobin}:{os.environ.get('PATH', '')}"
        os.environ['GOPATH'] = gopath
        
        user_home = os.path.expanduser('~')
        bashrc_path = os.path.join(user_home, '.bashrc')
        
        try:
            with open(bashrc_path, 'r') as f:
                bashrc_content = f.read()
            
            if gobin not in bashrc_content:
                with open(bashrc_path, 'a') as f:
                    f.write(f'\n# Go environment\nexport GOPATH={gopath}\nexport PATH=$PATH:{gobin}\n')
                setup_log.append("Added Go paths to .bashrc")
        except:
            setup_log.append("Could not modify .bashrc")
        
        # Install essential tools
        essential_tools = ['subfinder', 'httpx', 'nuclei', 'assetfinder', 'waybackurls', 'dnsx']
        
        installed_tools = []
        env = os.environ.copy()
        env['PATH'] = f"{gobin}:{env.get('PATH', '')}"
        env['GOPATH'] = gopath
        
        for tool_name in essential_tools:
            if tool_name in TOOL_DEFINITIONS and TOOL_DEFINITIONS[tool_name]['type'] == 'go':
                setup_log.append(f"Installing {tool_name}...")
                package = TOOL_DEFINITIONS[tool_name]['install']['go_package']
                cmd = f'go install -v {package}'
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env=env
                )
                
                if result.returncode == 0:
                    setup_log.append(f"{tool_name} installed")
                    installed_tools.append(tool_name)
                else:
                    setup_log.append(f"{tool_name} failed: {result.stderr[:100]}")
        
        return jsonify({
            'status': 'success',
            'message': 'Environment setup complete',
            'go_installed': True,
            'gopath': gopath,
            'tools_installed': installed_tools,
            'log': setup_log,
            'note': 'Tools are ready. You may need to restart your terminal or run: source ~/.bashrc'
        })
        
    except Exception as e:
        setup_log.append(f"Error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'log': setup_log
        }), 500

@app.route('/api/system/check', methods=['GET'])
def check_system():
    os_info = OS_INFO
    
    system_info = {
        'os': os_info['system'],
        'platform': os_info['platform'],
        'machine': os_info['machine'],
        'is_wsl': os_info['is_wsl'],
        'is_termux': os_info['is_termux'],
        'package_manager': os_info['package_manager'],
        'go_installed': False,
        'go_version': None,
        'gopath': None,
        'python_version': None,
        'pip_installed': False,
        'git_installed': False,
        'curl_installed': False,
        'sudo_available': False,
        'path_configured': False
    }
    
    which_cmd = 'which' if os_info['system'] != 'windows' else 'where'
    
    # Check Go
    go_check = subprocess.run([which_cmd, 'go'], capture_output=True, text=True)
    system_info['go_installed'] = go_check.returncode == 0
    
    if system_info['go_installed']:
        go_version = subprocess.run(['go', 'version'], capture_output=True, text=True)
        system_info['go_version'] = go_version.stdout.strip()
        
        gopath_result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
        if gopath_result.returncode == 0:
            gopath = gopath_result.stdout.strip()
            system_info['gopath'] = gopath
            gobin = os.path.join(gopath, 'bin')
            system_info['path_configured'] = gobin in os.environ.get('PATH', '')
    
    # Check Python
    python_version = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
    system_info['python_version'] = python_version.stdout.strip()
    
    # Check pip
    pip_check = subprocess.run([which_cmd, 'pip'], capture_output=True, text=True)
    system_info['pip_installed'] = pip_check.returncode == 0
    if not system_info['pip_installed']:
        pip3_check = subprocess.run([which_cmd, 'pip3'], capture_output=True, text=True)
        system_info['pip_installed'] = pip3_check.returncode == 0
    
    # Check git
    git_check = subprocess.run([which_cmd, 'git'], capture_output=True, text=True)
    system_info['git_installed'] = git_check.returncode == 0
    
    # Check curl
    curl_check = subprocess.run([which_cmd, 'curl'], capture_output=True, text=True)
    system_info['curl_installed'] = curl_check.returncode == 0
    
    # Check sudo
    if os_info['system'] != 'windows':
        try:
            sudo_check = subprocess.run(['sudo', '-n', 'true'], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True,
                                      timeout=2)
            system_info['sudo_available'] = sudo_check.returncode == 0
        except:
            system_info['sudo_available'] = False
    
    return jsonify(system_info)

@app.route('/api/system/fix-path', methods=['POST'])
def fix_path():
    try:
        os_info = OS_INFO
        user_home = os.path.expanduser('~')
        
        if os_info['system'] == 'windows':
            return jsonify({
                'status': 'manual',
                'message': 'Please add %USERPROFILE%\\go\\bin to your PATH manually'
            })
        
        shell_config = os.path.join(user_home, os_info.get('shell_config', '~/.bashrc').replace('~/', ''))
        gopath = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True).stdout.strip()
        gobin = os.path.join(gopath, 'bin')
        local_bin = os.path.expanduser('~/.local/bin')
        
        path_exports = [
            f'export PATH=$PATH:{gobin}',
            f'export PATH=$PATH:{local_bin}'
        ]
        
        try:
            with open(shell_config, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            content = ''
        
        added = []
        for path_export in path_exports:
            if path_export not in content:
                added.append(path_export)
        
        if added:
            with open(shell_config, 'a') as f:
                f.write('\n# ThreatScan paths\n')
                for export in added:
                    f.write(f'{export}\n')
            
            return jsonify({
                'status': 'success',
                'message': f'Added paths to {shell_config}',
                'action_required': f'Run: source {shell_config} or restart terminal',
                'paths_added': added
            })
        else:
            return jsonify({
                'status': 'already_configured',
                'message': 'Paths already in shell config'
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/bulk', methods=['POST'])
def bulk_scan():
    data = request.json
    targets = data.get('targets', [])
    
    if not targets:
        return jsonify({'error': 'No targets provided'}), 400
    
    scan_ids = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        scan_id = f"scan_{int(time.time())}_{len(scan_ids)}"
        output_dir = RESULTS_DIR / scan_id
        output_dir.mkdir(exist_ok=True)
        
        config = {
            'target': target,
            'scan_id': scan_id,
            'output_dir': str(output_dir),
            'timeout': data.get('timeout', 300),
            'max_workers': data.get('max_workers', 50),
            'enable_port_scan': data.get('enable_port_scan', True),
            'enable_waf_detection': data.get('enable_waf_detection', True),
            'enable_git_detection': data.get('enable_git_detection', True),
            'enable_vuln_scan': data.get('enable_vuln_scan', True),
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'progress': 0
        }
        
        active_scans[scan_id] = config
        
        thread = threading.Thread(target=run_scan, args=(scan_id, config))
        thread.daemon = True
        thread.start()
        
        scan_ids.append(scan_id)
        time.sleep(0.5)
    
    return jsonify({
        'status': 'started',
        'scan_ids': scan_ids,
        'message': f'Started {len(scan_ids)} scans'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)