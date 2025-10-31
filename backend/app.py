# /mnt/e/development/work/Google/ThreatScanUI/backend/app.py

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
SCAN_SCRIPT = BASE_DIR / 'backend' / 'threatscan.py'

RESULTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

active_scans = {}
installation_progress = {}

def find_tool_in_common_paths(tool_name):
    """Check common installation paths for a tool"""
    common_paths = [
        os.path.expanduser('~/go/bin'),
        '/usr/local/go/bin',
        '/usr/local/bin',
        '/usr/bin',
        '/bin',
        os.path.expanduser('~/.local/bin'),
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
    
    tool_location = shutil.which(tool_name)
    if tool_location:
        return tool_location
    
    return None

def get_install_commands(tool_name):
    """Get platform-specific installation commands"""
    os_system = OS_INFO['system']
    is_termux = OS_INFO['is_termux']
    pkg_manager = OS_INFO['package_manager']
    
    commands_map = {
        'subfinder': {
            'linux': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
                'verify': 'subfinder -version'
            },
            'darwin': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
                'verify': 'subfinder -version'
            },
            'windows': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
                'verify': 'subfinder -version'
            }
        },
        'httpx': {
            'linux': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'],
                'verify': 'httpx -version'
            },
            'darwin': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'],
                'verify': 'httpx -version'
            },
            'windows': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'],
                'verify': 'httpx -version'
            }
        },
        'nuclei': {
            'linux': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
                'verify': 'nuclei -version'
            },
            'darwin': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
                'verify': 'nuclei -version'
            },
            'windows': {
                'check_go': True,
                'commands': ['go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
                'verify': 'nuclei -version'
            }
        },
        'assetfinder': {
            'linux': {
                'check_go': True,
                'commands': ['go install github.com/tomnomnom/assetfinder@latest'],
                'verify': 'assetfinder --help'
            },
            'darwin': {
                'check_go': True,
                'commands': ['go install github.com/tomnomnom/assetfinder@latest'],
                'verify': 'assetfinder --help'
            },
            'windows': {
                'check_go': True,
                'commands': ['go install github.com/tomnomnom/assetfinder@latest'],
                'verify': 'assetfinder --help'
            }
        },
        'nmap': {
            'linux': {
                'check_go': False,
                'commands': [f'sudo {pkg_manager} update', f'sudo {pkg_manager} install -y nmap'] if not is_termux else ['pkg update', 'pkg install -y nmap'],
                'verify': 'nmap --version'
            },
            'darwin': {
                'check_go': False,
                'commands': ['brew install nmap'],
                'verify': 'nmap --version'
            },
            'windows': {
                'check_go': False,
                'commands': ['choco install nmap -y'],
                'verify': 'nmap --version'
            }
        },
        'findomain': {
            'linux': {
                'check_go': False,
                'commands': [
                    'wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /tmp/findomain',
                    'chmod +x /tmp/findomain',
                    'sudo mv /tmp/findomain /usr/local/bin/findomain' if not is_termux else 'mv /tmp/findomain $PREFIX/bin/findomain'
                ],
                'verify': 'findomain --version'
            },
            'darwin': {
                'check_go': False,
                'commands': ['brew install findomain'],
                'verify': 'findomain --version'
            },
            'windows': {
                'check_go': False,
                'commands': ['choco install findomain -y'],
                'verify': 'findomain --version'
            }
        },
        'wafw00f': {
            'linux': {
                'check_go': False,
                'commands': ['pip3 install wafw00f'] if shutil.which('pip3') else ['pip install wafw00f'],
                'verify': 'wafw00f -h'
            },
            'darwin': {
                'check_go': False,
                'commands': ['pip3 install wafw00f'],
                'verify': 'wafw00f -h'
            },
            'windows': {
                'check_go': False,
                'commands': ['pip install wafw00f'],
                'verify': 'wafw00f -h'
            }
        },
        'subgit': {
            'linux': {
                'check_go': True,
                'commands': ['go install github.com/hahwul/subgit@latest'],
                'verify': 'subgit -h'
            },
            'darwin': {
                'check_go': True,
                'commands': ['go install github.com/hahwul/subgit@latest'],
                'verify': 'subgit -h'
            },
            'windows': {
                'check_go': True,
                'commands': ['go install github.com/hahwul/subgit@latest'],
                'verify': 'subgit -h'
            }
        }
    }
    
    tool_config = commands_map.get(tool_name, {})
    
    if is_termux and tool_name in commands_map:
        return tool_config.get('linux', {})
    
    return tool_config.get(os_system, tool_config.get('linux', {}))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tools/install/<tool_name>', methods=['POST'])
def install_tool(tool_name):
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
        log(f"OS: {OS_INFO['system']} ({OS_INFO['platform']})")
        installation_progress[installation_id]['progress'] = 10
        
        tool_config = get_install_commands(tool_name)
        
        if not tool_config:
            log(f"ERROR: Tool {tool_name} not supported")
            installation_progress[installation_id]['status'] = 'error'
            return
        
        installation_progress[installation_id]['progress'] = 20
        
        if tool_config.get('check_go', False):
            log("Checking for Go installation...")
            go_path = shutil.which('go')
            if not go_path:
                log("ERROR: Go is not installed. Please run 'Auto Setup Environment' first")
                installation_progress[installation_id]['status'] = 'error'
                return
            
            gopath_result = subprocess.run(['go', 'env', 'GOPATH'], 
                                         capture_output=True, text=True)
            if gopath_result.returncode == 0:
                gopath = gopath_result.stdout.strip()
                log(f"GOPATH: {gopath}")
                os.environ['GOPATH'] = gopath
                gobin = os.path.join(gopath, 'bin')
                current_path = os.environ.get('PATH', '')
                if gobin not in current_path:
                    os.environ['PATH'] = f"{gobin}:{current_path}"
        
        installation_progress[installation_id]['progress'] = 30
        
        total_commands = len(tool_config['commands'])
        for idx, cmd in enumerate(tool_config['commands']):
            log(f"Executing [{idx+1}/{total_commands}]: {cmd}")
            
            try:
                env = os.environ.copy()
                
                if tool_config.get('check_go', False):
                    gopath = subprocess.run(['go', 'env', 'GOPATH'], 
                                         capture_output=True, text=True).stdout.strip()
                    if gopath:
                        gobin = os.path.join(gopath, 'bin')
                        env['PATH'] = f"{gobin}:{env.get('PATH', '')}"
                        env['GOPATH'] = gopath
                
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env
                )
                
                stdout, stderr = process.communicate(timeout=300)
                
                progress = 30 + ((idx + 1) / total_commands) * 50
                installation_progress[installation_id]['progress'] = int(progress)
                
                if process.returncode == 0:
                    log(f"✓ Command completed successfully")
                    if stdout.strip():
                        log(f"Output: {stdout.strip()[:200]}")
                else:
                    log(f"✗ Command failed with code {process.returncode}")
                    if stderr.strip():
                        log(f"Error: {stderr.strip()[:200]}")
                    
            except subprocess.TimeoutExpired:
                log(f"✗ Command timed out after 300s")
                installation_progress[installation_id]['status'] = 'error'
                return
            except Exception as e:
                log(f"✗ Command error: {str(e)}")
        
        installation_progress[installation_id]['progress'] = 90
        time.sleep(1)
        
        log(f"Verifying installation...")
        
        tool_path = find_tool_in_common_paths(tool_name)
        
        if tool_path:
            log(f"✓ Tool found at: {tool_path}")
            installation_progress[installation_id]['status'] = 'success'
            installation_progress[installation_id]['progress'] = 100
        else:
            if 'verify' in tool_config:
                verify_cmd = tool_config['verify']
                log(f"Running verify command: {verify_cmd}")
                
                env = os.environ.copy()
                if tool_config.get('check_go', False):
                    gopath = subprocess.run(['go', 'env', 'GOPATH'], 
                                         capture_output=True, text=True).stdout.strip()
                    if gopath:
                        gobin = os.path.join(gopath, 'bin')
                        env['PATH'] = f"{gobin}:{env.get('PATH', '')}"
                
                verify_process = subprocess.run(
                    verify_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=10
                )
                
                if verify_process.returncode == 0:
                    log(f"✓ Verification successful!")
                    installation_progress[installation_id]['status'] = 'success'
                else:
                    log(f"⚠ Tool installed but not in PATH")
                    log(f"You may need to restart your terminal or add Go bin to PATH")
                    installation_progress[installation_id]['status'] = 'warning'
            else:
                log(f"⚠ Could not verify installation")
                installation_progress[installation_id]['status'] = 'warning'
            
            installation_progress[installation_id]['progress'] = 100
            
    except Exception as e:
        log(f"ERROR: {str(e)}")
        installation_progress[installation_id]['status'] = 'error'

@app.route('/api/tools/install-progress/<installation_id>')
def get_install_progress(installation_id):
    if installation_id not in installation_progress:
        return jsonify({'error': 'Installation not found'}), 404
    
    return jsonify(installation_progress[installation_id])

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

@app.route('/api/tools/check')
def check_tools():
    tools = ['subfinder', 'findomain', 'assetfinder', 'httpx', 'nmap', 'wafw00f', 'subgit', 'nuclei']
    status = {}
    
    gopath = None
    try:
        result = subprocess.run(['go', 'env', 'GOPATH'], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            gopath = result.stdout.strip()
    except:
        pass
    
    for tool in tools:
        tool_path = find_tool_in_common_paths(tool)
        status[tool] = tool_path is not None
        
        if tool_path:
            logger.info(f"Found {tool} at: {tool_path}")
    
    path_configured = False
    if gopath:
        gobin = os.path.join(gopath, 'bin')
        path_configured = gobin in os.environ.get('PATH', '')
    
    return jsonify({
        'tools': status,
        'gopath': gopath,
        'path_configured': path_configured
    })

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
        
        essential_tools = {
            'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'assetfinder': 'github.com/tomnomnom/assetfinder@latest'
        }
        
        installed_tools = []
        env = os.environ.copy()
        env['PATH'] = f"{gobin}:{env.get('PATH', '')}"
        env['GOPATH'] = gopath
        
        for tool_name, package in essential_tools.items():
            setup_log.append(f"Installing {tool_name}...")
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
                setup_log.append(f"✓ {tool_name} installed")
                installed_tools.append(tool_name)
            else:
                setup_log.append(f"✗ {tool_name} failed: {result.stderr[:100]}")
        
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
        'sudo_available': False,
        'path_configured': False
    }
    
    which_cmd = 'which' if os_info['system'] != 'windows' else 'where'
    
    # Check Go installation
    try:
        go_check = subprocess.run([which_cmd, 'go'], capture_output=True, text=True, timeout=2)
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
    except Exception as e:
        logger.error(f"Error checking Go: {e}")
    
    # Check Python version
    try:
        python_version = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
        system_info['python_version'] = python_version.stdout.strip()
    except Exception as e:
        logger.error(f"Error checking Python: {e}")
    
    # Check pip installation
    try:
        pip_check = subprocess.run([which_cmd, 'pip'], capture_output=True, text=True, timeout=2)
        system_info['pip_installed'] = pip_check.returncode == 0
        
        if not system_info['pip_installed']:
            # Also check for pip3
            pip3_check = subprocess.run([which_cmd, 'pip3'], capture_output=True, text=True, timeout=2)
            system_info['pip_installed'] = pip3_check.returncode == 0
    except Exception as e:
        logger.error(f"Error checking pip: {e}")
    
    # Check sudo availability (Linux/Mac only)
    if os_info['system'] != 'windows':
        try:
            # Fix: Remove stderr=subprocess.DEVNULL when using capture_output=True
            sudo_check = subprocess.run(['sudo', '-n', 'true'], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True,
                                      timeout=2)
            system_info['sudo_available'] = sudo_check.returncode == 0
        except Exception as e:
            logger.debug(f"Error checking sudo: {e}")
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
        path_export = f'export PATH=$PATH:{gobin}'
        
        try:
            with open(shell_config, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            content = ''
        
        if gobin not in content:
            with open(shell_config, 'a') as f:
                f.write(f'\n# Go binaries path (added by ThreatScan UI)\n{path_export}\n')
            
            return jsonify({
                'status': 'success',
                'message': f'Added Go path to {shell_config}',
                'action_required': f'Run: source {shell_config} or restart terminal',
                'gobin': gobin
            })
        else:
            return jsonify({
                'status': 'already_configured',
                'message': 'Go path already in shell config',
                'gobin': gobin
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