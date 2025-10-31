# /mnt/e/development/work/Google/ThreatScanUI/backend/os_utils.py

import platform
import os

def detect_os():
    """Detect operating system and return platform info"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    os_info = {
        'system': system,
        'machine': machine,
        'platform': platform.platform(),
        'version': platform.version(),
        'is_wsl': False,
        'is_termux': False,
        'package_manager': None,
        'shell_config': None
    }
    
    if system == 'linux':
        try:
            with open('/proc/version', 'r') as f:
                version_info = f.read().lower()
                if 'microsoft' in version_info or 'wsl' in version_info:
                    os_info['is_wsl'] = True
        except:
            pass
        
        if os.path.exists('/data/data/com.termux'):
            os_info['is_termux'] = True
            os_info['package_manager'] = 'pkg'
            os_info['shell_config'] = '~/.bashrc'
        else:
            if os.path.exists('/etc/debian_version'):
                os_info['package_manager'] = 'apt'
            elif os.path.exists('/etc/redhat-release'):
                os_info['package_manager'] = 'yum'
            elif os.path.exists('/etc/arch-release'):
                os_info['package_manager'] = 'pacman'
            else:
                os_info['package_manager'] = 'apt'
            os_info['shell_config'] = '~/.bashrc'
    
    elif system == 'darwin':
        os_info['package_manager'] = 'brew'
        os_info['shell_config'] = '~/.zshrc'
    
    elif system == 'windows':
        os_info['package_manager'] = 'choco'
        os_info['shell_config'] = None
    
    return os_info

def get_install_hint_for_os(os_info):
    """Get OS-specific installation hints"""
    hints = {
        'go': {
            'linux': 'sudo apt install golang-go (Debian/Ubuntu) or sudo yum install golang (RedHat/CentOS)',
            'darwin': 'brew install go',
            'windows': 'choco install golang or download from https://golang.org/dl/',
            'termux': 'pkg install golang'
        },
        'path_config': {
            'linux': 'export PATH=$PATH:~/go/bin',
            'darwin': 'export PATH=$PATH:~/go/bin',
            'windows': 'Add %USERPROFILE%\\go\\bin to PATH',
            'termux': 'export PATH=$PATH:~/go/bin'
        }
    }
    
    os_key = 'termux' if os_info['is_termux'] else os_info['system']
    
    return {
        'go_install': hints['go'].get(os_key, 'Visit https://golang.org/dl/'),
        'path_config': hints['path_config'].get(os_key, 'Add Go bin directory to PATH')
    }