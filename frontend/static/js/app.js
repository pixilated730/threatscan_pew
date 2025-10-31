// /mnt/e/development/work/Google/ThreatScanUI/frontend/static/js/app.js

const API_BASE = '/api';
let refreshInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    console.log('=== ThreatScan UI Initializing ===');
    console.log('API Base:', API_BASE);
    
    setupEventListeners();
    console.log('✓ Event listeners setup');
    
    // Add delay to ensure backend is ready
    setTimeout(() => {
        checkTools();
        console.log('✓ Tools check initiated');
        
        loadScans();
        console.log('✓ Scans load initiated');
        
        checkSystemRequirements();
        console.log('✓ System check initiated');
    }, 500);
    
    startAutoRefresh();
    console.log('✓ Auto-refresh started');
    
    console.log('=== Initialization Complete ===');
}

function setupEventListeners() {
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }
    
    const checkToolsBtn = document.getElementById('checkToolsBtn');
    if (checkToolsBtn) {
        checkToolsBtn.addEventListener('click', checkTools);
    }
    
    const autoSetupBtn = document.getElementById('autoSetupBtn');
    if (autoSetupBtn) {
        autoSetupBtn.addEventListener('click', autoSetupEnvironment);
    }
    
    const fixPathBtn = document.getElementById('fixPathBtn');
    if (fixPathBtn) {
        fixPathBtn.addEventListener('click', fixPath);
        fixPathBtn.style.display = 'none'; // Hide initially
    }
    
    const refreshScansBtn = document.getElementById('refreshScansBtn');
    if (refreshScansBtn) {
        refreshScansBtn.addEventListener('click', loadScans);
    }
    
    const closeResultsBtn = document.getElementById('closeResultsBtn');
    if (closeResultsBtn) {
        closeResultsBtn.addEventListener('click', closeResults);
    }
    
    const scanMode = document.getElementById('scanMode');
    if (scanMode) {
        scanMode.addEventListener('change', toggleScanMode);
    }
}

async function checkTools() {
    const container = document.getElementById('toolsStatus');
    if (!container) {
        console.error('toolsStatus container not found');
        return;
    }
    
    container.innerHTML = '<div class="loading">Checking tools...</div>';
    
    try {
        console.log('Fetching tools status from:', `${API_BASE}/tools/check`);
        
        const response = await fetch(`${API_BASE}/tools/check`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Response error text:', errorText);
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('Tools data received:', data);
        
        container.innerHTML = '';
        
        // Check if PATH needs fixing
        const fixPathBtn = document.getElementById('fixPathBtn');
        if (!data.path_configured && data.gopath && fixPathBtn) {
            const pathWarning = document.createElement('div');
            pathWarning.className = 'info-banner';
            pathWarning.style.borderColor = 'var(--warning-color)';
            pathWarning.innerHTML = `
                <strong>⚠ PATH Not Configured</strong>
                <br>Go tools are installed in <code>${data.gopath}</code> but not in PATH.
                <br>Click "Fix PATH" button above to configure automatically.
            `;
            container.appendChild(pathWarning);
            
            fixPathBtn.style.display = 'inline-block';
        } else if (fixPathBtn) {
            fixPathBtn.style.display = 'none';
        }
        
        if (!data.tools) {
            console.warn('No tools data in response, using empty object');
            data.tools = {};
        }
        
        const toolsArray = Object.entries(data.tools);
        console.log(`Displaying ${toolsArray.length} tools`);
        
        if (toolsArray.length === 0) {
            container.innerHTML = '<div class="empty-state">No tools detected. Click "Auto Setup Environment" to install.</div>';
            return;
        }
        
        const toolsGrid = document.createElement('div');
        toolsGrid.className = 'tools-grid';
        
        toolsArray.forEach(([tool, available]) => {
            const toolDiv = document.createElement('div');
            toolDiv.className = `tool-item ${available ? 'available' : 'unavailable'}`;
            
            const toolName = document.createElement('div');
            toolName.className = 'tool-name';
            toolName.textContent = tool;
            
            const toolStatus = document.createElement('div');
            toolStatus.className = 'tool-status';
            toolStatus.textContent = available ? 'Available' : 'Not Found';
            
            toolDiv.appendChild(toolName);
            toolDiv.appendChild(toolStatus);
            
            if (!available) {
                const installBtn = document.createElement('button');
                installBtn.className = 'btn-install';
                installBtn.textContent = 'Install';
                installBtn.onclick = () => installTool(tool);
                toolDiv.appendChild(installBtn);
            }
            
            toolsGrid.appendChild(toolDiv);
        });
        
        container.appendChild(toolsGrid);
        console.log('Tools display complete');
        
    } catch (error) {
        console.error('Tools check error:', error);
        console.error('Error stack:', error.stack);
        container.innerHTML = `
            <div class="error-state">
                <p style="color: var(--danger-color);">
                    Error checking tools: ${error.message}
                </p>
                <button onclick="checkTools()" class="btn-install" style="margin-top: 10px;">Retry</button>
                <br><br>
                <small>Check browser console for details</small>
            </div>
        `;
    }
}

async function checkSystemRequirements() {
    try {
        console.log('Checking system requirements...');
        const response = await fetch(`${API_BASE}/system/check`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            console.error('System check failed:', response.status);
            return;
        }
        
        const data = await response.json();
        
        console.group('System Requirements');
        console.log('Go installed:', data.go_installed);
        if (data.go_version) console.log('Go version:', data.go_version);
        if (data.gopath) console.log('GOPATH:', data.gopath);
        console.log('Python version:', data.python_version);
        console.log('Pip installed:', data.pip_installed);
        console.log('Sudo available:', data.sudo_available);
        console.groupEnd();
        
        const banner = document.getElementById('systemInfoBanner');
        if (!banner) {
            console.warn('systemInfoBanner not found');
            return;
        }
        
        if (!data.go_installed) {
            banner.innerHTML = `
                <strong>⚠ Go Not Installed</strong>
                <br>Most security tools require Go language.
                <br>Click <strong>Auto Setup Environment</strong> button above to install automatically.
            `;
            banner.style.borderColor = 'var(--warning-color)';
            showNotification('Go is not installed. Use Auto Setup to install.', 'warning');
        } else {
            banner.innerHTML = `
                <strong>✓ Go Installed</strong> - ${data.go_version}
                <br>GOPATH: <code>${data.gopath}</code>
                <br>You can now install security tools using the Install buttons below.
            `;
            banner.style.borderColor = 'var(--success-color)';
        }
    } catch (error) {
        console.error('Failed to check system requirements:', error);
    }
}

async function loadScans() {
    const container = document.getElementById('scansContainer');
    if (!container) {
        console.error('scansContainer not found');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/scan/list`);
        const data = await response.json();
        
        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<div class="empty-state">No scans yet. Start your first scan above!</div>';
            return;
        }
        
        container.innerHTML = '';
        data.scans.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));
        
        for (const scan of data.scans) {
            const scanDiv = await createScanElement(scan);
            container.appendChild(scanDiv);
        }
    } catch (error) {
        console.error('Failed to load scans:', error);
        container.innerHTML = '<div class="error-state">Failed to load scans</div>';
    }
}

// ... (rest of the functions remain the same)

async function fixPath() {
    showNotification('Fixing PATH configuration...', 'info');
    
    try {
        const response = await fetch(`${API_BASE}/system/fix-path`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            showNotification(`PATH fixed! ${data.action_required}`, 'success');
            console.log('Go bin directory:', data.gobin);
            console.log('Action required:', data.action_required);
            
            const banner = document.getElementById('systemInfoBanner');
            if (banner) {
                banner.innerHTML = `
                    <strong>✓ PATH Configuration Updated</strong>
                    <br>${data.message}
                    <br><strong>Important:</strong> ${data.action_required}
                    <br>Tools are now accessible from: <code>${data.gobin}</code>
                `;
                banner.style.borderColor = 'var(--success-color)';
            }
            
            const fixPathBtn = document.getElementById('fixPathBtn');
            if (fixPathBtn) {
                fixPathBtn.style.display = 'none';
            }
            
            setTimeout(() => {
                checkTools();
            }, 2000);
        } else {
            showNotification(data.message, data.status === 'already_configured' ? 'info' : 'warning');
        }
    } catch (error) {
        showNotification(`PATH fix error: ${error.message}`, 'error');
    }
}

function toggleScanMode() {
    const mode = document.getElementById('scanMode').value;
    const singleGroup = document.getElementById('singleTargetGroup');
    const bulkGroup = document.getElementById('bulkTargetGroup');
    
    if (mode === 'bulk') {
        singleGroup.style.display = 'none';
        bulkGroup.style.display = 'block';
    } else {
        singleGroup.style.display = 'block';
        bulkGroup.style.display = 'none';
    }
}

async function handleScanSubmit(e) {
    e.preventDefault();
    
    const scanMode = document.getElementById('scanMode').value;
    
    if (scanMode === 'bulk') {
        const bulkTargets = document.getElementById('bulkTargets').value;
        const targets = bulkTargets.split('\n').map(t => t.trim()).filter(t => t);
        
        if (targets.length === 0) {
            showNotification('Please enter at least one target', 'error');
            return;
        }
        
        const formData = {
            targets: targets,
            timeout: parseInt(document.getElementById('timeout').value),
            max_workers: parseInt(document.getElementById('maxWorkers').value),
            enable_port_scan: document.getElementById('enablePortScan').checked,
            enable_waf_detection: document.getElementById('enableWafDetection').checked,
            enable_git_detection: document.getElementById('enableGitDetection').checked,
            enable_vuln_scan: document.getElementById('enableVulnScan').checked
        };
        
        try {
            const response = await fetch(`${API_BASE}/scan/bulk`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showNotification(`Started ${targets.length} scans`, 'success');
                document.getElementById('bulkTargets').value = '';
                setTimeout(loadScans, 1000);
            } else {
                showNotification(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            showNotification(`Failed to start scans: ${error.message}`, 'error');
        }
    } else {
        const target = document.getElementById('target').value;
        
        if (!target) {
            showNotification('Please enter a target', 'error');
            return;
        }
        
        const formData = {
            target: target,
            timeout: parseInt(document.getElementById('timeout').value),
            max_workers: parseInt(document.getElementById('maxWorkers').value),
            enable_port_scan: document.getElementById('enablePortScan').checked,
            enable_waf_detection: document.getElementById('enableWafDetection').checked,
            enable_git_detection: document.getElementById('enableGitDetection').checked,
            enable_vuln_scan: document.getElementById('enableVulnScan').checked
        };
        
        try {
            const response = await fetch(`${API_BASE}/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showNotification(`Scan started for ${formData.target}`, 'success');
                document.getElementById('target').value = '';
                setTimeout(loadScans, 1000);
            } else {
                showNotification(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            showNotification(`Failed to start scan: ${error.message}`, 'error');
        }
    }
}

async function installTool(toolName) {
    const toolDiv = event.target.closest('.tool-item');
    const statusDiv = toolDiv.querySelector('.tool-status');
    const originalStatus = statusDiv.textContent;
    const installBtn = event.target;
    
    installBtn.disabled = true;
    installBtn.textContent = 'Installing...';
    statusDiv.textContent = 'Starting...';
    statusDiv.style.color = 'var(--warning-color)';
    
    showNotification(`Installing ${toolName}...`, 'info');
    
    const progressDiv = document.createElement('div');
    progressDiv.className = 'install-progress';
    progressDiv.innerHTML = `
        <div class="progress-bar">
            <div class="progress-fill" style="width: 0%"></div>
        </div>
        <div class="progress-logs"></div>
    `;
    toolDiv.appendChild(progressDiv);
    
    try {
        const response = await fetch(`${API_BASE}/tools/install/${toolName}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'started') {
            const installationId = data.installation_id;
            
            const pollProgress = setInterval(async () => {
                try {
                    const progressResponse = await fetch(`${API_BASE}/tools/install-progress/${installationId}`);
                    const progressData = await progressResponse.json();
                    
                    const progressBar = progressDiv.querySelector('.progress-fill');
                    const logsDiv = progressDiv.querySelector('.progress-logs');
                    
                    progressBar.style.width = `${progressData.progress}%`;
                    statusDiv.textContent = `${progressData.progress}%`;
                    
                    if (progressData.logs && progressData.logs.length > 0) {
                        const latestLogs = progressData.logs.slice(-5);
                        logsDiv.innerHTML = latestLogs.map(log => 
                            `<div class="log-entry">[${log.time}] ${log.message}</div>`
                        ).join('');
                        logsDiv.scrollTop = logsDiv.scrollHeight;
                    }
                    
                    if (progressData.status === 'success') {
                        clearInterval(pollProgress);
                        showNotification(`${toolName} installed successfully!`, 'success');
                        statusDiv.textContent = 'Available';
                        statusDiv.style.color = 'var(--success-color)';
                        installBtn.style.display = 'none';
                        setTimeout(() => {
                            progressDiv.remove();
                            checkTools();
                        }, 3000);
                    } else if (progressData.status === 'error') {
                        clearInterval(pollProgress);
                        showNotification(`${toolName} installation failed`, 'error');
                        statusDiv.textContent = 'Failed';
                        statusDiv.style.color = 'var(--danger-color)';
                        installBtn.disabled = false;
                        installBtn.textContent = 'Retry';
                    } else if (progressData.status === 'warning') {
                        clearInterval(pollProgress);
                        showNotification(`${toolName} installed but verification failed`, 'warning');
                        statusDiv.textContent = 'Installed (PATH issue)';
                        installBtn.style.display = 'none';
                        setTimeout(() => {
                            progressDiv.remove();
                            checkTools();
                        }, 3000);
                    }
                } catch (error) {
                    console.error('Progress poll error:', error);
                }
            }, 1000);
            
            setTimeout(() => {
                clearInterval(pollProgress);
            }, 600000);
            
        } else {
            showNotification(data.message || 'Installation failed to start', 'error');
            statusDiv.textContent = originalStatus;
            installBtn.disabled = false;
            installBtn.textContent = 'Install';
            progressDiv.remove();
        }
    } catch (error) {
        showNotification(`Installation error: ${error.message}`, 'error');
        statusDiv.textContent = originalStatus;
        statusDiv.style.color = 'var(--danger-color)';
        installBtn.disabled = false;
        installBtn.textContent = 'Install';
        if (progressDiv.parentElement) {
            progressDiv.remove();
        }
    }
}

async function autoSetupEnvironment() {
    const setupBtn = document.getElementById('autoSetupBtn');
    const originalText = setupBtn.textContent;
    
    setupBtn.textContent = 'Setting up...';
    setupBtn.disabled = true;
    
    showNotification('Starting automated environment setup. This will take 5-10 minutes...', 'info');
    
    try {
        const response = await fetch(`${API_BASE}/system/setup-environment`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        console.group('Environment Setup Results');
        console.log('Status:', data.status);
        console.log('Go installed:', data.go_installed);
        if (data.gopath) console.log('GOPATH:', data.gopath);
        if (data.tools_installed) console.log('Tools installed:', data.tools_installed);
        if (data.log) {
            console.log('\nSetup Log:');
            data.log.forEach(line => console.log(line));
        }
        console.groupEnd();
        
        if (response.ok && data.status === 'success') {
            showNotification(`Setup complete! Installed: ${data.tools_installed.join(', ')}`, 'success');
            
            const banner = document.getElementById('systemInfoBanner');
            if (banner) {
                banner.innerHTML = `
                    <strong>✓ Environment Ready!</strong>
                    <br>Go installed at: <code>${data.gopath}</code>
                    <br>Tools installed: ${data.tools_installed.join(', ')}
                    <br>${data.note || ''}
                `;
                banner.style.borderColor = 'var(--success-color)';
            }
            
            setTimeout(() => {
                checkTools();
                checkSystemRequirements();
            }, 2000);
        } else {
            showNotification(`Setup failed: ${data.message}`, 'error');
            console.error('Setup log:', data.log || []);
        }
        
    } catch (error) {
        showNotification(`Setup error: ${error.message}`, 'error');
        console.error('Setup exception:', error);
    } finally {
        setupBtn.textContent = originalText;
        setupBtn.disabled = false;
    }
}

async function createScanElement(scan) {
    const scanDiv = document.createElement('div');
    scanDiv.className = 'scan-item';
    scanDiv.id = `scan-${scan.scan_id}`;
    
    try {
        const statusResponse = await fetch(`${API_BASE}/scan/status/${scan.scan_id}`);
        const statusData = await statusResponse.json();
        
        const startTime = new Date(scan.start_time).toLocaleString();
        const progress = statusData.progress || 0;
        
        scanDiv.innerHTML = `
            <div class="scan-header">
                <div class="scan-target">${scan.target}</div>
                <div class="scan-status ${scan.status}">${scan.status}</div>
            </div>
            <div class="scan-info">
                <div class="info-item">Started: <span>${startTime}</span></div>
                <div class="info-item">Scan ID: <span>${scan.scan_id}</span></div>
            </div>
            ${scan.status === 'running' ? `
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${progress}%"></div>
                </div>
            ` : ''}
            <div class="scan-actions">
                ${scan.status === 'completed' ? `
                    <button class="btn btn-small btn-secondary" onclick="viewResults('${scan.scan_id}')">View Results</button>
                    <button class="btn btn-small btn-secondary" onclick="downloadReport('${scan.scan_id}')">Download Report</button>
                ` : ''}
                <button class="btn btn-small" onclick="viewLogs('${scan.scan_id}')">View Logs</button>
            </div>
        `;
    } catch (error) {
        console.error('Error creating scan element:', error);
        scanDiv.innerHTML = `
            <div class="scan-header">
                <div class="scan-target">${scan.target}</div>
                <div class="scan-status error">Error</div>
            </div>
        `;
    }
    
    return scanDiv;
}

async function viewResults(scanId) {
    try {
        const response = await fetch(`${API_BASE}/scan/results/${scanId}`);
        const data = await response.json();
        
        if (!response.ok) {
            showNotification(data.error, 'error');
            return;
        }
        
        displayResults(data);
    } catch (error) {
        showNotification(`Failed to load results: ${error.message}`, 'error');
    }
}

function displayResults(data) {
    const section = document.getElementById('resultsSection');
    const container = document.getElementById('resultsContainer');
    const results = data.results;
    
    container.innerHTML = `
        <div class="results-grid">
            <div class="result-card">
                <div class="result-title">Total Subdomains</div>
                <div class="result-count">${results.subdomains?.length || 0}</div>
            </div>
            <div class="result-card">
                <div class="result-title">Live Subdomains</div>
                <div class="result-count">${results.live_subdomains?.length || 0}</div>
            </div>
            <div class="result-card">
                <div class="result-title">Unique IPs</div>
                <div class="result-count">${results.ips?.length || 0}</div>
            </div>
        </div>
        
        ${results.live_subdomains?.length > 0 ? `
            <div class="result-card">
                <div class="result-title">Live Subdomains</div>
                <div class="result-list">
                    ${results.live_subdomains.map(sub => `<div class="result-item">${sub}</div>`).join('')}
                </div>
            </div>
        ` : ''}
        
        ${results.ips?.length > 0 ? `
            <div class="result-card">
                <div class="result-title">IP Addresses</div>
                <div class="result-list">
                    ${results.ips.map(ip => `<div class="result-item">${ip}</div>`).join('')}
                </div>
            </div>
        ` : ''}
    `;
    
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth' });
}

function closeResults() {
    const section = document.getElementById('resultsSection');
    if (section) {
        section.style.display = 'none';
    }
}

async function downloadReport(scanId) {
    try {
        window.open(`${API_BASE}/scan/download/${scanId}/report`, '_blank');
        showNotification('Downloading report...', 'success');
    } catch (error) {
        showNotification(`Failed to download: ${error.message}`, 'error');
    }
}

async function viewLogs(scanId) {
    try {
        const response = await fetch(`${API_BASE}/scan/logs/${scanId}`);
        const data = await response.json();
        
        if (!response.ok) {
            showNotification(data.error, 'error');
            return;
        }
        
        const logWindow = window.open('', '_blank');
        logWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Scan Logs - ${scanId}</title>
                <style>
                    body { background: #0d1117; color: #c9d1d9; font-family: 'Fira Code', monospace; padding: 20px; margin: 0; }
                    pre { white-space: pre-wrap; word-wrap: break-word; }
                </style>
            </head>
            <body>
                <h2>Scan Logs - ${scanId}</h2>
                <pre>${data.logs}</pre>
            </body>
            </html>
        `);
    } catch (error) {
        showNotification(`Failed to load logs: ${error.message}`, 'error');
    }
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    if (!notification) {
        console.warn('Notification element not found');
        return;
    }
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');
    setTimeout(() => notification.classList.remove('show'), 5000);
}

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        const scansContainer = document.getElementById('scansContainer');
        if (scansContainer && !scansContainer.querySelector('.empty-state')) {
            loadScans();
        }
    }, 10000);
}

window.addEventListener('beforeunload', () => {
    if (refreshInterval) clearInterval(refreshInterval);
});

// Make functions globally accessible for onclick handlers
window.viewResults = viewResults;
window.downloadReport = downloadReport;
window.viewLogs = viewLogs;
window.installTool = installTool;
window.checkTools = checkTools;