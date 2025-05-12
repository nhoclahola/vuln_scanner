/**
 * Scan JavaScript for Vulnerability Scanner
 */

// Global variables
let scanInterval = null;
let scanId = null;
let eventSource = null;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize scan form submission
    initializeScanForm();
    
    // Check for existing scan in progress
    checkExistingScan();
});

/**
 * Initialize scan form submission
 */
function initializeScanForm() {
    const scanForm = document.getElementById('scanForm');
    if (!scanForm) return;
    
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        startScan();
    });
}

/**
 * Start a new vulnerability scan
 */
function startScan() {
    const targetUrl = document.getElementById('targetUrl').value.trim();
    const llmProvider = document.getElementById('llmProvider').value;
    const scanType = document.getElementById('scanType').value;
    
    if (!targetUrl) {
        showAlert('Please enter a target URL', 'danger');
        return;
    }
    
    // Show scan info card and hide placeholder
    document.getElementById('scanPlaceholder').classList.add('d-none');
    document.getElementById('scanInfo').classList.remove('d-none');
    document.getElementById('scanProgress').classList.remove('d-none');
    document.getElementById('scanResults').classList.add('d-none');
    
    // Update UI
    document.getElementById('scanTargetDisplay').textContent = targetUrl;
    document.getElementById('scanTypeDisplay').textContent = scanType;
    document.getElementById('scanStatusDisplay').innerHTML = '<span class="badge bg-primary">Starting</span>';
    document.getElementById('scanElapsedDisplay').textContent = '0s';
    document.getElementById('scanVulnDisplay').textContent = '0';
    
    // Reset progress and output
    updateProgress(0, 'Initializing scan...');
    const terminal = document.getElementById('scanOutput');
    if (terminal) terminal.innerHTML = '';
    
    // In a real application, send an AJAX request to start the scan
    // For demo purposes, we're simulating it
    
    // Show loading state on the button
    const submitButton = document.querySelector('#scanForm button[type="submit"]');
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Simulate API call to start scan
    setTimeout(() => {
        // Generate a random scan ID
        scanId = 'scan_' + Math.random().toString(36).substr(2, 9);
        
        // Update button
        submitButton.disabled = false;
        submitButton.innerHTML = 'Start Scan';
        
        // Update status
        document.getElementById('scanStatusDisplay').innerHTML = '<span class="badge bg-info">Running</span>';
        
        // Start polling for scan status
        startPollingStatus();
        
        // Connect to event stream for live updates
        connectToEventStream();
        
        // Set start time to track elapsed time
        window.scanStartTime = Date.now();
        updateElapsedTime();
        
        // Show message
        appendToTerminal(`[INFO] Starting ${scanType} scan against ${targetUrl}\n`);
        appendToTerminal(`[INFO] Using ${llmProvider} as the LLM provider\n`);
        appendToTerminal(`[INFO] Scan ID: ${scanId}\n`);
        appendToTerminal(`[INFO] Initializing vulnerability scanner...\n`);
        
        // Simulate scan progression
        simulateScanProgression();
    }, 1500);
}

/**
 * Start polling for scan status
 */
function startPollingStatus() {
    // Clear existing interval if any
    if (scanInterval) clearInterval(scanInterval);
    
    // Set up new polling interval (every 2 seconds)
    scanInterval = setInterval(() => {
        // In a real application, this would be an AJAX call to get scan status
        // For demo purposes, we're using the simulated scan state
        
        // Update elapsed time
        updateElapsedTime();
        
        // Check if scan is complete (in our simulation, we'll check a global variable)
        if (window.scanComplete) {
            clearInterval(scanInterval);
            scanInterval = null;
            onScanComplete();
        }
    }, 2000);
}

/**
 * Update elapsed time display
 */
function updateElapsedTime() {
    if (!window.scanStartTime) return;
    
    const elapsed = Math.floor((Date.now() - window.scanStartTime) / 1000);
    document.getElementById('scanElapsedDisplay').textContent = formatDuration(elapsed);
}

/**
 * Connect to event stream for live scan updates
 */
function connectToEventStream() {
    // In a real application, this would connect to a server-sent events endpoint
    // For demo purposes, we're simulating it
    
    // If there's an existing connection, close it
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    
    // Simulate connection
    console.log(`Connected to event stream for scan ${scanId}`);
}

/**
 * Update scan progress
 * @param {number} percent - Progress percentage (0-100)
 * @param {string} message - Progress message
 */
function updateProgress(percent, message) {
    const progressBar = document.getElementById('scanProgressBar');
    const progressText = document.getElementById('scanProgressText');
    
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
        progressBar.setAttribute('aria-valuenow', percent);
    }
    
    if (progressText) {
        progressText.textContent = message;
    }
}

/**
 * Append text to the terminal output
 * @param {string} text - Text to append
 */
function appendToTerminal(text) {
    const terminal = document.getElementById('scanOutput');
    if (!terminal) return;
    
    terminal.innerHTML += text.replace(/\n/g, '<br>');
    terminal.scrollTop = terminal.scrollHeight;
}

/**
 * Handle scan completion
 */
function onScanComplete() {
    // Update status
    document.getElementById('scanStatusDisplay').innerHTML = '<span class="badge bg-success">Completed</span>';
    
    // Show view report button
    document.getElementById('viewReportBtn').classList.remove('d-none');
    
    // Update progress
    updateProgress(100, 'Scan completed successfully');
    
    // Display results
    displayScanResults();
}

/**
 * Display scan results
 */
function displayScanResults() {
    // Show results card
    document.getElementById('scanResults').classList.remove('d-none');
    
    // In a real application, this would fetch results from the server
    // For demo purposes, we're using simulated results
    const results = window.simulatedResults || {
        summary: "No vulnerabilities found.",
        vulnerabilities: []
    };
    
    // Update vulnerability count
    const vulnCount = results.vulnerabilities.length;
    document.getElementById('scanVulnDisplay').textContent = vulnCount;
    
    // Parse and display results
    if (typeof results === 'string') {
        // If results are a string, just display as is
        document.getElementById('summaryTab').innerHTML = `<div class="p-3">${parseMarkdown(results)}</div>`;
        document.getElementById('detailedTab').innerHTML = `<div class="p-3">${parseMarkdown(results)}</div>`;
        document.getElementById('rawTab').innerHTML = `<pre class="p-3"><code>${results}</code></pre>`;
    } else {
        // If results are a JSON object, format appropriately
        
        // Summary tab
        let summaryHtml = `<div class="p-3">
            <h3>Scan Summary</h3>
            <p>${results.summary || 'Scan completed successfully.'}</p>
            <p><strong>Target:</strong> ${document.getElementById('scanTargetDisplay').textContent}</p>
            <p><strong>Scan Type:</strong> ${document.getElementById('scanTypeDisplay').textContent}</p>
            <p><strong>Duration:</strong> ${document.getElementById('scanElapsedDisplay').textContent}</p>
            <p><strong>Vulnerabilities Found:</strong> ${vulnCount}</p>
        `;
        
        if (vulnCount > 0) {
            summaryHtml += '<h4>Vulnerability Summary</h4><ul>';
            results.vulnerabilities.forEach(vuln => {
                const severityClass = getSeverityClass(vuln.severity);
                summaryHtml += `<li><span class="badge ${severityClass}">${vuln.severity}</span> ${vuln.title}</li>`;
            });
            summaryHtml += '</ul>';
        } else {
            summaryHtml += '<div class="alert alert-success">No vulnerabilities were found. Good job!</div>';
        }
        
        summaryHtml += '</div>';
        document.getElementById('summaryTab').innerHTML = summaryHtml;
        
        // Detailed tab
        let detailedHtml = '<div class="p-3">';
        
        if (vulnCount > 0) {
            results.vulnerabilities.forEach((vuln, index) => {
                const severityClass = getSeverityClass(vuln.severity);
                
                detailedHtml += `<div class="card mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <span class="badge ${severityClass} me-2">${vuln.severity}</span>
                            ${vuln.title}
                        </h5>
                        <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" 
                                data-bs-target="#vuln${index}" aria-expanded="true" aria-controls="vuln${index}">
                            Toggle
                        </button>
                    </div>
                    <div class="collapse show" id="vuln${index}">
                        <div class="card-body">
                            <p><strong>Description:</strong> ${vuln.description}</p>
                            ${vuln.location ? `<p><strong>Location:</strong> ${vuln.location}</p>` : ''}
                            ${vuln.evidence ? `<p><strong>Evidence:</strong></p><pre><code>${vuln.evidence}</code></pre>` : ''}
                            ${vuln.recommendation ? `<p><strong>Recommendation:</strong> ${vuln.recommendation}</p>` : ''}
                        </div>
                    </div>
                </div>`;
            });
        } else {
            detailedHtml += '<div class="alert alert-success">No vulnerabilities were found. Good job!</div>';
        }
        
        detailedHtml += '</div>';
        document.getElementById('detailedTab').innerHTML = detailedHtml;
        
        // Raw tab (JSON)
        document.getElementById('rawTab').innerHTML = `<pre class="p-3"><code>${JSON.stringify(results, null, 2)}</code></pre>`;
    }
}

/**
 * Get Bootstrap color class based on severity
 * @param {string} severity - Vulnerability severity
 * @returns {string} CSS class name
 */
function getSeverityClass(severity) {
    severity = severity.toLowerCase();
    
    switch (severity) {
        case 'critical':
            return 'bg-danger';
        case 'high':
            return 'bg-warning text-dark';
        case 'medium':
            return 'bg-info text-dark';
        case 'low':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

/**
 * Check for an existing scan in progress
 */
function checkExistingScan() {
    // In a real application, this would check for an active scan session
    // For demo purposes, we won't implement this
    console.log('Checking for existing scan in progress');
}

/**
 * Show an alert message
 * @param {string} message - Alert message
 * @param {string} type - Alert type (success, danger, warning, info)
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;
    
    const alertId = 'alert-' + Math.random().toString(36).substr(2, 9);
    
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    alertContainer.innerHTML += alertHtml;
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        const alertElement = document.getElementById(alertId);
        if (alertElement) {
            const bsAlert = new bootstrap.Alert(alertElement);
            bsAlert.close();
        }
    }, 5000);
}

/**
 * Download scan report
 * @param {string} format - Report format (json or text)
 */
function downloadReport(format = 'json') {
    // In a real application, this would fetch the report from the server
    // For demo purposes, we're using the simulated results
    
    const results = window.simulatedResults || {
        summary: "No vulnerabilities found.",
        vulnerabilities: []
    };
    
    const target = document.getElementById('scanTargetDisplay').textContent;
    const filename = `vuln_scan_${target.replace(/[^a-z0-9]/gi, '_')}_${new Date().toISOString().split('T')[0]}`;
    
    if (format === 'json') {
        createDownload(`${filename}.json`, JSON.stringify(results, null, 2), 'application/json');
    } else {
        let textReport = `Vulnerability Scan Report
=======================
Target: ${target}
Date: ${new Date().toLocaleString()}
Duration: ${document.getElementById('scanElapsedDisplay').textContent}
Vulnerabilities: ${results.vulnerabilities.length}

Summary:
${results.summary || 'Scan completed successfully.'}

`;

        if (results.vulnerabilities.length > 0) {
            textReport += `\nDetailed Findings:\n`;
            
            results.vulnerabilities.forEach((vuln, index) => {
                textReport += `\n${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.title}\n`;
                textReport += `   Description: ${vuln.description}\n`;
                if (vuln.location) textReport += `   Location: ${vuln.location}\n`;
                if (vuln.evidence) textReport += `   Evidence: ${vuln.evidence}\n`;
                if (vuln.recommendation) textReport += `   Recommendation: ${vuln.recommendation}\n`;
            });
        }
        
        createDownload(`${filename}.txt`, textReport, 'text/plain');
    }
}

/**
 * Simulate scan progression for demo purposes
 */
function simulateScanProgression() {
    // Reset global state
    window.scanComplete = false;
    window.simulatedResults = null;
    
    // Simulate initial discovery phase
    setTimeout(() => {
        updateProgress(10, 'Checking target availability...');
        appendToTerminal(`[INFO] Target is reachable\n`);
        appendToTerminal(`[INFO] Performing initial reconnaissance...\n`);
    }, 2000);
    
    setTimeout(() => {
        updateProgress(20, 'Gathering target information...');
        appendToTerminal(`[INFO] Server identified: Apache/2.4.41\n`);
        appendToTerminal(`[INFO] Technologies detected: PHP 7.4, MySQL, WordPress 5.9.3\n`);
    }, 4000);
    
    setTimeout(() => {
        updateProgress(30, 'Scanning for common vulnerabilities...');
        appendToTerminal(`[INFO] Starting vulnerability analysis\n`);
        appendToTerminal(`[INFO] Checking for XSS vulnerabilities...\n`);
    }, 6000);
    
    setTimeout(() => {
        updateProgress(45, 'Scanning for XSS vulnerabilities...');
        appendToTerminal(`[WARNING] Potential XSS vulnerability found in search parameter\n`);
        appendToTerminal(`[INFO] Checking for SQL injection vulnerabilities...\n`);
        
        // Update vulnerability count
        document.getElementById('scanVulnDisplay').textContent = '1';
    }, 8000);
    
    setTimeout(() => {
        updateProgress(60, 'Scanning for SQL injection vulnerabilities...');
        appendToTerminal(`[INFO] No SQL injection vulnerabilities found\n`);
        appendToTerminal(`[INFO] Checking for CSRF vulnerabilities...\n`);
    }, 10000);
    
    setTimeout(() => {
        updateProgress(75, 'Scanning for CSRF vulnerabilities...');
        appendToTerminal(`[WARNING] CSRF protection missing in form submission\n`);
        appendToTerminal(`[INFO] Checking for security headers...\n`);
        
        // Update vulnerability count
        document.getElementById('scanVulnDisplay').textContent = '2';
    }, 12000);
    
    setTimeout(() => {
        updateProgress(85, 'Checking security headers...');
        appendToTerminal(`[WARNING] Security headers missing: X-Content-Type-Options, X-Frame-Options\n`);
        appendToTerminal(`[INFO] Finalizing scan...\n`);
        
        // Update vulnerability count
        document.getElementById('scanVulnDisplay').textContent = '3';
    }, 14000);
    
    // Complete scan
    setTimeout(() => {
        updateProgress(100, 'Scan completed');
        appendToTerminal(`[INFO] Scan completed successfully\n`);
        appendToTerminal(`[INFO] Total vulnerabilities found: 3\n`);
        
        // Set simulated results
        window.simulatedResults = {
            summary: "Scan completed. Found 3 vulnerabilities in the target application.",
            vulnerabilities: [
                {
                    title: "Cross-Site Scripting (XSS)",
                    severity: "high",
                    description: "The application is vulnerable to Cross-Site Scripting attacks in the search functionality. User input is not properly sanitized before being reflected back to the user.",
                    location: "/search?q=parameter",
                    evidence: "<script>alert('XSS')</script>",
                    recommendation: "Implement proper input validation and output encoding to prevent XSS attacks."
                },
                {
                    title: "Cross-Site Request Forgery (CSRF)",
                    severity: "medium",
                    description: "The application lacks CSRF protection tokens in form submissions, making it vulnerable to CSRF attacks.",
                    location: "/account/update",
                    recommendation: "Implement anti-CSRF tokens for all state-changing operations."
                },
                {
                    title: "Missing Security Headers",
                    severity: "low",
                    description: "The application is missing important security headers that help protect against common web vulnerabilities.",
                    evidence: "X-Content-Type-Options: missing\nX-Frame-Options: missing",
                    recommendation: "Configure the web server to include recommended security headers."
                }
            ]
        };
        
        // Set scan as complete
        window.scanComplete = true;
        onScanComplete();
    }, 16000);
} 