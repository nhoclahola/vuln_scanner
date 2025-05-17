document.addEventListener('DOMContentLoaded', function() {
    // Dark mode toggle functionality
    const darkModeToggle = document.getElementById('darkModeToggle');
    const htmlElement = document.documentElement;
    
    // Check for saved theme preference or use preferred color scheme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        htmlElement.setAttribute('data-theme', savedTheme);
        updateDarkModeIcon(savedTheme === 'dark');
    } else {
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (prefersDarkMode) {
            htmlElement.setAttribute('data-theme', 'dark');
            updateDarkModeIcon(true);
        }
    }
    
    // Toggle dark/light mode
    if (darkModeToggle) { // Check if darkModeToggle exists
        darkModeToggle.addEventListener('click', function() {
            const currentTheme = htmlElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            htmlElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateDarkModeIcon(newTheme === 'dark');
        });
    }
    
    function updateDarkModeIcon(isDark) {
        if (darkModeToggle) { // Check if darkModeToggle exists
            darkModeToggle.innerHTML = isDark ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon"></i>';
        }
    }
    
    // Initialize charts if they exist
    if (typeof initializeCharts === 'function') {
        initializeCharts();
    }
    
    // Scan form initialization is now handled by the inline script in scan.html
    // initializeScanForm(); 
    
    // Load dashboard data if on dashboard page
    if (document.querySelector('.dashboard-container') && typeof loadDashboardData === 'function') {
        loadDashboardData();
    }
    
    // Load history data if on history page
    if (document.querySelector('.history-container') && typeof loadHistoryData === 'function') {
        loadHistoryData();
    }

    const llmSettingsForm = document.getElementById('llmSettingsForm');
    if (llmSettingsForm && typeof saveLLMSettings === 'function') {
        llmSettingsForm.addEventListener('submit', function(event) {
            event.preventDefault();
            saveLLMSettings();
        });
    }
});

// Initialize Charts (Keep this function if used on other pages like dashboard)
function initializeCharts() {
    // Weekly chart
    const weeklyChartEl = document.getElementById('weeklyChart');
    if (weeklyChartEl && typeof Chart !== 'undefined') { // Check for Chart library
        const weeklyCtx = weeklyChartEl.getContext('2d');
        new Chart(weeklyCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [
                    {
                        label: 'High Risk',
                        data: [3, 5, 2, 7, 6, 3, 4],
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    },
                    {
                        label: 'Medium Risk',
                        data: [7, 8, 6, 9, 8, 5, 7],
                        borderColor: '#f39c12',
                        backgroundColor: 'rgba(243, 156, 18, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    },
                    {
                        label: 'Low Risk',
                        data: [12, 15, 11, 13, 15, 10, 12],
                        borderColor: '#2ecc71',
                        backgroundColor: 'rgba(46, 204, 113, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // Monthly chart (similar checks)
    const monthlyChartEl = document.getElementById('monthlyChart');
    if (monthlyChartEl && typeof Chart !== 'undefined') {
        const monthlyCtx = monthlyChartEl.getContext('2d');
        new Chart(monthlyCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [
                    {
                        label: 'High Risk',
                        data: [20, 25, 18, 30, 28, 32],
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    },
                    {
                        label: 'Medium Risk',
                        data: [35, 40, 30, 45, 42, 38],
                        borderColor: '#f39c12',
                        backgroundColor: 'rgba(243, 156, 18, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    },
                    {
                        label: 'Low Risk',
                        data: [60, 70, 55, 75, 65, 72],
                        borderColor: '#2ecc71',
                        backgroundColor: 'rgba(46, 204, 113, 0.1)',
                        borderWidth: 2,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

// Scan functionality
// REMOVE/COMMENT OUT initializeScanForm and startScan as they are now handled by scan.html's inline script
/*
function initializeScanForm() {
    const scanForm = document.getElementById('scanForm');
    if (!scanForm) return;
    
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(scanForm);
        const targetUrl = formData.get('url');
        
        if (!targetUrl) {
            alert('Please enter a URL to scan');
            return;
        }
        
        // Show loading state
        document.getElementById('scanFormContainer').style.display = 'none';
        document.getElementById('scanResults').style.display = 'block';
        document.getElementById('scanProgress').style.width = '0%';
        document.getElementById('scanProgressText').textContent = '0%';
        document.getElementById('consoleOutput').innerHTML = '';
        
        // Start scan
        startScan(formData);
    });
}

function startScan(formData) {
    fetch('/api/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showScanError(data.error);
            return;
        }
        
        const scanId = data.scan_id;
        // The /api/stream endpoint for EventSource was generic. 
        // A scan-specific stream or relying on polling output might be more robust.
        // For now, keeping the old logic if server supports it, but it's a point of potential issue.
        const eventSource = new EventSource('/api/stream'); 
        
        eventSource.addEventListener('message', function(e) {
            const eventData = JSON.parse(e.data); // Renamed to avoid conflict
            if (eventData.scan_id === scanId && eventData.text) {
                appendToConsole(eventData.text);
            }
        });
        
        pollScanStatus(scanId, eventSource);
    })
    .catch(error => {
        showScanError('An error occurred: ' + error.message);
    });
}
*/

// Global function called by scan.html's inline script after successful scan initiation
window.initiateScanMonitoring = function(scanId) {
    console.log(`[main.js] initiateScanMonitoring called for scan ID: ${scanId}`);
    const consoleOutputEl = document.getElementById('consoleOutput');
    if (consoleOutputEl) {
        consoleOutputEl.innerHTML = ''; // Explicitly clear console first
    }
    currentScanLog = null; // Reset cached log to null for a fresh start
    if (statusPollTimeoutId) clearTimeout(statusPollTimeoutId); 

    appendToConsole(`>>> Scan monitoring active via main.js for ID: ${scanId}. Polling status...`);
    pollScanStatus(scanId); 
};

let currentScanLog = null; // Initialize to null; stores RAW log text to detect any byte change
let statusPollTimeoutId = null; // To store timeout for general status polling

function pollScanStatus(scanId) {
    if (statusPollTimeoutId) clearTimeout(statusPollTimeoutId); // Clear previous timeout

    const statusUrl = `/api/scan/${scanId}`;
    console.log(`[main.js] Polling status for ${scanId} from ${statusUrl}`);

    fetch(statusUrl)
        .then(response => {
            if (!response.ok) {
                return response.json().then(errData => {
                    throw new Error(errData.error || `Status poll HTTP ${response.status}`);
                }).catch(() => { throw new Error(`Status poll HTTP ${response.status}`); });
            }
            return response.json();
        })
        .then(data => {
            console.log(`[main.js] Received status for ${scanId}:`, JSON.stringify(data));
            if (data.error) {
                showScanError(data.error);
                updateUIAfterScanEnd(false, scanId, data.result || data.error);
                appendToConsole(`[main.js] Scan ${scanId} error from status: ${data.error}`);
                return;
            }

            updateScanProgress(data.progress);
            fetchAndDisplayLogs(scanId); // Call log fetching

            if (data.status === 'completed' || data.status === 'Completed') {
                console.log(`[main.js] Scan ${scanId} reported as completed.`);
                updateScanProgress(100);
                fetchScanResults(scanId);
                updateUIAfterScanEnd(true, scanId, data.report_file || data.report_json_path || data.report_md_path);
            } else if (data.status === 'failed' || data.status === 'Error') {
                console.log(`[main.js] Scan ${scanId} reported as failed/error. Message: ${data.result}`);
                showScanError(data.result || 'Scan failed or encountered an error.');
                updateUIAfterScanEnd(false, scanId, data.result || 'Scan failed');
                appendToConsole(`Scan status: ${data.status}. Error: ${data.result || 'Unknown scan error'}`);
            } else { // Still running or pending
                console.log(`[main.js] Scan ${scanId} is ${data.status}. Scheduling next poll.`);
                statusPollTimeoutId = setTimeout(() => pollScanStatus(scanId), 3000); // Poll every 3 seconds
            }
        })
        .catch(error => {
            console.error(`[main.js] Error polling scan status for ${scanId}:`, error);
            showScanError('Error polling scan status: ' + error.message);
            updateUIAfterScanEnd(false, scanId, 'Polling error');
            appendToConsole(`[SYSTEM ERROR] Problem polling status: ${error.message}`);
        });
}

function fetchAndDisplayLogs(scanId) {
    console.log(`[main.js] fetchAndDisplayLogs called for scan ID: ${scanId}.`);
    fetch(`/api/scan/${scanId}/output?_=${new Date().getTime()}`) // Cache-busting
        .then(logResponse => {
            if (!logResponse.ok) {
                const errorMsgBase = `Log fetch HTTP ${logResponse.status} for scan ${scanId}`;
                console.error(`[main.js] ${errorMsgBase}`, logResponse);
                return logResponse.text().then(text => {
                    throw new Error(`${errorMsgBase}: ${text || 'Server error details unavailable'}`);
                });
            }
            return logResponse.text(); 
        })
        .then(logText => { 
            console.log(`[main.js] Received raw logText for ${scanId}. Length: ${logText.length}. Preview: "${logText.substring(0, 100).replace(/\n/g, '\\n')}"`);
            const consoleOutputEl = document.getElementById('consoleOutput');
            if (!consoleOutputEl) {
                console.error("[main.js] consoleOutputEl not found! Cannot display logs.");
                return;
            }

            if (logText !== currentScanLog) {
                console.log("[main.js] Raw logText has changed, attempting to update UI console.");
                consoleOutputEl.innerHTML = ''; // Clear previous content
                
                // Diagnostic line to see if this block is reached and console is cleared
                // appendToConsole("---LOG UPDATE CYCLE START---"); 

                const trimmedLogForDisplay = logText.trim(); 
                if (trimmedLogForDisplay) { 
                    trimmedLogForDisplay.split('\n').forEach(line => appendToConsole(line));
                } else {
                    // If the new log (after trim) is empty, console remains cleared.
                    // appendToConsole("[No displayable log content from server]"); // Optional placeholder
                }
                currentScanLog = logText; // Update cache with the new RAW logText
            } else {
                console.log("[main.js] No change in raw logText based on cache, UI console not updated.");
            }
        }).catch(logError => {
            console.error("[main.js] Error fetching or processing scan output:", logError);
            const consoleOutputEl = document.getElementById('consoleOutput');
            if (consoleOutputEl) {
                // Avoid clearing and re-adding if there's an error, just append the error.
                appendToConsole(`[SYSTEM ERROR] Problem fetching/processing logs: ${logError.message}`);
            }
        });
}

function fetchScanResults(scanId) {
    const resultUrl = `/api/scan/${scanId}/result`; // Endpoint should provide final structured result
    appendToConsole(`Fetching final results from: ${resultUrl}`);
    fetch(resultUrl)
        .then(response => {
            if (!response.ok) {
                return response.json().then(errData => {
                    throw new Error(errData.error || `Fetch results: Server returned ${response.status}`);
                }).catch(() => {
                     throw new Error(`Fetch results: Server returned ${response.status}`);
                });
            }
            // Check content type for JSON or Markdown
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.indexOf("application/json") !== -1) {
                return response.json();
            } else {
                return response.text().then(text => ({_isMarkdown: true, content: text})); // Wrap markdown for identification
            }
        })
        .then(data => {
            if (data.error) {
                showScanError(data.error);
                appendToConsole(`Error fetching results: ${data.error}`);
                return;
            }
            // Assuming displayVulnerabilities expects a specific JSON structure
            // If data is markdown, handle differently or adapt displayVulnerabilities
            if (data._isMarkdown) {
                appendToConsole("Received Markdown report. Displaying raw content in results area for now.");
                const vulnResultsEl = document.getElementById('vulnerabilityResults');
                if (vulnResultsEl) {
                    const mdCard = `
                        <div class="card">
                            <div class="card-header">Markdown Report</div>
                            <div class="card-body">
                                <pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(data.content)}</pre>
                            </div>
                        </div>`;
                    vulnResultsEl.innerHTML = mdCard;
                }
            } else {
                 appendToConsole("Processing JSON results for display...");
                 displayVulnerabilities(data); // This function needs to exist and handle the JSON
            }
        })
        .catch(error => {
            showScanError('Error fetching scan results: ' + error.message);
            appendToConsole(`Error fetching results: ${error.message}`);
            console.error("Error in fetchScanResults:", error);
        });
}

function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') {
        return ''; // Explicitly handle null or undefined
    }
    // Convert to string if it's not already a string (e.g., numbers, booleans)
    if (typeof unsafe !== 'string') {
        unsafe = String(unsafe);
    }
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}


function updateScanProgress(progress) {
    const progressEl = document.getElementById('scanProgress');
    const progressTextEl = document.getElementById('scanProgressText');
    if (progressEl && progressTextEl) {
        console.log(`[main.js] updateScanProgress - Received raw progress: "${progress}", type: ${typeof progress}`);
        const p = Math.max(0, Math.min(100, parseInt(progress) || 0)); // Ensure 0-100
        console.log(`[main.js] updateScanProgress - Parsed progress to: ${p}`);
        
        progressEl.style.width = p + '%';
        progressTextEl.textContent = p + '%';
        
        if (p < 100) {
            progressEl.classList.add('progress-bar-animated');
            progressEl.classList.remove('bg-success', 'bg-danger'); // Actively remove final state colors
        } else { // p === 100 (or clamped to 100)
            progressEl.classList.remove('progress-bar-animated');
            // The final color (bg-success or bg-danger) will be set by updateUIAfterScanEnd.
            // No need to add bg-success here as it might conflict if scan reaches 100% then fails.
        }
    } else {
        console.error("[main.js] updateScanProgress - Progress bar elements (scanProgress or scanProgressText) not found.");
    }
}

function appendToConsole(text) {
    const consoleOutputEl = document.getElementById('consoleOutput');
    if (consoleOutputEl && text != null) { // Check if text is not null or undefined
        let sanitizedText = String(text); 
        // Basic ANSI code removal
        sanitizedText = sanitizedText.replace(/\u001b\[\d+(;\d+)*m/g, ''); 
        sanitizedText = sanitizedText.replace(/\u001b\[\d*[a-zA-Z]/g, '');  

        const lineEl = document.createElement('div');
        lineEl.className = 'console-line';
        if (sanitizedText.toLowerCase().includes('agent:') || sanitizedText.toLowerCase().includes('task output:')) {
            lineEl.classList.add('agent-line');
        }
        // Use textContent for security, and trim the individual line
        lineEl.textContent = sanitizedText.trim(); 
        
        // Only append if the trimmed line is not empty, to avoid lots of blank lines
        if (lineEl.textContent) { 
            consoleOutputEl.appendChild(lineEl);
            consoleOutputEl.scrollTop = consoleOutputEl.scrollHeight;
        }
    }
}

function showScanError(errorMessage) {
    const errorEl = document.getElementById('scanError'); // Error display on scan page
    if (errorEl) {
        errorEl.textContent = errorMessage;
        errorEl.style.display = 'block';
    }
    // Also log to browser console for debugging
    console.error("Scan Error:", errorMessage);
    // Optionally update a general status area if one exists outside the scan form
}

// displayVulnerabilities function - this is a complex part and depends heavily on the JSON structure
// The version from main_old.js might need adjustments based on actual report JSON.
// This is a simplified placeholder or should be the one from main_old.js
function displayVulnerabilities(data) {
    const resultsContainer = document.getElementById('vulnerabilityResults');
    if (!resultsContainer) return;

    resultsContainer.innerHTML = ''; // Clear previous results

    let vulnerabilities = [];
    if (data && data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
        vulnerabilities = data.vulnerabilities;
    } else if (data && data.findings && Array.isArray(data.findings)) { // Alternative structure
        vulnerabilities = data.findings;
    } else if (data && Array.isArray(data)) { // If the data itself is an array of vulnerabilities
        vulnerabilities = data;
    }


    if (vulnerabilities.length === 0 && !(data.summary && data.summary.total_vulnerabilities > 0) ) {
         if (data.summary && data.summary.message) {
             resultsContainer.innerHTML = `<div class="alert alert-info">${escapeHtml(data.summary.message)}</div>`;
         } else if (data.message) {
             resultsContainer.innerHTML = `<div class="alert alert-info">${escapeHtml(data.message)}</div>`;
         }
         else {
            resultsContainer.innerHTML = '<div class="alert alert-success">No vulnerabilities detected in the structured report data.</div>';
         }
        return;
    }
    
    const summary = data.summary || {}; // Use summary if available
    let summaryHtml = '<div class="card mb-3"><div class="card-body">';
    summaryHtml += `<h5 class="card-title">Scan Summary</h5>`;
    if(summary.target_url) summaryHtml += `<p class="card-text"><strong>Target:</strong> ${escapeHtml(summary.target_url)}</p>`;
    if(summary.total_vulnerabilities !== undefined) summaryHtml += `<p class="card-text"><strong>Total Vulnerabilities:</strong> ${summary.total_vulnerabilities}</p>`;
    if(summary.critical_count !== undefined) summaryHtml += `<p class="card-text text-danger"><strong>Critical:</strong> ${summary.critical_count}</p>`;
    if(summary.high_count !== undefined) summaryHtml += `<p class="card-text text-warning"><strong>High:</strong> ${summary.high_count}</p>`; // Common color for high
    if(summary.medium_count !== undefined) summaryHtml += `<p class="card-text text-info"><strong>Medium:</strong> ${summary.medium_count}</p>`; // Common color for medium
    if(summary.low_count !== undefined) summaryHtml += `<p class="card-text"><strong>Low:</strong> ${summary.low_count}</p>`;
     if(summary.message) summaryHtml += `<p class="mt-2"><em>${escapeHtml(summary.message)}</em></p>`;
    summaryHtml += '</div></div>';
    resultsContainer.innerHTML += summaryHtml;


    const accordionId = 'vulnerabilitiesAccordion';
    let accordionHtml = `<div class="accordion" id="${accordionId}">`;

    vulnerabilities.forEach((vuln, index) => {
        const itemId = `vuln-item-${index}`;
        const collapseId = `vuln-collapse-${index}`;
        const severity = vuln.severity || 'Unknown';
        const severityClass = getSeverityClass(severity); // Helper for class

        accordionHtml += `
            <div class="accordion-item">
                <h2 class="accordion-header" id="heading-${itemId}">
                    <button class="accordion-button collapsed ${severityClass}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="false" aria-controls="${collapseId}">
                        <strong>${escapeHtml(vuln.name || vuln.type || 'Vulnerability')}</strong> - <span class="badge bg-secondary ms-2">${escapeHtml(severity)}</span>
                         ${vuln.location ? `<small class="ms-auto text-muted pe-2" style="font-size: 0.8em;">${escapeHtml(truncate(vuln.location, 50))}</small>` : ''}
                    </button>
                </h2>
                <div id="${collapseId}" class="accordion-collapse collapse" aria-labelledby="heading-${itemId}" data-bs-parent="#${accordionId}">
                    <div class="accordion-body">
                        <p><strong>Description:</strong> ${escapeHtml(vuln.description || 'N/A')}</p>
                        ${vuln.location ? `<p><strong>Location:</strong> <code style="word-break:break-all;">${escapeHtml(vuln.location)}</code></p>` : ''}
                        ${vuln.parameter ? `<p><strong>Parameter:</strong> <code>${escapeHtml(vuln.parameter)}</code></p>` : ''}
                        ${vuln.cvss_score ? `<p><strong>CVSS Score:</strong> ${escapeHtml(vuln.cvss_score)}</p>` : ''}
                        ${vuln.cve_id ? `<p><strong>CVE ID:</strong> ${escapeHtml(vuln.cve_id)}</p>` : ''}
                        ${vuln.impact ? `<p><strong>Impact:</strong> ${escapeHtml(vuln.impact)}</p>` : ''}
                        ${vuln.remediation || vuln.recommendation ? `<p><strong>Remediation:</strong> ${escapeHtml(vuln.remediation || vuln.recommendation)}</p>` : ''}
                        ${vuln.payload ? `<p><strong>Payload:</strong> <pre style="white-space: pre-wrap; word-break: break-all; background-color: #f0f0f0; padding: 5px; border-radius: 3px;"><code>${escapeHtml(vuln.payload)}</code></pre></p>` : ''}
                        ${vuln.references && vuln.references.length > 0 ? 
                            '<p><strong>References:</strong><ul>' + vuln.references.map(ref => `<li><a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref)}</a></li>`).join('') + '</ul></p>' 
                            : ''
                        }
                    </div>
                </div>
            </div>
        `;
    });
    accordionHtml += '</div>';
    resultsContainer.innerHTML += accordionHtml;
     appendToConsole(`Displayed ${vulnerabilities.length} vulnerabilities.`);
}

function getSeverityClass(severity) {
    severity = String(severity).toLowerCase();
    if (severity === 'critical') return 'text-danger fw-bold'; // Bootstrap 5 text colors
    if (severity === 'high') return 'text-warning';    // More standard high color
    if (severity === 'medium') return 'text-info';
    if (severity === 'low') return 'text-muted';
    return '';
}

function truncate(str, maxLength) {
    if (typeof str !== 'string') return '';
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
}


// --- Dashboard and History specific functions ---
// These should remain as they are, assuming they are called from their respective pages
// and their corresponding HTML elements exist on those pages.

function loadDashboardData() {
    fetch('/api/history?limit=5&status=Completed') // Example: fetch recent completed scans
        .then(response => response.json())
        .then(data => {
            updateRecentScans(data.scans || data); // Adapt based on actual API response structure
        }).catch(error => console.error('Error loading recent scans for dashboard:', error));

    fetch('/api/stats/vulnerability_distribution') // Example endpoint for stats
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data); // This function needs to be created or adapted
        }).catch(error => console.error('Error loading vulnerability distribution for dashboard:', error));
    
    fetch('/api/stats/top_vulnerabilities') // Example endpoint for top vulnerabilities
        .then(response => response.json())
        .then(data => {
           updateTopVulnerabilities(data); // This function needs to be created or adapted
        }).catch(error => console.error('Error loading top vulnerabilities for dashboard:', error));
}

function updateDashboardStats(data) {
    // This function needs to populate charts or stats display on the dashboard
    // For example, if you have a chart for vulnerability distribution:
    const distributionChartEl = document.getElementById('vulnerabilityDistributionChart'); // Assume this ID exists
    if (distributionChartEl && data && typeof Chart !== 'undefined') {
        const ctx = distributionChartEl.getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.labels || ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                datasets: [{
                    label: 'Vulnerability Distribution',
                    data: data.counts || [0,0,0,0,0], // from data.critical, data.high etc.
                    backgroundColor: [
                        'rgba(217, 83, 79, 0.7)', // Critical (red)
                        'rgba(240, 173, 78, 0.7)', // High (orange)
                        'rgba(91, 192, 222, 0.7)', // Medium (blue)
                        'rgba(92, 184, 92, 0.7)',  // Low (green)
                        'rgba(173, 216, 230, 0.7)' // Informational (light blue)
                    ],
                    borderColor: [
                        'rgba(217, 83, 79, 1)',
                        'rgba(240, 173, 78, 1)',
                        'rgba(91, 192, 222, 1)',
                        'rgba(92, 184, 92, 1)',
                        'rgba(173, 216, 230, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Overall Vulnerability Distribution'
                    }
                }
            }
        });
    }
     console.log("Dashboard stats updated (placeholder):", data);
}

function updateRecentScans(scans) {
    const recentScansTableBody = document.querySelector('#recentScansTable tbody'); // Assuming this ID exists
    if (!recentScansTableBody) return;

    recentScansTableBody.innerHTML = ''; // Clear old data
    if (!scans || scans.length === 0) {
        recentScansTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No recent scans found.</td></tr>';
        return;
    }

    scans.slice(0, 5).forEach(scan => { // Display top 5
        const row = recentScansTableBody.insertRow();
        row.insertCell().textContent = scan.id;
        const targetCell = row.insertCell();
        targetCell.innerHTML = `<a href="${escapeHtml(scan.target_url)}" target="_blank">${escapeHtml(truncate(scan.target_url, 40))}</a>`;
        row.insertCell().textContent = new Date(scan.scan_timestamp || scan.timestamp).toLocaleString();
        row.insertCell().innerHTML = `<span class="badge bg-${scan.status === 'Completed' ? 'success' : 'warning'}">${escapeHtml(scan.status)}</span>`;
        const reportCell = row.insertCell();
        if (scan.report_md_path || scan.report_json_path) {
            const reportPath = scan.report_md_path || scan.report_json_path;
            const filename = reportPath.substring(reportPath.lastIndexOf('/') + 1).substring(reportPath.lastIndexOf('\\') + 1);
            reportCell.innerHTML = `<a href="/report/${encodeURIComponent(filename)}" class="btn btn-sm btn-outline-primary">View Report</a>`;
        } else {
            reportCell.textContent = 'N/A';
        }
    });
     console.log("Recent scans updated on dashboard:", scans);
}


function updateTopVulnerabilities(data) {
    // This function would populate a list or chart of top vulnerabilities on the dashboard
    const topVulnsListEl = document.getElementById('topVulnerabilitiesList'); // Assuming this ID
    if (topVulnsListEl && data && data.length > 0) {
        let html = '<ul class="list-group">';
        data.forEach(vuln => {
            html += `<li class="list-group-item d-flex justify-content-between align-items-center">
                        ${escapeHtml(vuln.name)}
                        <span class="badge bg-primary rounded-pill">${vuln.count}</span>
                     </li>`;
        });
        html += '</ul>';
        topVulnsListEl.innerHTML = html;
    } else if (topVulnsListEl) {
         topVulnsListEl.innerHTML = '<p class="text-muted">No vulnerability data to display.</p>';
    }
    console.log("Top vulnerabilities updated (placeholder):", data);
}


function loadHistoryData() {
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            displayHistoryItems(data);
        }).catch(error => {
            console.error('Error loading scan history:', error);
            const historyContainer = document.querySelector('.history-container');
            if (historyContainer) {
                 historyContainer.innerHTML = '<div class="alert alert-danger">Could not load scan history.</div>';
            }
        });
}

function displayHistoryItems(scans) {
    const historyTableBody = document.querySelector('#historyTable tbody'); // Assuming ID historyTable
    if (!historyTableBody) {
        console.error("History table body not found.");
        return;
    }
    historyTableBody.innerHTML = ''; // Clear existing rows

    if (!scans || scans.length === 0) {
        historyTableBody.innerHTML = '<tr><td colspan="7" class="text-center">No scan history found.</td></tr>';
        return;
    }

    scans.forEach(scan => {
        const row = historyTableBody.insertRow();
        row.insertCell().textContent = scan.id;
        
        const targetCell = row.insertCell();
        targetCell.innerHTML = `<a href="${escapeHtml(scan.target_url)}" target="_blank" title="${escapeHtml(scan.target_url)}">${escapeHtml(truncate(scan.target_url,30))}</a>`;
        
        row.insertCell().textContent = escapeHtml(scan.scan_type || 'N/A');
        row.insertCell().textContent = new Date(scan.scan_timestamp || scan.timestamp).toLocaleString(); // Ensure timestamp field is correct
        
        let statusBadge = 'secondary';
        if (scan.status === 'Completed') statusBadge = 'success';
        if (scan.status === 'Error' || scan.status === 'Failed') statusBadge = 'danger';
        if (scan.status === 'Running') statusBadge = 'info progress-bar-striped progress-bar-animated';
        row.insertCell().innerHTML = `<span class="badge bg-${statusBadge}">${escapeHtml(scan.status)}</span>`;

        const duration = scan.duration ? `${scan.duration}s` : (scan.start_time && scan.end_time ? `${Math.round((new Date(scan.end_time) - new Date(scan.start_time))/1000)}s` : 'N/A');
        row.insertCell().textContent = duration;

        const actionsCell = row.insertCell();
        let actionsHtml = '';
        if (scan.report_md_path || scan.report_json_path) {
             const reportPath = scan.report_md_path || scan.report_json_path;
             const filename = reportPath.substring(reportPath.lastIndexOf('/') + 1).substring(reportPath.lastIndexOf('\\') + 1);
             actionsHtml += `<a href="/report/${encodeURIComponent(filename)}" class="btn btn-sm btn-outline-primary me-1" title="View Report"><i class="bi bi-file-earmark-text"></i></a>`;
        } else if (scan.status === 'Completed' || scan.status === 'Error' || scan.status ==='Failed'){
             actionsHtml += `<button class="btn btn-sm btn-outline-secondary me-1" title="Report not available" disabled><i class="bi bi-file-earmark-excel"></i></button>`;
        }
        
        // Add delete button
        actionsHtml += `<button class="btn btn-sm btn-outline-danger" title="Delete Scan ${scan.id}" onclick="deleteScanHistory(${scan.id}, this)"><i class="bi bi-trash"></i></button>`;
        actionsCell.innerHTML = actionsHtml;
    });
}

function deleteScanHistory(scanId, buttonElement) {
    if (!confirm(`Are you sure you want to delete scan history ID ${scanId}? This will also delete associated report files.`)) {
        return;
    }
    fetch(`/api/history/${scanId}`, { method: 'DELETE' })
        .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
        .then(result => {
            if (result.ok) {
                alert(result.data.message || `Scan history ${scanId} deleted.`);
                // Remove row from table or reload history
                if (buttonElement) {
                    buttonElement.closest('tr').remove();
                } else {
                    loadHistoryData(); // Fallback to reload all
                }
            } else {
                alert(`Error deleting scan: ${result.data.error || `Server returned ${result.status}`}`);
            }
        })
        .catch(error => {
            console.error('Error deleting scan history:', error);
            alert('Failed to delete scan history. See console for details.');
        });
}

// Add this if not already present for settings page functionality
function saveLLMSettings() {
    const form = document.getElementById('llmSettingsForm'); // Assuming form ID
    if (!form) return;

    const payload = {
        deepseek_api_key: form.elements['deepseek_api_key'].value,
        deepseek_api_base: form.elements['deepseek_api_base'].value,
        openai_api_key: form.elements['openai_api_key'].value,
        openai_api_base: form.elements['openai_api_base'].value,
    };

    const messageDiv = document.getElementById('settingsMessage'); // For feedback

    fetch('/api/settings/llm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(response => response.json().then(data => ({ ok: response.ok, data })))
    .then(result => {
        if (messageDiv) {
            messageDiv.textContent = result.data.message || result.data.error;
            messageDiv.className = result.ok ? 'alert alert-success' : 'alert alert-danger';
            messageDiv.style.display = 'block';
        }
    })
    .catch(error => {
        if (messageDiv) {
            messageDiv.textContent = 'Error saving settings: ' + error.message;
            messageDiv.className = 'alert alert-danger';
            messageDiv.style.display = 'block';
        }
        console.error("Error saving LLM settings:", error);
    });
}

// Make sure event listener for settings form is added if settings page uses this
document.addEventListener('DOMContentLoaded', function() {
    const llmSettingsForm = document.getElementById('llmSettingsForm');
    if (llmSettingsForm) {
        llmSettingsForm.addEventListener('submit', function(event) {
            event.preventDefault();
            saveLLMSettings();
        });
    }
});

function updateUIAfterScanEnd(isSuccess, scanId, resultPayload) {
    if (statusPollTimeoutId) clearTimeout(statusPollTimeoutId);
    
    const scanProgressEl = document.getElementById('scanProgress');
    const scanProgressTextEl = document.getElementById('scanProgressText');

    if (scanProgressEl) {
        scanProgressEl.classList.remove('progress-bar-animated');
        if (isSuccess) {
            scanProgressEl.style.width = '100%'; // Ensure it's 100% on success
            if(scanProgressTextEl) scanProgressTextEl.textContent = '100%';
            scanProgressEl.classList.remove('bg-danger');
            scanProgressEl.classList.add('bg-success');
        } else {
            // For failures, progress might not be 100%, but bar should reflect error.
            // Width will be whatever it was, or you can set it to 100% too.
            // scanProgressEl.style.width = '100%'; 
            scanProgressEl.classList.remove('bg-success');
            scanProgressEl.classList.add('bg-danger');
        }
    }

    if (isSuccess && resultPayload && (typeof resultPayload === 'string' || (resultPayload.markdown || resultPayload.json))) {
        const reportBtn = document.getElementById('viewReportBtn');
        let reportPath = '';

        if (typeof resultPayload === 'string') { // If resultPayload is just a path string
            reportPath = resultPayload;
        } else if (resultPayload.markdown) {
            reportPath = resultPayload.markdown;
        } else if (resultPayload.json) {
            reportPath = resultPayload.json;
        }
        
        const filename = reportPath.substring(reportPath.lastIndexOf('/') + 1).substring(reportPath.lastIndexOf('\\') + 1);
        if (reportBtn && filename) {
            reportBtn.href = `/report/${encodeURIComponent(filename)}`;
            reportBtn.style.display = 'inline-block';
            appendToConsole(`Scan completed. Report available: ${filename}`);
        }
    } else if (!isSuccess) {
        // Ensure report button is hidden if scan failed or no report
        const reportBtn = document.getElementById('viewReportBtn');
        if(reportBtn) reportBtn.style.display = 'none';
        appendToConsole(`Scan ended. Status: ${typeof resultPayload === 'string' ? resultPayload : 'Failed/Error'}`);
    }
} 