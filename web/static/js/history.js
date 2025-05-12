/**
 * History JavaScript for Vulnerability Scanner
 */

document.addEventListener('DOMContentLoaded', function() {
    // Load scan history
    loadScanHistory();
    
    // Set up refresh button
    const refreshBtn = document.getElementById('refreshHistory');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadScanHistory();
        });
    }
    
    // Check for scan_id parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    if (scanId) {
        loadScanReport(scanId);
    }
});

/**
 * Load scan history
 */
function loadScanHistory() {
    const historyContainer = document.getElementById('scanHistoryList');
    if (!historyContainer) return;
    
    // Show loading indicator
    historyContainer.innerHTML = '<div class="text-center p-3"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">Loading scan history...</p></div>';
    
    // In a real application, fetch scan history from the server
    // For demo purposes, we're simulating it
    
    // Check if we're in demo mode
    if (historyContainer.dataset.demo === 'true') {
        // Demo data already in HTML, just return
        return;
    }
    
    // Simulate loading delay
    setTimeout(() => {
        // Sample data for demonstration
        const scanHistory = [
            { id: 'scan_abcd1234', target: 'https://example.com', date: '2023-07-15T14:30:00', vulnCount: 5, scanType: 'Full Scan' },
            { id: 'scan_efgh5678', target: 'https://test-site.org', date: '2023-07-14T10:15:00', vulnCount: 2, scanType: 'Basic Scan' },
            { id: 'scan_ijkl9012', target: 'https://vulntest.net', date: '2023-07-13T16:45:00', vulnCount: 8, scanType: 'Full Scan' },
            { id: 'scan_mnop3456', target: 'https://securitytest.com', date: '2023-07-12T09:20:00', vulnCount: 0, scanType: 'Basic Scan' },
            { id: 'scan_qrst7890', target: 'https://webtest.io', date: '2023-07-11T11:30:00', vulnCount: 3, scanType: 'Full Scan' }
        ];
        
        if (scanHistory.length === 0) {
            historyContainer.innerHTML = '<div class="alert alert-info m-3">No scan history found. Run a scan to get started.</div>';
            return;
        }
        
        let html = '';
        scanHistory.forEach(scan => {
            const date = new Date(scan.date);
            const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
            
            // Determine status indicator color based on vulnerability count
            let indicatorClass = 'bg-success';
            if (scan.vulnCount > 5) {
                indicatorClass = 'bg-danger';
            } else if (scan.vulnCount > 0) {
                indicatorClass = 'bg-warning';
            }
            
            html += `
                <div class="scan-history-item p-3 border-bottom" data-scan-id="${scan.id}">
                    <div class="d-flex">
                        <div class="scan-indicator ${indicatorClass} me-3"></div>
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${scan.target}</h6>
                            <div class="text-muted small mb-2">${formattedDate} • ${scan.scanType}</div>
                            <div>
                                <span class="badge ${indicatorClass === 'bg-success' ? 'bg-success' : 'bg-warning text-dark'}">${scan.vulnCount} vulnerabilities</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        historyContainer.innerHTML = html;
        
        // Add click event to scan history items
        const historyItems = document.querySelectorAll('.scan-history-item');
        historyItems.forEach(item => {
            item.addEventListener('click', function() {
                const scanId = this.dataset.scanId;
                loadScanReport(scanId);
                
                // Update active state
                historyItems.forEach(i => i.classList.remove('active'));
                this.classList.add('active');
            });
        });
        
        // If there's no selected scan, select the first one
        if (!document.querySelector('.scan-history-item.active') && historyItems.length > 0) {
            historyItems[0].click();
        }
    }, 1000);
}

/**
 * Load scan report for a specific scan
 * @param {string} scanId - Scan ID to load
 */
function loadScanReport(scanId) {
    // Update URL without refreshing page
    const url = new URL(window.location);
    url.searchParams.set('scan_id', scanId);
    window.history.pushState({}, '', url);
    
    // Show loading state
    document.getElementById('scanDetailsContent').innerHTML = '<div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Loading scan details...</p></div>';
    document.getElementById('reportContent').classList.add('d-none');
    
    // Make scan details visible
    document.getElementById('scanDetails').classList.remove('d-none');
    
    // In a real application, fetch scan details from the server
    // For demo purposes, we're simulating it
    
    // Simulate loading delay
    setTimeout(() => {
        // Sample data for demonstration
        const scanDetails = {
            id: scanId,
            target: 'https://example.com',
            date: '2023-07-15T14:30:00',
            scanType: 'Full Scan',
            duration: 134,
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
        
        // Update details section
        const detailsContent = document.getElementById('scanDetailsContent');
        const date = new Date(scanDetails.date);
        const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        
        detailsContent.innerHTML = `
            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Target URL:</strong> <a href="${scanDetails.target}" target="_blank">${scanDetails.target}</a></p>
                            <p><strong>Scan Date:</strong> ${formattedDate}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Scan Type:</strong> ${scanDetails.scanType}</p>
                            <p><strong>Duration:</strong> ${formatDuration(scanDetails.duration)}</p>
                        </div>
                    </div>
                    <div class="d-flex justify-content-between mt-3">
                        <div>
                            <span class="badge bg-${scanDetails.vulnerabilities.length > 0 ? 'warning text-dark' : 'success'}">
                                ${scanDetails.vulnerabilities.length} vulnerabilities found
                            </span>
                        </div>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="downloadReport('${scanId}', 'json')">
                                <i class="bi bi-download"></i> Download JSON
                            </button>
                            <button class="btn btn-sm btn-outline-primary ms-2" onclick="downloadReport('${scanId}', 'text')">
                                <i class="bi bi-download"></i> Download Text
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Show report content
        document.getElementById('reportContent').classList.remove('d-none');
        
        // Update report tabs
        updateReportTabs(scanDetails);
    }, 1000);
}

/**
 * Update report tabs with scan details
 * @param {Object} scanDetails - Scan details object
 */
function updateReportTabs(scanDetails) {
    const summaryTab = document.getElementById('summaryTab');
    const detailedTab = document.getElementById('detailedTab');
    const jsonTab = document.getElementById('jsonTab');
    
    if (!summaryTab || !detailedTab || !jsonTab) return;
    
    // Summary tab
    let summaryHtml = `<div class="p-3">
        <h3>Scan Summary</h3>
        <p>This report summarizes the findings from the vulnerability scan performed on ${scanDetails.target}.</p>
        
        <div class="alert ${scanDetails.vulnerabilities.length > 0 ? 'alert-warning' : 'alert-success'}">
            <strong>${scanDetails.vulnerabilities.length}</strong> vulnerabilities were found during this scan.
        </div>
    `;
    
    if (scanDetails.vulnerabilities.length > 0) {
        // Group vulnerabilities by severity
        const severityGroups = {
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: []
        };
        
        scanDetails.vulnerabilities.forEach(vuln => {
            const severity = vuln.severity.toLowerCase();
            if (severityGroups[severity]) {
                severityGroups[severity].push(vuln);
            } else {
                severityGroups.info.push(vuln);
            }
        });
        
        summaryHtml += '<h4>Vulnerability Breakdown</h4>';
        summaryHtml += '<div class="vulnerability-summary mb-4">';
        
        for (const [severity, vulns] of Object.entries(severityGroups)) {
            if (vulns.length === 0) continue;
            
            const severityClass = getSeverityClass(severity);
            summaryHtml += `
                <div class="severity-group">
                    <div class="severity-badge ${severityClass}">${severity.toUpperCase()}</div>
                    <div class="severity-count">${vulns.length}</div>
                </div>
            `;
        }
        
        summaryHtml += '</div>';
        
        summaryHtml += '<h4>Top Vulnerabilities</h4><ul>';
        scanDetails.vulnerabilities.slice(0, 3).forEach(vuln => {
            const severityClass = getSeverityClass(vuln.severity);
            summaryHtml += `<li><span class="badge ${severityClass}">${vuln.severity.toUpperCase()}</span> ${vuln.title}</li>`;
        });
        summaryHtml += '</ul>';
    } else {
        summaryHtml += '<div class="alert alert-success">No vulnerabilities were found. Good job!</div>';
    }
    
    summaryHtml += '</div>';
    summaryTab.innerHTML = summaryHtml;
    
    // Detailed tab
    let detailedHtml = '<div class="p-3">';
    
    if (scanDetails.vulnerabilities.length > 0) {
        detailedHtml += '<h3>Detailed Findings</h3>';
        
        scanDetails.vulnerabilities.forEach((vuln, index) => {
            const severityClass = getSeverityClass(vuln.severity);
            
            detailedHtml += `<div class="card mb-3">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">
                        <span class="badge ${severityClass} me-2">${vuln.severity.toUpperCase()}</span>
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
    detailedTab.innerHTML = detailedHtml;
    
    // JSON tab
    jsonTab.innerHTML = `<pre class="p-3"><code>${JSON.stringify(scanDetails, null, 2)}</code></pre>`;
}

/**
 * Get severity class for badges
 * @param {string} severity - Vulnerability severity
 * @returns {string} CSS class
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
 * Download report for a specific scan
 * @param {string} scanId - Scan ID
 * @param {string} format - Report format (json or text)
 */
function downloadReport(scanId, format = 'json') {
    // In a real application, this would fetch the report from the server
    // For demo purposes, we're generating a sample report
    
    // Sample data for demonstration
    const scanDetails = {
        id: scanId,
        target: 'https://example.com',
        date: '2023-07-15T14:30:00',
        scanType: 'Full Scan',
        duration: 134,
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
    
    const filename = `vuln_scan_${scanDetails.target.replace(/[^a-z0-9]/gi, '_')}_${new Date(scanDetails.date).toISOString().split('T')[0]}`;
    
    if (format === 'json') {
        createDownload(`${filename}.json`, JSON.stringify(scanDetails, null, 2), 'application/json');
    } else {
        let textReport = `Vulnerability Scan Report
=======================
Target: ${scanDetails.target}
Date: ${new Date(scanDetails.date).toLocaleString()}
Scan Type: ${scanDetails.scanType}
Duration: ${formatDuration(scanDetails.duration)}
Vulnerabilities: ${scanDetails.vulnerabilities.length}

`;

        if (scanDetails.vulnerabilities.length > 0) {
            textReport += `\nDetailed Findings:\n`;
            
            scanDetails.vulnerabilities.forEach((vuln, index) => {
                textReport += `\n${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.title}\n`;
                textReport += `   Description: ${vuln.description}\n`;
                if (vuln.location) textReport += `   Location: ${vuln.location}\n`;
                if (vuln.evidence) textReport += `   Evidence: ${vuln.evidence}\n`;
                if (vuln.recommendation) textReport += `   Recommendation: ${vuln.recommendation}\n`;
            });
        } else {
            textReport += '\nNo vulnerabilities were found. Good job!';
        }
        
        createDownload(`${filename}.txt`, textReport, 'text/plain');
    }
} 