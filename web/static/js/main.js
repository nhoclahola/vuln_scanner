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
    darkModeToggle.addEventListener('click', function() {
        const currentTheme = htmlElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        htmlElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateDarkModeIcon(newTheme === 'dark');
    });
    
    function updateDarkModeIcon(isDark) {
        if (isDark) {
            darkModeToggle.innerHTML = '<i class="bi bi-sun"></i>';
        } else {
            darkModeToggle.innerHTML = '<i class="bi bi-moon"></i>';
        }
    }
    
    // Initialize charts if they exist
    initializeCharts();
    
    // Initialize scan form if it exists
    initializeScanForm();
    
    // Load dashboard data if on dashboard page
    if (document.querySelector('.dashboard-container')) {
        loadDashboardData();
    }
    
    // Load history data if on history page
    if (document.querySelector('.history-container')) {
        loadHistoryData();
    }
});

// Initialize Charts
function initializeCharts() {
    // Weekly chart
    const weeklyChartEl = document.getElementById('weeklyChart');
    if (weeklyChartEl) {
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
    
    // Monthly chart
    const monthlyChartEl = document.getElementById('monthlyChart');
    if (monthlyChartEl) {
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
        const eventSource = new EventSource('/api/stream');
        
        // Listen for scan updates
        eventSource.addEventListener('message', function(e) {
            const data = JSON.parse(e.data);
            
            // If this message is for our scan
            if (data.scan_id === scanId) {
                appendToConsole(data.text);
            }
        });
        
        // Poll for scan status
        pollScanStatus(scanId, eventSource);
    })
    .catch(error => {
        showScanError('An error occurred: ' + error.message);
    });
}

function pollScanStatus(scanId, eventSource) {
    const statusUrl = `/api/scan/${scanId}`;
    
    fetch(statusUrl)
        .then(response => response.json())
        .then(data => {
            updateScanProgress(data.progress);
            
            if (data.status === 'completed') {
                // Scan completed
                eventSource.close();
                fetchScanResults(scanId);
            } else if (data.status === 'error') {
                // Scan error
                eventSource.close();
                showScanError('An error occurred during the scan');
            } else {
                // Poll again after 2 seconds
                setTimeout(() => pollScanStatus(scanId, eventSource), 2000);
            }
        })
        .catch(error => {
            eventSource.close();
            showScanError('Error checking scan status: ' + error.message);
        });
}

function fetchScanResults(scanId) {
    fetch(`/api/scan/${scanId}/result`)
        .then(response => response.json())
        .then(data => {
            // Update UI with scan results
            document.getElementById('scanProgressText').textContent = 'Scan Complete';
            
            if (data.report_file) {
                const viewReportBtn = document.getElementById('viewReportBtn');
                viewReportBtn.href = `/report/${data.report_file}`;
                viewReportBtn.style.display = 'inline-block';
            }
            
            // Display vulnerability results
            displayVulnerabilities(data.result);
        })
        .catch(error => {
            showScanError('Error fetching scan results: ' + error.message);
        });
}

function updateScanProgress(progress) {
    document.getElementById('scanProgress').style.width = `${progress}%`;
    document.getElementById('scanProgressText').textContent = `${progress}%`;
}

function appendToConsole(text) {
    const consoleOutput = document.getElementById('consoleOutput');
    if (!consoleOutput) return;
    
    // Parse ANSI escape codes using the ansiParser
    const formattedText = window.ansiParser ? window.ansiParser.parse(text) : text;
    
    const line = document.createElement('div');
    line.className = 'console-line';
    line.innerHTML = formattedText;
    consoleOutput.appendChild(line);
    
    // Auto-scroll to bottom
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

function showScanError(errorMessage) {
    document.getElementById('scanError').textContent = errorMessage;
    document.getElementById('scanError').style.display = 'block';
    document.getElementById('scanFormContainer').style.display = 'block';
    document.getElementById('scanResults').style.display = 'none';
}

function displayVulnerabilities(vulnerabilities) {
    const resultsContainer = document.getElementById('vulnerabilityResults');
    resultsContainer.innerHTML = '';
    
    if (!vulnerabilities || Object.keys(vulnerabilities).length === 0) {
        resultsContainer.innerHTML = '<div class="alert alert-success">No vulnerabilities found!</div>';
        return;
    }
    
    // Create summary card
    const summaryCard = document.createElement('div');
    summaryCard.className = 'card mb-4';
    summaryCard.innerHTML = `
        <div class="card-header">
            <h5 class="card-title">Vulnerability Summary</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-icon" style="background-color: rgba(231, 76, 60, 0.1);">
                            <i class="bi bi-exclamation-triangle" style="color: #e74c3c;"></i>
                        </div>
                        <div class="stat-details">
                            <p class="stat-title">High Risk</p>
                            <h3 class="stat-value" id="highRiskCount">0</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-icon" style="background-color: rgba(243, 156, 18, 0.1);">
                            <i class="bi bi-exclamation-circle" style="color: #f39c12;"></i>
                        </div>
                        <div class="stat-details">
                            <p class="stat-title">Medium Risk</p>
                            <h3 class="stat-value" id="mediumRiskCount">0</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-icon" style="background-color: rgba(46, 204, 113, 0.1);">
                            <i class="bi bi-info-circle" style="color: #2ecc71;"></i>
                        </div>
                        <div class="stat-details">
                            <p class="stat-title">Low Risk</p>
                            <h3 class="stat-value" id="lowRiskCount">0</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-icon" style="background-color: rgba(52, 152, 219, 0.1);">
                            <i class="bi bi-info" style="color: #3498db;"></i>
                        </div>
                        <div class="stat-details">
                            <p class="stat-title">Information</p>
                            <h3 class="stat-value" id="infoCount">0</h3>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    resultsContainer.appendChild(summaryCard);
    
    // Add vulnerability list
    const vulnerabilityList = document.createElement('div');
    vulnerabilityList.className = 'vulnerability-list';
    
    // Count vulnerabilities by severity
    let highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0;
    
    // Display each vulnerability
    for (const category in vulnerabilities) {
        if (category === 'summary' || category === 'metadata') continue;
        
        const categoryIssues = vulnerabilities[category];
        if (!Array.isArray(categoryIssues) || categoryIssues.length === 0) continue;
        
        // Add category header
        const categoryHeader = document.createElement('h4');
        categoryHeader.className = 'mt-4 mb-3';
        categoryHeader.textContent = formatCategoryName(category);
        vulnerabilityList.appendChild(categoryHeader);
        
        // Add each vulnerability in the category
        categoryIssues.forEach(vuln => {
            // Count by severity
            if (vuln.severity === 'high') highCount++;
            else if (vuln.severity === 'medium') mediumCount++;
            else if (vuln.severity === 'low') lowCount++;
            else infoCount++;
            
            const vulnItem = document.createElement('div');
            vulnItem.className = 'vulnerability-item';
            
            // Create severity badge
            const severityClass = getSeverityClass(vuln.severity);
            const severityBadge = `<span class="badge ${severityClass}">${vuln.severity.toUpperCase()}</span>`;
            
            vulnItem.innerHTML = `
                <div class="vulnerability-header">
                    <h5 class="vulnerability-title">${vuln.name || 'Unnamed Vulnerability'}</h5>
                    ${severityBadge}
                </div>
                <p class="vulnerability-description">${vuln.description || 'No description provided'}</p>
                ${vuln.details ? `<div class="vulnerability-details">${formatDetails(vuln.details)}</div>` : ''}
                ${vuln.remediation ? `
                    <div class="mt-3">
                        <h6>Remediation:</h6>
                        <p>${vuln.remediation}</p>
                    </div>
                ` : ''}
            `;
            
            vulnerabilityList.appendChild(vulnItem);
        });
    }
    
    resultsContainer.appendChild(vulnerabilityList);
    
    // Update summary counts
    document.getElementById('highRiskCount').textContent = highCount;
    document.getElementById('mediumRiskCount').textContent = mediumCount;
    document.getElementById('lowRiskCount').textContent = lowCount;
    document.getElementById('infoCount').textContent = infoCount;
}

function formatCategoryName(category) {
    return category
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'high': return 'risk-high';
        case 'medium': return 'risk-medium';
        case 'low': return 'risk-low';
        default: return 'risk-info';
    }
}

function formatDetails(details) {
    // If details is a string, return it with line breaks converted to <br>
    if (typeof details === 'string') {
        return details.replace(/\n/g, '<br>');
    }
    
    // If details is an object, format as JSON
    return `<pre>${JSON.stringify(details, null, 2)}</pre>`;
}

// Load dashboard data
function loadDashboardData() {
    // Fetch scan history
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data);
            updateRecentScans(data);
        })
        .catch(error => {
            console.error('Error loading dashboard data:', error);
        });
        
    // Fetch report data
    fetch('/api/reports')
        .then(response => response.json())
        .then(data => {
            updateTopVulnerabilities(data);
        })
        .catch(error => {
            console.error('Error loading report data:', error);
        });
}

function updateDashboardStats(data) {
    if (!data || !Array.isArray(data)) return;
    
    // Total scans
    const totalScans = data.length;
    const totalScansElement = document.getElementById('total-scans');
    if (totalScansElement) totalScansElement.textContent = totalScans;
    
    // Calculate average scan time
    let totalScanTime = 0;
    let validScans = 0;
    
    data.forEach(scan => {
        if (scan.duration && scan.duration !== 'N/A') {
            const durationParts = scan.duration.split(':');
            const minutes = parseInt(durationParts[0]) * 60 + parseInt(durationParts[1]);
            totalScanTime += minutes;
            validScans++;
        }
    });
    
    const avgScanTime = validScans > 0 ? Math.round(totalScanTime / validScans) : 0;
    const avgScanTimeElement = document.getElementById('avg-scan-time');
    if (avgScanTimeElement) {
        avgScanTimeElement.textContent = `${Math.floor(avgScanTime / 60)}:${(avgScanTime % 60).toString().padStart(2, '0')}`;
    }
}

function updateRecentScans(data) {
    if (!data || !Array.isArray(data)) return;
    
    const recentScansContainer = document.getElementById('recent-scans-list');
    if (!recentScansContainer) return;
    
    // Clear loading indicator
    recentScansContainer.innerHTML = '';
    
    // Get 5 most recent scans
    const recentScans = data.slice(0, 5);
    
    if (recentScans.length === 0) {
        recentScansContainer.innerHTML = '<p class="text-center text-muted">No scans yet</p>';
        return;
    }
    
    recentScans.forEach(scan => {
        const scanItem = document.createElement('div');
        scanItem.className = 'recent-scan-item p-2 border-bottom';
        
        scanItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1 text-truncate" style="max-width: 200px;">${scan.url}</h6>
                    <p class="small text-muted mb-0">${scan.time}</p>
                </div>
                <a href="/report/${scan.report_file}" class="btn btn-sm btn-outline-primary">View</a>
            </div>
        `;
        
        recentScansContainer.appendChild(scanItem);
    });
}

function updateTopVulnerabilities(data) {
    if (!data || !Array.isArray(data)) return;
    
    const tableBody = document.querySelector('#top-vulnerabilities-table tbody');
    if (!tableBody) return;
    
    // Clear loading indicator
    tableBody.innerHTML = '';
    
    // Extract all vulnerabilities from all reports
    const allVulnerabilities = [];
    data.forEach(report => {
        if (report.file && report.file.endsWith('.json')) {
            fetch(`/api/report/${report.file}`)
                .then(response => response.json())
                .then(reportData => {
                    // Process the report data to extract vulnerabilities
                    for (const category in reportData) {
                        if (category === 'summary' || category === 'metadata') continue;
                        
                        const categoryIssues = reportData[category];
                        if (Array.isArray(categoryIssues)) {
                            categoryIssues.forEach(vuln => {
                                allVulnerabilities.push({
                                    type: vuln.name || category,
                                    severity: vuln.severity || 'info'
                                });
                            });
                        }
                    }
                    
                    // Now count vulnerabilities by type
                    const vulnCounts = {};
                    allVulnerabilities.forEach(vuln => {
                        if (!vulnCounts[vuln.type]) {
                            vulnCounts[vuln.type] = {
                                count: 0,
                                severity: vuln.severity
                            };
                        }
                        vulnCounts[vuln.type].count++;
                    });
                    
                    // Convert to array and sort by count
                    const vulnArray = Object.entries(vulnCounts)
                        .map(([type, data]) => ({
                            type,
                            count: data.count,
                            severity: data.severity
                        }))
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 5);
                    
                    // Update table
                    if (vulnArray.length === 0) {
                        tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No vulnerabilities found</td></tr>';
                        return;
                    }
                    
                    tableBody.innerHTML = vulnArray.map(vuln => `
                        <tr>
                            <td>${vuln.type}</td>
                            <td>${vuln.count}</td>
                            <td><span class="badge ${getSeverityClass(vuln.severity)}">${vuln.severity.toUpperCase()}</span></td>
                        </tr>
                    `).join('');
                })
                .catch(error => {
                    console.error('Error loading report:', error);
                });
        }
    });
}

// Load history data
function loadHistoryData() {
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            displayHistoryItems(data);
        })
        .catch(error => {
            console.error('Error loading history data:', error);
        });
}

function displayHistoryItems(scans) {
    const historyContainer = document.getElementById('historyItems');
    if (!historyContainer) return;
    
    // Clear loading state
    historyContainer.innerHTML = '';
    
    if (!scans || scans.length === 0) {
        historyContainer.innerHTML = '<div class="alert alert-info">No scan history found</div>';
        return;
    }
    
    // Create table
    const table = document.createElement('table');
    table.className = 'table table-hover';
    
    table.innerHTML = `
        <thead>
            <tr>
                <th>URL</th>
                <th>Scan Type</th>
                <th>Date & Time</th>
                <th>Duration</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody></tbody>
    `;
    
    const tbody = table.querySelector('tbody');
    
    scans.forEach(scan => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td class="text-truncate" style="max-width: 200px;">${scan.url}</td>
            <td>${scan.type || 'Standard'}</td>
            <td>${scan.time}</td>
            <td>${scan.duration || 'N/A'}</td>
            <td>
                <a href="/report/${scan.report_file}" class="btn btn-sm btn-primary">View Report</a>
            </td>
        `;
        
        tbody.appendChild(row);
    });
    
    historyContainer.appendChild(table);
} 