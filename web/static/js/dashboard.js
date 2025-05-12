/**
 * Dashboard JavaScript for Vulnerability Scanner
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initVulnerabilityChart();
    initScanHistoryChart();
    
    // Setup dashboard updates
    setupDashboardUpdates();
});

/**
 * Initialize vulnerability distribution chart
 */
function initVulnerabilityChart() {
    const ctx = document.getElementById('vulnerabilityChart');
    if (!ctx) return;
    
    // Sample data - in a real application, this would be fetched from the server
    const vulnerabilityData = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            label: 'Vulnerabilities',
            data: [4, 12, 28, 15, 6],
            backgroundColor: [
                'rgba(220, 53, 69, 0.8)',   // Critical - Red
                'rgba(255, 193, 7, 0.8)',   // High - Yellow
                'rgba(23, 162, 184, 0.8)',  // Medium - Cyan
                'rgba(40, 167, 69, 0.8)',   // Low - Green
                'rgba(108, 117, 125, 0.8)'  // Info - Gray
            ],
            borderColor: [
                'rgb(220, 53, 69)',
                'rgb(255, 193, 7)',
                'rgb(23, 162, 184)',
                'rgb(40, 167, 69)',
                'rgb(108, 117, 125)'
            ],
            borderWidth: 1
        }]
    };
    
    const config = {
        type: 'doughnut',
        data: vulnerabilityData,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                },
                title: {
                    display: true,
                    text: 'Vulnerability Distribution'
                }
            },
            cutout: '70%',
            animation: {
                animateScale: true
            }
        }
    };
    
    new Chart(ctx, config);
}

/**
 * Initialize scan history chart
 */
function initScanHistoryChart() {
    const ctx = document.getElementById('scanHistoryChart');
    if (!ctx) return;
    
    // Sample data - in a real application, this would be fetched from the server
    const labels = ['January', 'February', 'March', 'April', 'May', 'June', 'July'];
    const data = {
        labels: labels,
        datasets: [
            {
                label: 'Scans Performed',
                data: [5, 8, 12, 9, 12, 15, 10],
                borderColor: 'rgb(13, 110, 253)',
                backgroundColor: 'rgba(13, 110, 253, 0.5)',
                tension: 0.4
            },
            {
                label: 'Vulnerabilities Found',
                data: [12, 19, 25, 18, 27, 31, 24],
                borderColor: 'rgb(220, 53, 69)',
                backgroundColor: 'rgba(220, 53, 69, 0.5)',
                tension: 0.4
            }
        ]
    };
    
    const config = {
        type: 'line',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Scan History Trends'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    };
    
    new Chart(ctx, config);
}

/**
 * Setup dashboard periodic updates
 */
function setupDashboardUpdates() {
    // Update recent scans
    updateRecentScans();
    
    // Update statistics
    updateStatistics();
    
    // Set up periodic updates (every 30 seconds)
    setInterval(() => {
        updateRecentScans();
        updateStatistics();
    }, 30000);
}

/**
 * Update recent scans list
 */
function updateRecentScans() {
    const recentScansContainer = document.getElementById('recentScans');
    if (!recentScansContainer) return;
    
    // In a real application, fetch this data from the server
    // For demo purposes, we're using sample data
    
    // Check if we're in demo mode without backend connection
    if (recentScansContainer.dataset.demo === 'true') {
        // Sample data already in HTML, just return
        return;
    }
    
    // Add loading indicator
    recentScansContainer.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm text-primary" role="status"></div> Loading recent scans...</div>';
    
    // Fetch recent scans (mocked for demo)
    setTimeout(() => {
        const scans = [
            { id: 'scan123', target: 'https://example.com', date: '2023-07-15T14:30:00', vulnCount: 5, status: 'completed' },
            { id: 'scan124', target: 'https://test-site.org', date: '2023-07-14T10:15:00', vulnCount: 2, status: 'completed' },
            { id: 'scan125', target: 'https://vulntest.net', date: '2023-07-13T16:45:00', vulnCount: 8, status: 'completed' },
            { id: 'scan126', target: 'https://securitytest.com', date: '2023-07-12T09:20:00', vulnCount: 0, status: 'completed' }
        ];
        
        if (scans.length === 0) {
            recentScansContainer.innerHTML = '<div class="text-center text-muted">No recent scans found</div>';
            return;
        }
        
        let html = '';
        scans.forEach(scan => {
            const date = new Date(scan.date);
            const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
            
            let statusClass = 'bg-secondary';
            if (scan.status === 'completed') {
                statusClass = scan.vulnCount > 0 ? 'bg-warning' : 'bg-success';
            }
            
            html += `
                <div class="scan-item p-2 mb-2 border-bottom">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="mb-0">${scan.target}</h6>
                            <small class="text-muted">${formattedDate}</small>
                        </div>
                        <div>
                            <span class="badge ${statusClass}">${scan.vulnCount} issues</span>
                            <a href="#" class="btn btn-sm btn-outline-primary ms-2" 
                               onclick="viewScanDetails('${scan.id}')">View</a>
                        </div>
                    </div>
                </div>
            `;
        });
        
        recentScansContainer.innerHTML = html;
    }, 500); // Simulated delay
}

/**
 * Update dashboard statistics
 */
function updateStatistics() {
    // In a real application, fetch this data from the server
    // For demo purposes, we're using sample data
    
    updateStatValue('totalScans', 45);
    updateStatValue('totalVulnerabilities', 237);
    updateStatValue('criticalVulnerabilities', 14);
    updateStatValue('avgScanTime', '1m 45s');
}

/**
 * Update a specific statistic value with animation
 * @param {string} id - Element ID
 * @param {string|number} value - New value
 */
function updateStatValue(id, value) {
    const element = document.getElementById(id);
    if (!element) return;
    
    // If element has data-demo attribute, don't update
    if (element.dataset.demo === 'true') return;
    
    const oldValue = element.innerText;
    
    // If it's a number, animate counting
    if (!isNaN(parseInt(value))) {
        animateCounter(element, parseInt(oldValue) || 0, parseInt(value));
    } else {
        // For non-numbers, just update
        element.innerText = value;
    }
}

/**
 * Animate a counter value
 * @param {HTMLElement} element - Element to update
 * @param {number} start - Start value
 * @param {number} end - End value
 */
function animateCounter(element, start, end) {
    if (start === end) return;
    
    const duration = 1000; // 1 second
    const step = Math.max(1, Math.floor(Math.abs(end - start) / (duration / 50)));
    let current = start;
    
    const animate = () => {
        if (start < end) {
            current = Math.min(current + step, end);
        } else {
            current = Math.max(current - step, end);
        }
        
        element.innerText = formatNumber(current);
        
        if (current !== end) {
            requestAnimationFrame(animate);
        }
    };
    
    requestAnimationFrame(animate);
}

/**
 * Handle viewing scan details (for the recent scans list)
 * @param {string} scanId - Scan ID to view
 */
function viewScanDetails(scanId) {
    // In a real application, redirect to the scan details page
    window.location.href = `/history?scan_id=${scanId}`;
} 