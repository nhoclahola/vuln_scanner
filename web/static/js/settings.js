/**
 * Settings JavaScript for Vulnerability Scanner
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize password toggle functionality
    initPasswordToggles();
    
    // Initialize form submissions
    initFormSubmissions();
    
    // Load system information
    loadSystemInfo();
});

/**
 * Initialize password toggle functionality
 */
function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.password-toggle');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.dataset.target;
            const inputField = document.getElementById(targetId);
            
            if (!inputField) return;
            
            // Toggle input type
            if (inputField.type === 'password') {
                inputField.type = 'text';
                this.innerHTML = '<i class="bi bi-eye-slash"></i>';
                this.setAttribute('title', 'Hide');
            } else {
                inputField.type = 'password';
                this.innerHTML = '<i class="bi bi-eye"></i>';
                this.setAttribute('title', 'Show');
            }
        });
    });
}

/**
 * Initialize form submissions
 */
function initFormSubmissions() {
    // API Settings form
    const apiForm = document.getElementById('apiSettingsForm');
    if (apiForm) {
        apiForm.addEventListener('submit', function(e) {
            e.preventDefault();
            saveApiSettings();
        });
    }
    
    // Scan Settings form
    const scanForm = document.getElementById('scanSettingsForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            saveScanSettings();
        });
    }
    
    // Report Settings form
    const reportForm = document.getElementById('reportSettingsForm');
    if (reportForm) {
        reportForm.addEventListener('submit', function(e) {
            e.preventDefault();
            saveReportSettings();
        });
    }
    
    // System info refresh button
    const refreshBtn = document.getElementById('refreshSystemInfo');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadSystemInfo();
        });
    }
}

/**
 * Save API settings
 */
function saveApiSettings() {
    const openaiKey = document.getElementById('openaiApiKey').value;
    const deepseekKey = document.getElementById('deepseekApiKey').value;
    const deepseekUrl = document.getElementById('deepseekApiUrl').value;
    
    // In a real application, send data to the server
    // For demo purposes, we're just showing a success message
    
    // Show loading state
    const submitButton = document.querySelector('#apiSettingsForm button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
    
    // Simulate server request
    setTimeout(() => {
        // Reset button
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
        
        // Show success message
        showAlert('API settings saved successfully', 'success');
        
        // Update system info
        loadSystemInfo();
    }, 1000);
}

/**
 * Save scan settings
 */
function saveScanSettings() {
    const defaultLlm = document.getElementById('defaultLlmProvider').value;
    const defaultScanType = document.getElementById('defaultScanType').value;
    
    // Get selected vulnerability types
    const vulnTypes = [];
    document.querySelectorAll('input[name="vulnTypes"]:checked').forEach(checkbox => {
        vulnTypes.push(checkbox.value);
    });
    
    // In a real application, send data to the server
    // For demo purposes, we're just showing a success message
    
    // Show loading state
    const submitButton = document.querySelector('#scanSettingsForm button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
    
    // Simulate server request
    setTimeout(() => {
        // Reset button
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
        
        // Show success message
        showAlert('Scan settings saved successfully', 'success');
        
        // Update system info
        loadSystemInfo();
    }, 1000);
}

/**
 * Save report settings
 */
function saveReportSettings() {
    const reportFormat = document.getElementById('reportFormat').value;
    const reportDir = document.getElementById('reportDirectory').value;
    const autoSave = document.getElementById('autoSaveReports').checked;
    const includeRemediation = document.getElementById('includeRemediation').checked;
    
    // In a real application, send data to the server
    // For demo purposes, we're just showing a success message
    
    // Show loading state
    const submitButton = document.querySelector('#reportSettingsForm button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
    
    // Simulate server request
    setTimeout(() => {
        // Reset button
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
        
        // Show success message
        showAlert('Report settings saved successfully', 'success');
    }, 1000);
}

/**
 * Load system information
 */
function loadSystemInfo() {
    const infoContainer = document.getElementById('systemInfoTable');
    if (!infoContainer) return;
    
    // Show loading state
    infoContainer.innerHTML = '<tr><td colspan="2" class="text-center"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">Loading system information...</p></td></tr>';
    
    // In a real application, fetch this data from the server
    // For demo purposes, we're simulating it
    
    // Simulate server request
    setTimeout(() => {
        // Sample system information
        const systemInfo = {
            appVersion: '1.0.0',
            pythonVersion: '3.9.5',
            os: 'Windows 10',
            crewaiVersion: '0.14.2',
            agents: 4,
            defaultLlm: 'DeepSeek',
            defaultScanType: 'Full Scan',
            openaiConfigured: false,
            deepseekConfigured: true
        };
        
        // Generate table rows
        let html = `
            <tr>
                <td>Application Version</td>
                <td>${systemInfo.appVersion}</td>
            </tr>
            <tr>
                <td>Python Version</td>
                <td>${systemInfo.pythonVersion}</td>
            </tr>
            <tr>
                <td>Operating System</td>
                <td>${systemInfo.os}</td>
            </tr>
            <tr>
                <td>CrewAI Version</td>
                <td>${systemInfo.crewaiVersion}</td>
            </tr>
            <tr>
                <td>Number of Agents</td>
                <td>${systemInfo.agents}</td>
            </tr>
            <tr>
                <td>Default LLM</td>
                <td>${systemInfo.defaultLlm}</td>
            </tr>
            <tr>
                <td>Default Scan Type</td>
                <td>${systemInfo.defaultScanType}</td>
            </tr>
            <tr>
                <td>OpenAI API</td>
                <td>${systemInfo.openaiConfigured ? 
                    '<span class="badge bg-success">Configured</span>' : 
                    '<span class="badge bg-danger">Not Configured</span>'}</td>
            </tr>
            <tr>
                <td>DeepSeek API</td>
                <td>${systemInfo.deepseekConfigured ? 
                    '<span class="badge bg-success">Configured</span>' : 
                    '<span class="badge bg-danger">Not Configured</span>'}</td>
            </tr>
        `;
        
        infoContainer.innerHTML = html;
    }, 1000);
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