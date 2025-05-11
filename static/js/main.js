/**
 * Vulnerability Scanner - Main JavaScript
 * Main script file for the vulnerability scanner application
 */

$(document).ready(function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Highlight code blocks
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach((el) => {
            hljs.highlightElement(el);
        });
    }
    
    // Form validation
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const url = document.getElementById('url').value.trim();
            if (!url) {
                e.preventDefault();
                showAlert('Vui lòng nhập URL cần quét!', 'danger');
                return false;
            }
            
            const hasVulnSelected = document.querySelectorAll('input[type="checkbox"]:checked').length > 0;
            if (!hasVulnSelected) {
                e.preventDefault();
                showAlert('Vui lòng chọn ít nhất một loại lỗ hổng để quét!', 'danger');
                return false;
            }
            
            // Show loading state
            const submitBtn = scanForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang xử lý...';
            }
            
            return true;
        });
    }
    
    // Vulnerability option cards click handler
    $('.vulnerability-option').on('click', function(e) {
        if (!$(e.target).is('input') && !$(e.target).is('label')) {
            const checkbox = $(this).find('input[type="checkbox"]');
            checkbox.prop('checked', !checkbox.prop('checked'));
        }
    });
    
    // Delete scan confirmation
    $('.delete-scan-btn').on('click', function(e) {
        if (!confirm('Bạn có chắc chắn muốn xóa kết quả quét này không?')) {
            e.preventDefault();
        }
    });
    
    // Search functionality for history page
    $('#scan-search').on('keyup', function() {
        const value = $(this).val().toLowerCase();
        $('.scan-history-item').filter(function() {
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1);
        });
        
        // Show no results message if needed
        const visibleItems = $('.scan-history-item:visible').length;
        if (visibleItems === 0) {
            $('#no-results').show();
        } else {
            $('#no-results').hide();
        }
    });
    
    // Copy URL to clipboard
    $('.copy-url-btn').on('click', function() {
        const url = $(this).data('url');
        navigator.clipboard.writeText(url).then(function() {
            showToast('URL đã được sao chép!', 'success');
        }, function() {
            showToast('Không thể sao chép URL', 'danger');
        });
    });
    
    // Report page: Toggle sections
    $('.toggle-section').on('click', function() {
        const target = $(this).data('target');
        $(target).slideToggle(300);
        $(this).find('i').toggleClass('fa-chevron-down fa-chevron-up');
    });
    
    // Expand/collapse all vulnerabilities in report
    $('#expand-all-btn').on('click', function() {
        $('.vulnerability-details').slideDown(300);
        $('.toggle-details i').removeClass('fa-chevron-down').addClass('fa-chevron-up');
    });
    
    $('#collapse-all-btn').on('click', function() {
        $('.vulnerability-details').slideUp(300);
        $('.toggle-details i').removeClass('fa-chevron-up').addClass('fa-chevron-down');
    });
});

/**
 * Show an alert message
 * @param {string} message - The message to display
 * @param {string} type - The type of alert (success, danger, warning, info)
 */
function showAlert(message, type = 'info') {
    const alertPlaceholder = document.getElementById('alert-placeholder');
    if (!alertPlaceholder) return;
    
    const wrapper = document.createElement('div');
    wrapper.classList.add('alert', `alert-${type}`, 'alert-dismissible', 'fade', 'show');
    wrapper.role = 'alert';
    
    wrapper.innerHTML = `
        <div>${message}</div>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertPlaceholder.appendChild(wrapper);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        const alert = bootstrap.Alert.getOrCreateInstance(wrapper);
        alert.close();
    }, 5000);
}

/**
 * Show a toast notification
 * @param {string} message - The message to display
 * @param {string} type - The type of toast (success, danger, warning, info)
 */
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;
    
    const toastId = 'toast-' + Date.now();
    const toastEl = document.createElement('div');
    toastEl.id = toastId;
    toastEl.classList.add('toast', 'align-items-center', `text-bg-${type}`, 'border-0');
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    
    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastContainer.appendChild(toastEl);
    
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
    
    // Remove from DOM after hiding
    toastEl.addEventListener('hidden.bs.toast', function() {
        toastEl.remove();
    });
}

/**
 * Format date and time
 * @param {string} dateString - Date string to format
 * @returns {string} Formatted date
 */
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('vi-VN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * Create animated progress chart
 * @param {string} elementId - Canvas element ID
 * @param {object} data - Chart data
 */
function createChart(elementId, data) {
    if (typeof Chart === 'undefined') return;
    
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            animation: {
                animateRotate: true,
                animateScale: true
            },
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
} 