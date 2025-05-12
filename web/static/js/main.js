/**
 * Main JavaScript file for Vulnerability Scanner
 */

document.addEventListener('DOMContentLoaded', function() {
    // Dark Mode Toggle
    setupDarkMode();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Add smooth scrolling
    addSmoothScrolling();
    
    // Make terminal add new output at the bottom
    initializeTerminals();
    
    // Responsive sidebar
    setupResponsiveSidebar();
});

/**
 * Setup dark mode functionality
 */
function setupDarkMode() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    const body = document.body;
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        body.classList.add('dark-theme');
        updateDarkModeToggle(true);
    }
    
    // Handle dark mode toggle
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            if (body.classList.contains('dark-theme')) {
                body.classList.remove('dark-theme');
                localStorage.setItem('theme', 'light');
                updateDarkModeToggle(false);
            } else {
                body.classList.add('dark-theme');
                localStorage.setItem('theme', 'dark');
                updateDarkModeToggle(true);
            }
        });
    }
}

/**
 * Update dark mode toggle button
 * @param {boolean} isDark - Whether dark mode is active
 */
function updateDarkModeToggle(isDark) {
    const toggle = document.getElementById('darkModeToggle');
    if (!toggle) return;
    
    const icon = toggle.querySelector('i');
    if (isDark) {
        icon.classList.remove('bi-moon');
        icon.classList.add('bi-sun');
    } else {
        icon.classList.remove('bi-sun');
        icon.classList.add('bi-moon');
    }
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Add smooth scrolling behavior
 */
function addSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
}

/**
 * Initialize terminal elements
 */
function initializeTerminals() {
    const terminals = document.querySelectorAll('.terminal');
    terminals.forEach(terminal => {
        // Auto-scroll to bottom when content changes
        const observer = new MutationObserver(() => {
            terminal.scrollTop = terminal.scrollHeight;
        });
        
        observer.observe(terminal, {
            childList: true,
            characterData: true,
            subtree: true
        });
    });
}

/**
 * Setup responsive sidebar
 */
function setupResponsiveSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    
    if (!sidebar || !mainContent) return;
    
    // Handle sidebar toggle for mobile
    const createToggleButton = () => {
        if (document.getElementById('sidebarToggle')) return;
        
        const toggleButton = document.createElement('button');
        toggleButton.id = 'sidebarToggle';
        toggleButton.className = 'btn btn-sm btn-outline-primary d-md-none position-fixed';
        toggleButton.style.top = '10px';
        toggleButton.style.left = '80px';
        toggleButton.style.zIndex = '1050';
        toggleButton.innerHTML = '<i class="bi bi-list"></i>';
        
        toggleButton.addEventListener('click', function() {
            sidebar.classList.toggle('d-none');
        });
        
        document.body.appendChild(toggleButton);
    };
    
    // Add toggle button for mobile
    const handleResize = () => {
        if (window.innerWidth < 768) {
            createToggleButton();
        } else {
            const toggleButton = document.getElementById('sidebarToggle');
            if (toggleButton) {
                toggleButton.remove();
            }
            sidebar.classList.remove('d-none');
        }
    };
    
    // Initial setup
    handleResize();
    
    // Handle window resize
    window.addEventListener('resize', handleResize);
}

/**
 * Format date in user-friendly format
 * @param {string|Date} date - Date to format
 * @returns {string} Formatted date
 */
function formatDate(date) {
    if (!date) return 'N/A';
    
    const d = new Date(date);
    if (isNaN(d.getTime())) return date; // Return original if invalid
    
    return d.toLocaleString();
}

/**
 * Format duration in user-friendly format
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration
 */
function formatDuration(seconds) {
    if (!seconds) return 'N/A';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    let result = '';
    if (hours > 0) result += `${hours}h `;
    if (minutes > 0) result += `${minutes}m `;
    result += `${secs}s`;
    
    return result;
}

/**
 * Format number with commas
 * @param {number} num - Number to format
 * @returns {string} Formatted number
 */
function formatNumber(num) {
    if (num === undefined || num === null) return '-';
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Create a download with specified content
 * @param {string} filename - Name of the file to download
 * @param {string} content - Content of the file
 * @param {string} type - MIME type of the file
 */
function createDownload(filename, content, type = 'text/plain') {
    const blob = new Blob([content], { type });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    
    document.body.appendChild(a);
    a.click();
    
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

/**
 * Parse markdown-like text to HTML
 * @param {string} text - Text to parse
 * @returns {string} HTML content
 */
function parseMarkdown(text) {
    if (!text) return '';
    
    let html = '';
    const lines = text.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        if (line.startsWith('# ')) {
            html += `<h1>${line.substring(2)}</h1>`;
        } else if (line.startsWith('## ')) {
            html += `<h2>${line.substring(3)}</h2>`;
        } else if (line.startsWith('### ')) {
            html += `<h3>${line.substring(4)}</h3>`;
        } else if (line.startsWith('- ')) {
            html += '<ul>';
            html += `<li>${line.substring(2)}</li>`;
            
            // Look ahead for more list items
            let j = i + 1;
            while (j < lines.length && lines[j].startsWith('- ')) {
                html += `<li>${lines[j].substring(2)}</li>`;
                i = j;
                j++;
            }
            
            html += '</ul>';
        } else if (line.trim() === '') {
            html += '<br>';
        } else if (line.includes('Critical:') || line.includes('CRITICAL')) {
            html += `<p><span class="badge bg-danger">CRITICAL</span> ${line}</p>`;
        } else if (line.includes('High:') || line.includes('HIGH')) {
            html += `<p><span class="badge bg-warning text-dark">HIGH</span> ${line}</p>`;
        } else if (line.includes('Medium:') || line.includes('MEDIUM')) {
            html += `<p><span class="badge bg-info text-dark">MEDIUM</span> ${line}</p>`;
        } else if (line.includes('Low:') || line.includes('LOW')) {
            html += `<p><span class="badge bg-success">LOW</span> ${line}</p>`;
        } else {
            html += `<p>${line}</p>`;
        }
    }
    
    return html;
} 