// Dashboard JavaScript functionality for Netlify

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    // Initialize dashboard stats
    updateDashboardStats('init');
    
    // Add sample data for demonstration
    setTimeout(() => {
        addActivityLog('System initialized and ready for analysis', 'success');
    }, 1000);
}

function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });
    
    // Remove active class from all nav tabs
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab content
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
    
    // Add active class to selected nav tab
    const selectedNavTab = document.querySelector(`[onclick="showTab('${tabName}')"]`);
    if (selectedNavTab) {
        selectedNavTab.classList.add('active');
    }
}

function updateDashboardStats(type) {
    if (type === 'init') {
        // Initialize with default values
        document.getElementById('emails-analyzed').textContent = '0';
        document.getElementById('urls-scanned').textContent = '0';
        document.getElementById('threats-detected').textContent = '0';
    } else if (type === 'email') {
        const emailsAnalyzed = document.getElementById('emails-analyzed');
        const currentCount = parseInt(emailsAnalyzed.textContent) || 0;
        emailsAnalyzed.textContent = currentCount + 1;
    } else if (type === 'url') {
        const urlsScanned = document.getElementById('urls-scanned');
        const currentCount = parseInt(urlsScanned.textContent) || 0;
        urlsScanned.textContent = currentCount + 1;
    } else if (type === 'threat') {
        const threatsDetected = document.getElementById('threats-detected');
        const currentCount = parseInt(threatsDetected.textContent) || 0;
        threatsDetected.textContent = currentCount + 1;
    }
}

function addActivityLog(message, type = 'info') {
    const activityList = document.getElementById('activity-list');
    const activityItem = document.createElement('div');
    activityItem.className = 'activity-item';
    
    const iconClass = type === 'success' ? 'fa-check-circle' : 
                     type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle';
    
    const timeAgo = 'Just now';
    
    activityItem.innerHTML = `
        <i class="fas ${iconClass}"></i>
        <span>${message}</span>
        <span class="activity-time">${timeAgo}</span>
    `;
    
    activityList.insertBefore(activityItem, activityList.firstChild);
    
    // Keep only last 10 activities
    while (activityList.children.length > 10) {
        activityList.removeChild(activityList.lastChild);
    }
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Tab switching with number keys
    if (e.key >= '1' && e.key <= '3') {
        e.preventDefault();
        const tabs = ['dashboard', 'email', 'url'];
        const tabIndex = parseInt(e.key) - 1;
        if (tabs[tabIndex]) {
            showTab(tabs[tabIndex]);
        }
    }
    
    // Escape to go to dashboard
    if (e.key === 'Escape') {
        showTab('dashboard');
    }
});

// Add smooth scrolling for better UX
function smoothScrollTo(element) {
    element.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
}

// Add loading states for better UX
function showLoading(element) {
    if (element) {
        element.classList.add('loading');
    }
}

function hideLoading(element) {
    if (element) {
        element.classList.remove('loading');
    }
}

// Add error handling
function showError(message, element = null) {
    const errorElement = element || document.body;
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `
        <i class="fas fa-exclamation-triangle"></i>
        <span>${message}</span>
    `;
    
    errorElement.appendChild(errorDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.parentNode.removeChild(errorDiv);
        }
    }, 5000);
}

// Add success notifications
function showSuccess(message, element = null) {
    const successElement = element || document.body;
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <span>${message}</span>
    `;
    
    successElement.appendChild(successDiv);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (successDiv.parentNode) {
            successDiv.parentNode.removeChild(successDiv);
        }
    }, 3000);
}