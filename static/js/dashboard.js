// Dashboard JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    // Load system statistics
    loadSystemStats();
    
    // Set up auto-refresh for stats
    setInterval(loadSystemStats, 30000); // Refresh every 30 seconds
});

function loadSystemStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateStatsDisplay(data.stats);
            } else {
                console.error('Failed to load stats:', data.error);
            }
        })
        .catch(error => {
            console.error('Error loading stats:', error);
        });
}

function updateStatsDisplay(stats) {
    // Update model accuracies
    const emailAccuracy = document.getElementById('email-accuracy');
    const urlAccuracy = document.getElementById('url-accuracy');
    const lastUpdate = document.getElementById('last-update');
    const emailCount = document.getElementById('email-count');
    const urlCount = document.getElementById('url-count');
    
    if (emailAccuracy) {
        emailAccuracy.textContent = `${(stats.email_model_accuracy * 100).toFixed(1)}%`;
    }
    
    if (urlAccuracy) {
        urlAccuracy.textContent = `${(stats.url_model_accuracy * 100).toFixed(1)}%`;
    }
    
    if (lastUpdate) {
        const updateDate = new Date(stats.last_model_update);
        lastUpdate.textContent = updateDate.toLocaleString();
    }
    
    if (emailCount) {
        emailCount.textContent = stats.total_emails_analyzed || 0;
    }
    
    if (urlCount) {
        urlCount.textContent = stats.total_urls_analyzed || 0;
    }
    
    // Update progress bars
    updateProgressBars(stats);
}

function updateProgressBars(stats) {
    // Update email model accuracy bar
    const emailProgress = document.querySelector('.card:nth-child(1) .progress-bar');
    if (emailProgress) {
        const accuracy = (stats.email_model_accuracy * 100) || 95;
        emailProgress.style.width = `${accuracy}%`;
        emailProgress.setAttribute('aria-valuenow', accuracy);
    }
    
    // Update URL model accuracy bar
    const urlProgress = document.querySelector('.card:nth-child(2) .progress-bar');
    if (urlProgress) {
        const accuracy = (stats.url_model_accuracy * 100) || 92;
        urlProgress.style.width = `${accuracy}%`;
        urlProgress.setAttribute('aria-valuenow', accuracy);
    }
    
    // Update threat detection bar
    const threatProgress = document.querySelector('.card:nth-child(3) .progress-bar');
    if (threatProgress) {
        const detectionRate = 88; // Static for demo
        threatProgress.style.width = `${detectionRate}%`;
        threatProgress.setAttribute('aria-valuenow', detectionRate);
    }
    
    // Update response time bar
    const responseProgress = document.querySelector('.card:nth-child(4) .progress-bar');
    if (responseProgress) {
        const responseTime = 100; // Static for demo
        responseProgress.style.width = `${responseTime}%`;
        responseProgress.setAttribute('aria-valuenow', responseTime);
    }
}

// Add smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Add animation classes to cards on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
        }
    });
}, observerOptions);

// Observe all cards
document.querySelectorAll('.card').forEach(card => {
    observer.observe(card);
});

// Add hover effects to feature cards
document.querySelectorAll('.feature-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-10px)';
        this.style.boxShadow = '0 15px 35px rgba(0,0,0,0.2)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0)';
        this.style.boxShadow = '0 4px 6px rgba(0,0,0,0.1)';
    });
});

// Add click tracking for analytics
function trackClick(element, action) {
    console.log(`Analytics: ${action} clicked`);
    // In a real application, you would send this data to your analytics service
}

// Add click handlers for tracking
document.querySelectorAll('a[href="/email-analyzer"]').forEach(link => {
    link.addEventListener('click', () => trackClick(link, 'Email Analyzer'));
});

document.querySelectorAll('a[href="/url-analyzer"]').forEach(link => {
    link.addEventListener('click', () => trackClick(link, 'URL Analyzer'));
});

// Add loading state management
function showLoading(element) {
    element.innerHTML = '<div class="spinner-border spinner-border-sm me-2" role="status"></div>Loading...';
    element.disabled = true;
}

function hideLoading(element, originalText) {
    element.innerHTML = originalText;
    element.disabled = false;
}

// Add error handling for failed requests
function handleError(error, context) {
    console.error(`Error in ${context}:`, error);
    
    // Show user-friendly error message
    const errorAlert = document.createElement('div');
    errorAlert.className = 'alert alert-warning alert-dismissible fade show position-fixed';
    errorAlert.style.top = '20px';
    errorAlert.style.right = '20px';
    errorAlert.style.zIndex = '9999';
    errorAlert.innerHTML = `
        <strong>Warning!</strong> ${context} failed. Please try again.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(errorAlert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (errorAlert.parentNode) {
            errorAlert.parentNode.removeChild(errorAlert);
        }
    }, 5000);
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + E for Email Analyzer
    if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
        e.preventDefault();
        window.location.href = '/email-analyzer';
    }
    
    // Ctrl/Cmd + U for URL Analyzer
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        window.location.href = '/url-analyzer';
    }
    
    // Ctrl/Cmd + H for Home
    if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
        e.preventDefault();
        window.location.href = '/';
    }
});

// Add tooltip initialization
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Add performance monitoring
function measurePerformance() {
    if (window.performance && window.performance.timing) {
        const timing = window.performance.timing;
        const loadTime = timing.loadEventEnd - timing.navigationStart;
        console.log(`Page load time: ${loadTime}ms`);
    }
}

// Run performance measurement when page loads
window.addEventListener('load', measurePerformance);
