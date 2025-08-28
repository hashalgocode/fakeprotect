// Ultimate Advanced Phishing Protector Pro v7.0 - Blocked Page Script

console.log('🚫 Ultimate Phishing Protector Pro - Blocked Page Loaded');

// Initialize blocked page
document.addEventListener('DOMContentLoaded', initializeBlockedPage);

let blockedSiteInfo = {
  hostname: 'unknown',
  threats: [],
  riskLevel: 'HIGH RISK',
  blockTime: new Date()
};

async function initializeBlockedPage() {
  try {
    // Get site information from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const site = urlParams.get('site');
    
    if (site) {
      blockedSiteInfo.hostname = decodeURIComponent(site);
    }
    
    // Update page with site information
    updateBlockedPageInfo();
    
    // Setup event listeners
    setupEventListeners();
    
    // Try to get detailed threat information
    await loadThreatDetails();
    
    console.log('✅ Blocked page initialized successfully');
    
  } catch (error) {
    console.error('❌ Error initializing blocked page:', error);
  }
}

function updateBlockedPageInfo() {
  // Update blocked site name
  const blockedSiteElement = document.getElementById('blocked-site');
  if (blockedSiteElement) {
    blockedSiteElement.textContent = blockedSiteInfo.hostname;
  }
  
  // Update risk level
  const riskLevelElement = document.getElementById('risk-level');
  if (riskLevelElement) {
    riskLevelElement.textContent = blockedSiteInfo.riskLevel;
  }
  
  // Update detection time
  const detectionTimeElement = document.getElementById('detection-time');
  if (detectionTimeElement) {
    detectionTimeElement.textContent = blockedSiteInfo.blockTime.toLocaleString();
  }
}

async function loadThreatDetails() {
  try {
    // Try to get threat details from background script
    const response = await chrome.runtime.sendMessage({
      action: 'get_site_status',
      hostname: blockedSiteInfo.hostname
    });
    
    if (response && response.threatsDetected && response.threatsDetected.length > 0) {
      blockedSiteInfo.threats = response.threatsDetected;
      updateThreatList();
    }
  } catch (error) {
    console.warn('Could not load threat details:', error);
  }
}

function updateThreatList() {
  const threatListElement = document.getElementById('threat-list');
  if (!threatListElement || blockedSiteInfo.threats.length === 0) return;
  
  threatListElement.innerHTML = blockedSiteInfo.threats.map(threat => 
    `<div class="threat-item">
      <span class="threat-icon">⚠️</span>
      <span>${threat}</span>
    </div>`
  ).join('');
}

function setupEventListeners() {
  // Go Back button
  const goBackBtn = document.getElementById('go-back');
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      window.history.back();
    });
  }
  
  // Report Site button
  const reportBtn = document.getElementById('report-site');
  if (reportBtn) {
    reportBtn.addEventListener('click', handleReportSite);
  }
  
  // Whitelist Site button
  const whitelistBtn = document.getElementById('whitelist-site');
  if (whitelistBtn) {
    whitelistBtn.addEventListener('click', handleWhitelistSite);
  }
  
  // View Details button
  const viewDetailsBtn = document.getElementById('view-details');
  if (viewDetailsBtn) {
    viewDetailsBtn.addEventListener('click', handleViewDetails);
  }
  
  // Override Protection button
  const overrideBtn = document.getElementById('override-protection');
  if (overrideBtn) {
    overrideBtn.addEventListener('click', handleOverrideProtection);
  }
}

async function handleReportSite() {
  try {
    showNotification('📝 Report submitted successfully!', 'success');
    
    // Optionally send report to background script
    await chrome.runtime.sendMessage({
      action: 'report_threat',
      hostname: blockedSiteInfo.hostname,
      threats: blockedSiteInfo.threats
    });
    
  } catch (error) {
    console.error('Report error:', error);
    showNotification('❌ Error submitting report', 'error');
  }
}

async function handleWhitelistSite() {
  try {
    if (!confirm(`Are you sure you want to whitelist "${blockedSiteInfo.hostname}"?\n\nThis will allow the site to be accessed without protection warnings.`)) {
      return;
    }
    
    const response = await chrome.runtime.sendMessage({
      action: 'add_to_whitelist',
      hostname: blockedSiteInfo.hostname
    });
    
    if (response && response.success) {
      showNotification('✅ Site added to whitelist successfully!', 'success');
      
      // Redirect back to the site after a delay
      setTimeout(() => {
        window.location.href = `https://${blockedSiteInfo.hostname}`;
      }, 2000);
    } else {
      showNotification('❌ Failed to add site to whitelist', 'error');
    }
    
  } catch (error) {
    console.error('Whitelist error:', error);
    showNotification('❌ Error adding to whitelist', 'error');
  }
}

function handleViewDetails() {
  const detailsModal = createDetailsModal();
  document.body.appendChild(detailsModal);
}

function createDetailsModal() {
  const modal = document.createElement('div');
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0,0,0,0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
  `;
  
  modal.innerHTML = `
    <div style="
      background: white;
      border-radius: 16px;
      padding: 30px;
      max-width: 600px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
    ">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #dc3545;">📊 Full Security Analysis</h2>
        <button id="close-modal" style="
          background: none;
          border: none;
          font-size: 24px;
          cursor: pointer;
          color: #6c757d;
        ">×</button>
      </div>
      
      <div style="margin-bottom: 20px;">
        <h3 style="color: #495057; border-bottom: 2px solid #dc3545; padding-bottom: 5px;">🌐 Site Information</h3>
        <p><strong>Hostname:</strong> ${blockedSiteInfo.hostname}</p>
        <p><strong>Risk Level:</strong> <span style="color: #dc3545; font-weight: bold;">${blockedSiteInfo.riskLevel}</span></p>
        <p><strong>Blocked At:</strong> ${blockedSiteInfo.blockTime.toLocaleString()}</p>
      </div>
      
      <div style="margin-bottom: 20px;">
        <h3 style="color: #495057; border-bottom: 2px solid #dc3545; padding-bottom: 5px;">⚠️ Detected Threats</h3>
        <div style="background: #fff5f5; border-radius: 8px; padding: 15px;">
          ${blockedSiteInfo.threats.length > 0 ? 
            blockedSiteInfo.threats.map(threat => 
              `<div style="margin: 8px 0; padding: 8px; background: white; border-radius: 4px; border-left: 3px solid #dc3545;">
                🚨 ${threat}
              </div>`
            ).join('') :
            '<div style="color: #6c757d; font-style: italic;">No specific threats recorded</div>'
          }
        </div>
      </div>
      
      <div style="margin-bottom: 20px;">
        <h3 style="color: #495057; border-bottom: 2px solid #dc3545; padding-bottom: 5px;">🛡️ Protection Methods</h3>
        <div style="background: #f8f9fa; border-radius: 8px; padding: 15px;">
          <div style="margin: 5px 0;">✅ Heuristic Analysis</div>
          <div style="margin: 5px 0;">✅ Multi-AI Security Scanning</div>
          <div style="margin: 5px 0;">✅ Behavioral Pattern Analysis</div>
          <div style="margin: 5px 0;">✅ Real-time Threat Detection</div>
          <div style="margin: 5px 0;">✅ Brand Impersonation Detection</div>
        </div>
      </div>
      
      <div style="text-align: center;">
        <button id="close-modal-btn" style="
          background: #6c757d;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
        ">Close</button>
      </div>
    </div>
  `;
  
  // Add event listeners for modal
  modal.addEventListener('click', (e) => {
    if (e.target === modal || e.target.id === 'close-modal' || e.target.id === 'close-modal-btn') {
      modal.remove();
    }
  });
  
  return modal;
}

function handleOverrideProtection() {
  const confirmed = confirm(
    `⚠️ SECURITY WARNING ⚠️\n\n` +
    `You are about to visit a site that has been flagged as potentially dangerous.\n\n` +
    `Risks include:\n` +
    `• Identity theft\n` +
    `• Credential harvesting\n` +
    `• Malware installation\n` +
    `• Financial fraud\n\n` +
    `Do you really want to continue?`
  );
  
  if (confirmed) {
    const doubleConfirm = confirm(
      `🚨 FINAL WARNING 🚨\n\n` +
      `This is your last chance to reconsider.\n\n` +
      `The Ultimate Phishing Protector Pro strongly advises against visiting this site.\n\n` +
      `Continue at your own risk?`
    );
    
    if (doubleConfirm) {
      showNotification('⚠️ Protection overridden. Proceeding with caution...', 'warning');
      
      // Add temporary whitelist for this session
      sessionStorage.setItem('override-' + blockedSiteInfo.hostname, 'true');
      
      setTimeout(() => {
        window.location.href = `https://${blockedSiteInfo.hostname}`;
      }, 2000);
    }
  }
}

function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : type === 'warning' ? '#ffc107' : '#17a2b8'};
    color: ${type === 'warning' ? '#856404' : 'white'};
    padding: 15px 20px;
    border-radius: 8px;
    font-weight: 600;
    z-index: 10001;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    animation: slideInFromRight 0.3s ease-out;
  `;
  
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 4000);
}

// Add CSS for slide-in animation
const style = document.createElement('style');
style.textContent = `
  @keyframes slideInFromRight {
    from {
      opacity: 0;
      transform: translateX(100%);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }
`;
document.head.appendChild(style);

console.log('✅ Blocked page script loaded successfully!');