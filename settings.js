// Ultimate Advanced Phishing Protector Pro v7.0 - Settings Page Script

console.log('⚙️ Ultimate Advanced Phishing Protector Pro - Settings Page Loading...');

// Settings state management
let currentSettings = {
  general: {
    realtimeScanning: true,
    autoBlock: true,
    blockingThreshold: 0.25,
    notifications: true,
    warningPopups: true
  },
  ai: {
    primaryKey: '',
    secondaryKey: '',
    tertiaryKey: '',
    multiAiConsensus: true
  },
  security: {
    strictMode: false,
    formProtection: true,
    whitelistedSites: [],
    blockedSites: []
  }
};

let currentTab = 'general';

// Initialize settings page
document.addEventListener('DOMContentLoaded', initializeSettingsPage);

async function initializeSettingsPage() {
  try {
    console.log('🔧 Initializing Ultimate Settings Page...');
    
    // Setup navigation
    setupTabNavigation();
    
    // Load current settings
    await loadAllSettings();
    
    // Setup event listeners
    setupAllSettingsListeners();
    
    // Load analytics data
    await loadAnalyticsData();
    
    // Load whitelist and blocklist
    await loadSecurityLists();
    
    console.log('✅ Settings page initialized successfully');
    
  } catch (error) {
    console.error('❌ Error initializing settings page:', error);
    showNotification('Failed to initialize settings page', 'error');
  }
}

// Setup tab navigation
function setupTabNavigation() {
  const tabButtons = document.querySelectorAll('.nav-tab');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      
      // Remove active class from all tabs and contents
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      // Add active class to current tab and content
      button.classList.add('active');
      document.getElementById(`${tabName}-tab`).classList.add('active');
      
      currentTab = tabName;
    });
  });
}

// Load all settings from storage
async function loadAllSettings() {
  try {
    const result = await chrome.storage.local.get([
      'settings', 
      'aiApiKeys', 
      'whitelistedSites', 
      'blockedSites'
    ]);
    
    // Load general settings
    if (result.settings) {
      currentSettings.general = { ...currentSettings.general, ...result.settings };
      updateGeneralSettingsUI();
    }
    
    // Load AI settings
    if (result.aiApiKeys) {
      currentSettings.ai = { 
        ...currentSettings.ai, 
        primaryKey: result.aiApiKeys.primary || '',
        secondaryKey: result.aiApiKeys.secondary || '',
        tertiaryKey: result.aiApiKeys.tertiary || ''
      };
      updateAISettingsUI();
    }
    
    // Load security settings
    if (result.whitelistedSites) {
      currentSettings.security.whitelistedSites = result.whitelistedSites;
    }
    
    if (result.blockedSites) {
      currentSettings.security.blockedSites = result.blockedSites;
    }
    
    console.log('✅ All settings loaded successfully');
    
  } catch (error) {
    console.error('❌ Error loading settings:', error);
  }
}

// Update general settings UI
function updateGeneralSettingsUI() {
  const settings = currentSettings.general;
  
  // Update checkboxes
  const realtimeScanning = document.getElementById('realtime-scanning');
  const autoBlock = document.getElementById('auto-block');
  const notifications = document.getElementById('notifications');
  const warningPopups = document.getElementById('warning-popups');
  const blockingThreshold = document.getElementById('blocking-threshold');
  
  if (realtimeScanning) realtimeScanning.checked = settings.realtimeScanning;
  if (autoBlock) autoBlock.checked = settings.autoBlock;
  if (notifications) notifications.checked = settings.notifications;
  if (warningPopups) warningPopups.checked = settings.warningPopups;
  if (blockingThreshold) blockingThreshold.value = settings.blockingThreshold;
}

// Update AI settings UI
function updateAISettingsUI() {
  const primaryKey = document.getElementById('primary-key');
  const secondaryKey = document.getElementById('secondary-key');
  const tertiaryKey = document.getElementById('tertiary-key');
  const multiAiConsensus = document.getElementById('multi-ai-consensus');
  
  if (primaryKey) primaryKey.value = maskApiKey(currentSettings.ai.primaryKey);
  if (secondaryKey) secondaryKey.value = maskApiKey(currentSettings.ai.secondaryKey);
  if (tertiaryKey) tertiaryKey.value = maskApiKey(currentSettings.ai.tertiaryKey);
  if (multiAiConsensus) multiAiConsensus.checked = currentSettings.ai.multiAiConsensus;
  
  // Update status indicators
  updateApiKeyStatus();
}

// Setup all event listeners
function setupAllSettingsListeners() {
  // General settings listeners
  setupGeneralSettingsListeners();
  
  // AI settings listeners
  setupAISettingsListeners();
  
  // Security settings listeners
  setupSecuritySettingsListeners();
  
  // Analytics listeners
  setupAnalyticsListeners();
  
  // About listeners
  setupAboutListeners();
  
  // Save all settings button
  const saveAllBtn = document.getElementById('save-all-settings');
  if (saveAllBtn) {
    saveAllBtn.addEventListener('click', saveAllSettings);
  }
}

// Setup general settings listeners
function setupGeneralSettingsListeners() {
  const generalInputs = [
    'realtime-scanning', 'auto-block', 'notifications', 
    'warning-popups', 'blocking-threshold'
  ];
  
  generalInputs.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener('change', (e) => {
        const value = element.type === 'checkbox' ? element.checked : 
                     element.type === 'select-one' ? parseFloat(element.value) : 
                     element.value;
        
        // Update currentSettings
        const settingName = id.replace(/-([a-z])/g, (g) => g[1].toUpperCase());
        currentSettings.general[settingName] = value;
        
        console.log(`Updated ${settingName}:`, value);
      });
    }
  });
}

// Setup AI settings listeners
function setupAISettingsListeners() {
  const aiInputs = ['primary-key', 'secondary-key', 'tertiary-key'];
  
  aiInputs.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener('blur', (e) => {
        const value = element.value;
        if (value && !value.includes('***')) {
          const keyName = id.replace('-key', 'Key');
          currentSettings.ai[keyName] = value;
        }
      });
    }
  });
  
  const multiAiConsensus = document.getElementById('multi-ai-consensus');
  if (multiAiConsensus) {
    multiAiConsensus.addEventListener('change', (e) => {
      currentSettings.ai.multiAiConsensus = e.target.checked;
    });
  }
  
  // Test AI connection button
  const testConnectionBtn = document.getElementById('test-ai-connection');
  if (testConnectionBtn) {
    testConnectionBtn.addEventListener('click', testAIConnection);
  }
  
  // Save AI keys button
  const saveAIKeysBtn = document.getElementById('save-ai-keys');
  if (saveAIKeysBtn) {
    saveAIKeysBtn.addEventListener('click', saveAIKeys);
  }
}

// Setup security settings listeners
function setupSecuritySettingsListeners() {
  // Add whitelist site
  const addWhitelistBtn = document.getElementById('add-whitelist');
  if (addWhitelistBtn) {
    addWhitelistBtn.addEventListener('click', addWhitelistSite);
  }
  
  // Add blocked site
  const addBlockedBtn = document.getElementById('add-blocked');
  if (addBlockedBtn) {
    addBlockedBtn.addEventListener('click', addBlockedSite);
  }
  
  // Enter key support for inputs
  const newWhitelistInput = document.getElementById('new-whitelist-site');
  const newBlockedInput = document.getElementById('new-blocked-site');
  
  if (newWhitelistInput) {
    newWhitelistInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') addWhitelistSite();
    });
  }
  
  if (newBlockedInput) {
    newBlockedInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') addBlockedSite();
    });
  }
  
  // Security toggles
  const strictMode = document.getElementById('strict-mode');
  const formProtection = document.getElementById('form-protection');
  
  if (strictMode) {
    strictMode.addEventListener('change', (e) => {
      currentSettings.security.strictMode = e.target.checked;
    });
  }
  
  if (formProtection) {
    formProtection.addEventListener('change', (e) => {
      currentSettings.security.formProtection = e.target.checked;
    });
  }
}

// Setup analytics listeners
function setupAnalyticsListeners() {
  const exportDataBtn = document.getElementById('export-data');
  const clearAnalyticsBtn = document.getElementById('clear-analytics');
  const resetExtensionBtn = document.getElementById('reset-extension');
  
  if (exportDataBtn) {
    exportDataBtn.addEventListener('click', exportData);
  }
  
  if (clearAnalyticsBtn) {
    clearAnalyticsBtn.addEventListener('click', clearAnalytics);
  }
  
  if (resetExtensionBtn) {
    resetExtensionBtn.addEventListener('click', resetExtension);
  }
}

// Setup about listeners
function setupAboutListeners() {
  const viewLogsBtn = document.getElementById('view-logs');
  const contactSupportBtn = document.getElementById('contact-support');
  
  if (viewLogsBtn) {
    viewLogsBtn.addEventListener('click', () => {
      showNotification('Opening console logs...', 'info');
      // Open developer console
      chrome.tabs.create({ url: 'chrome://extensions/' });
    });
  }
  
  if (contactSupportBtn) {
    contactSupportBtn.addEventListener('click', () => {
      showNotification('Opening support contact...', 'info');
      // This would open a support page or email
    });
  }
}

// Load analytics data
async function loadAnalyticsData() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'get_analytics' });
    
    if (response && response.analytics) {
      const analytics = response.analytics;
      
      const totalScansEl = document.getElementById('total-scans');
      const threatsBlockedEl = document.getElementById('threats-blocked');
      const aiQueriesEl = document.getElementById('ai-queries');
      const accuracyEl = document.getElementById('accuracy');
      
      if (totalScansEl) totalScansEl.textContent = analytics.sitesScanned || '0';
      if (threatsBlockedEl) threatsBlockedEl.textContent = analytics.threatsBlocked || '0';
      if (aiQueriesEl) aiQueriesEl.textContent = analytics.aiQueriesUsed || '0';
      if (accuracyEl) {
        const accuracy = analytics.accuracyRate || 0;
        accuracyEl.textContent = accuracy > 0 ? `${accuracy}%` : '--%';
      }
    }
  } catch (error) {
    console.error('Error loading analytics:', error);
  }
}

// Load security lists
async function loadSecurityLists() {
  try {
    const whitelistContainer = document.getElementById('whitelist-container');
    const blocklistContainer = document.getElementById('blocklist-container');
    
    // Update whitelist display
    if (whitelistContainer) {
      if (currentSettings.security.whitelistedSites.length === 0) {
        whitelistContainer.innerHTML = '<div style="color: #6c757d; font-style: italic; padding: 10px;">No whitelisted sites</div>';
      } else {
        whitelistContainer.innerHTML = currentSettings.security.whitelistedSites.map(site => 
          `<div class="list-item">
            <span>${site}</span>
            <button onclick="removeFromWhitelist('${site}')" style="background: #dc3545; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px;">Remove</button>
          </div>`
        ).join('');
      }
    }
    
    // Update blocklist display
    if (blocklistContainer) {
      if (currentSettings.security.blockedSites.length === 0) {
        blocklistContainer.innerHTML = '<div style="color: #6c757d; font-style: italic; padding: 10px;">No blocked sites</div>';
      } else {
        blocklistContainer.innerHTML = currentSettings.security.blockedSites.map(site => 
          `<div class="list-item">
            <span>${site}</span>
            <button onclick="removeFromBlocklist('${site}')" style="background: #28a745; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px;">Unblock</button>
          </div>`
        ).join('');
      }
    }
  } catch (error) {
    console.error('Error loading security lists:', error);
  }
}

// Event handlers

async function testAIConnection() {
  try {
    const testBtn = document.getElementById('test-ai-connection');
    if (testBtn) {
      testBtn.textContent = '🧪 Testing...';
      testBtn.disabled = true;
    }
    
    // First save the current keys
    await saveAIKeys();
    
    const response = await chrome.runtime.sendMessage({
      action: 'test_ai_connection'
    });
    
    if (response && response.success) {
      const results = response.results;
      updateConnectionStatus(results);
      
      const connectedCount = Object.values(results).filter(Boolean).length;
      showNotification(`🧪 Connection test complete: ${connectedCount}/3 models connected`, 'success');
    } else {
      showNotification('❌ Connection test failed', 'error');
    }
    
  } catch (error) {
    console.error('AI connection test error:', error);
    showNotification('❌ Error testing AI connection', 'error');
  } finally {
    const testBtn = document.getElementById('test-ai-connection');
    if (testBtn) {
      testBtn.textContent = '🧪 Test AI Connection';
      testBtn.disabled = false;
    }
  }
}

async function saveAIKeys() {
  try {
    const keys = {
      primary: currentSettings.ai.primaryKey,
      secondary: currentSettings.ai.secondaryKey,
      tertiary: currentSettings.ai.tertiaryKey
    };
    
    const response = await chrome.runtime.sendMessage({
      action: 'save_ai_keys',
      keys: keys
    });
    
    if (response && response.success) {
      showNotification('🔑 AI keys saved successfully!', 'success');
      updateApiKeyStatus();
    } else {
      showNotification('❌ Failed to save AI keys', 'error');
    }
  } catch (error) {
    console.error('Save AI keys error:', error);
    showNotification('❌ Error saving AI keys', 'error');
  }
}

function addWhitelistSite() {
  const input = document.getElementById('new-whitelist-site');
  if (!input) return;
  
  const site = input.value.trim().toLowerCase();
  if (!site) {
    showNotification('Please enter a valid site', 'error');
    return;
  }
  
  if (currentSettings.security.whitelistedSites.includes(site)) {
    showNotification('Site is already whitelisted', 'warning');
    return;
  }
  
  currentSettings.security.whitelistedSites.push(site);
  input.value = '';
  loadSecurityLists();
  showNotification(`✅ Added ${site} to whitelist`, 'success');
}

function addBlockedSite() {
  const input = document.getElementById('new-blocked-site');
  if (!input) return;
  
  const site = input.value.trim().toLowerCase();
  if (!site) {
    showNotification('Please enter a valid site', 'error');
    return;
  }
  
  if (currentSettings.security.blockedSites.includes(site)) {
    showNotification('Site is already blocked', 'warning');
    return;
  }
  
  currentSettings.security.blockedSites.push(site);
  input.value = '';
  loadSecurityLists();
  showNotification(`🚫 Added ${site} to blocklist`, 'success');
}

// Global functions for remove buttons
window.removeFromWhitelist = function(site) {
  currentSettings.security.whitelistedSites = currentSettings.security.whitelistedSites.filter(s => s !== site);
  loadSecurityLists();
  showNotification(`Removed ${site} from whitelist`, 'success');
};

window.removeFromBlocklist = function(site) {
  currentSettings.security.blockedSites = currentSettings.security.blockedSites.filter(s => s !== site);
  loadSecurityLists();
  showNotification(`Unblocked ${site}`, 'success');
};

async function exportData() {
  try {
    const data = {
      settings: currentSettings,
      exportDate: new Date().toISOString(),
      version: '7.0'
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing-protector-settings-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    URL.revokeObjectURL(url);
    showNotification('📤 Settings exported successfully!', 'success');
  } catch (error) {
    console.error('Export error:', error);
    showNotification('❌ Error exporting settings', 'error');
  }
}

async function clearAnalytics() {
  if (!confirm('Are you sure you want to clear all analytics data? This cannot be undone.')) {
    return;
  }
  
  try {
    await chrome.storage.local.set({
      analytics: {
        sitesScanned: 0,
        threatsBlocked: 0,
        aiQueriesUsed: 0,
        accuracyRate: 0,
        startTime: Date.now()
      }
    });
    
    await loadAnalyticsData();
    showNotification('🗑️ Analytics cleared successfully!', 'success');
  } catch (error) {
    console.error('Clear analytics error:', error);
    showNotification('❌ Error clearing analytics', 'error');
  }
}

async function resetExtension() {
  const confirmed = confirm(
    '🔄 RESET EXTENSION\n\n' +
    'This will reset ALL settings to defaults including:\n' +
    '• All configuration settings\n' +
    '• AI API keys\n' +
    '• Whitelist and blocklist\n' +
    '• Analytics data\n\n' +
    'This action cannot be undone. Continue?'
  );
  
  if (!confirmed) return;
  
  try {
    await chrome.storage.local.clear();
    showNotification('🔄 Extension reset successfully! Reloading...', 'success');
    
    setTimeout(() => {
      location.reload();
    }, 2000);
  } catch (error) {
    console.error('Reset extension error:', error);
    showNotification('❌ Error resetting extension', 'error');
  }
}

async function saveAllSettings() {
  try {
    // Save general settings
    await chrome.runtime.sendMessage({
      action: 'update_settings',
      settings: currentSettings.general
    });
    
    // Save AI keys
    await chrome.runtime.sendMessage({
      action: 'save_ai_keys',
      keys: {
        primary: currentSettings.ai.primaryKey,
        secondary: currentSettings.ai.secondaryKey,
        tertiary: currentSettings.ai.tertiaryKey
      }
    });
    
    // Save security lists
    await chrome.storage.local.set({
      whitelistedSites: currentSettings.security.whitelistedSites,
      blockedSites: currentSettings.security.blockedSites
    });
    
    showNotification('💾 All settings saved successfully!', 'success');
    
  } catch (error) {
    console.error('Save all settings error:', error);
    showNotification('❌ Error saving settings', 'error');
  }
}

// Helper functions

function maskApiKey(key) {
  if (!key || key.length < 8) return key;
  return key.substring(0, 8) + '***' + key.substring(key.length - 4);
}

function updateApiKeyStatus() {
  const statuses = [
    { element: document.getElementById('primary-status'), key: currentSettings.ai.primaryKey },
    { element: document.getElementById('secondary-status'), key: currentSettings.ai.secondaryKey },
    { element: document.getElementById('tertiary-status'), key: currentSettings.ai.tertiaryKey }
  ];
  
  statuses.forEach(({ element, key }) => {
    if (element) {
      const dot = element.querySelector('.status-dot');
      const text = element.querySelector('.status-text');
      
      if (key && key.trim()) {
        if (dot) dot.className = 'status-dot connected';
        if (text) text.textContent = 'Configured';
      } else {
        if (dot) dot.className = 'status-dot';
        if (text) text.textContent = 'Not Configured';
      }
    }
  });
}

function updateConnectionStatus(results) {
  const statusElements = [
    { element: document.getElementById('primary-status'), connected: results.primary },
    { element: document.getElementById('secondary-status'), connected: results.secondary },
    { element: document.getElementById('tertiary-status'), connected: results.tertiary }
  ];
  
  statusElements.forEach(({ element, connected }) => {
    if (element) {
      const dot = element.querySelector('.status-dot');
      const text = element.querySelector('.status-text');
      
      if (connected) {
        if (dot) dot.className = 'status-dot connected';
        if (text) text.textContent = 'Connected';
      } else {
        if (dot) dot.className = 'status-dot error';
        if (text) text.textContent = 'Connection Failed';
      }
    }
  });
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
    z-index: 10000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    animation: slideInFromRight 0.3s ease-out;
    max-width: 300px;
  `;
  
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 4000);
}

// Add CSS for notification animation
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

console.log('✅ Ultimate Advanced Phishing Protector Pro - Settings script loaded successfully!');