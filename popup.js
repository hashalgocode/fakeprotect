// Advanced Real-time Threat Intelligence Dashboard

console.log('🚀 Loading Perfect Phishing Protector Pro Popup v8.0...');

// ===== STATE MANAGEMENT =====
let currentSiteData = null;
let settingsVisible = false;
let apiConfigVisible = false;
let currentApiKeys = {
  googleSafeBrowsing: 'add ur key',
  virusTotal: 'add ur key',
};

// ===== DOM ELEMENTS CACHE =====
const elements = {
  // Basic status elements
  currentSite: null,
  siteStatus: null,
  scoreValue: null,
  confidenceLevel: null,
  recommendedAction: null,
  
  // Advanced analysis elements
  heuristicScore: null,
  threatIntelSources: null,
  reputationScore: null,
  processingTime: null,
  
  // Threat details
  threatDetails: null,
  threatList: null,
  threatCount: null,
  
  // Action buttons
  whitelistBtn: null,
  reportThreatBtn: null,
  reportSafeBtn: null,
  forceReanalyzeBtn: null,
  settingsBtn: null,
  apiSettingsBtn: null,
  
  // API configuration
  apiKeyInputs: {},
  apiStatusIndicators: {},
  testApisBtn: null,
  saveApiKeysBtn: null,
  
  // Settings toggles
  settingsToggles: {},
  
  // Analytics display
  sitesScanned: null,
  threatsBlocked: null,
  accuracyRate: null,
  uptime: null
};

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', initializePerfectPopup);

async function initializePerfectPopup() {
  console.log('🔧 Initializing Perfect Phishing Protector Pro Popup...');
  
  try {
    // Cache DOM elements
    cacheAllElements();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load API keys and settings
    await loadApiKeysAndSettings();
    
    // Load current site data
    await loadCurrentSiteData();
    
    // Update complete interface
    updateCompleteInterface();
    
    // Load analytics
    await loadAnalytics();
    
    // Setup auto-refresh for real-time updates
    setupAutoRefresh();
    
    console.log('✅ Perfect popup initialized successfully!');
    
  } catch (error) {
    console.error('❌ Error initializing perfect popup:', error);
    showNotification('Failed to initialize. Please refresh.', 'error');
  }
}

// ===== DOM ELEMENT CACHING =====
function cacheAllElements() {
  // Basic status elements
  elements.currentSite = document.getElementById('current-site');
  elements.siteStatus = document.getElementById('site-status');
  elements.scoreValue = document.getElementById('score-value');
  elements.confidenceLevel = document.getElementById('confidence-level');
  elements.recommendedAction = document.getElementById('recommended-action');
  
  // Advanced analysis elements
  elements.heuristicScore = document.getElementById('heuristic-score');
  elements.threatIntelSources = document.getElementById('threat-intel-sources');
  elements.reputationScore = document.getElementById('reputation-score');
  elements.processingTime = document.getElementById('processing-time');
  
  // Threat details
  elements.threatDetails = document.getElementById('threat-details');
  elements.threatList = document.getElementById('threat-list');
  elements.threatCount = document.getElementById('threat-count');
  
  // Action buttons
  elements.whitelistBtn = document.getElementById('whitelist-btn');
  elements.reportThreatBtn = document.getElementById('report-threat-btn');
  elements.reportSafeBtn = document.getElementById('report-safe-btn');
  elements.forceReanalyzeBtn = document.getElementById('force-reanalyze-btn');
  elements.settingsBtn = document.getElementById('settings-btn');
  elements.apiSettingsBtn = document.getElementById('api-settings-btn');
  
  // API configuration elements
  const apiTypes = ['googleSafeBrowsing','virusTotal'];
  apiTypes.forEach(apiType => {
    elements.apiKeyInputs[apiType] = document.getElementById(`${apiType}-api-key`);
    elements.apiStatusIndicators[apiType] = document.getElementById(`${apiType}-status`);
  });
  
  elements.testApisBtn = document.getElementById('test-apis-btn');
  elements.saveApiKeysBtn = document.getElementById('save-api-keys-btn');
  
  // Settings toggles
  const toggles = ['heuristicAnalysis', 'threatIntelligence', 'dynamicReputation', 
                   'realTimeScanning', 'aggressiveMode', 'enableNotifications'];
  toggles.forEach(toggle => {
    elements.settingsToggles[toggle] = document.getElementById(`toggle-${toggle}`);
  });
  
  // Analytics elements
  elements.sitesScanned = document.getElementById('sites-scanned');
  elements.threatsBlocked = document.getElementById('threats-blocked');
  elements.accuracyRate = document.getElementById('accuracy-rate');
  elements.uptime = document.getElementById('uptime');
  
  console.log('✅ All DOM elements cached successfully');
}

// ===== EVENT LISTENERS =====
function setupEventListeners() {
  // Action buttons
  if (elements.whitelistBtn) {
    elements.whitelistBtn.addEventListener('click', handleWhitelistSite);
  }
  
  if (elements.reportThreatBtn) {
    elements.reportThreatBtn.addEventListener('click', () => handleReportSite(true));
  }
  
  if (elements.reportSafeBtn) {
    elements.reportSafeBtn.addEventListener('click', () => handleReportSite(false));
  }
  
  if (elements.forceReanalyzeBtn) {
    elements.forceReanalyzeBtn.addEventListener('click', handleForceReanalyze);
  }
  
  if (elements.settingsBtn) {
    elements.settingsBtn.addEventListener('click', toggleSettings);
  }
  
  if (elements.apiSettingsBtn) {
    elements.apiSettingsBtn.addEventListener('click', toggleApiSettings);
  }
  
  // API configuration buttons
  if (elements.testApisBtn) {
    elements.testApisBtn.addEventListener('click', handleTestApis);
  }
  
  if (elements.saveApiKeysBtn) {
    elements.saveApiKeysBtn.addEventListener('click', handleSaveApiKeys);
  }
  
  // Settings toggles
  Object.values(elements.settingsToggles).forEach(toggle => {
    if (toggle) {
      toggle.addEventListener('change', handleSettingsChange);
    }
  });
  
  console.log('✅ Event listeners setup complete');
}

// ===== LOAD API KEYS AND SETTINGS =====
async function loadApiKeysAndSettings() {
  try {
    const { threatApiKeys, settings } = await chrome.storage.local.get(['threatApiKeys', 'settings']);
    
    // Load API keys
    if (threatApiKeys) {
      currentApiKeys = { ...currentApiKeys, ...threatApiKeys };
      
      // Update API key inputs (mask for security)
      Object.entries(currentApiKeys).forEach(([apiType, key]) => {
        const input = elements.apiKeyInputs[apiType];
        if (input && key) {
          input.value = maskApiKey(key);
        }
      });
      
      updateApiKeyStatus();
    }
    
    // Load settings
    if (settings) {
      Object.entries(elements.settingsToggles).forEach(([setting, toggle]) => {
        if (toggle && settings[setting] !== undefined) {
          toggle.checked = settings[setting];
        }
      });
    }
    
  } catch (error) {
    console.error('Error loading API keys and settings:', error);
  }
}

// ===== LOAD CURRENT SITE DATA =====
async function loadCurrentSiteData() {
  try {
    showLoadingState();
    
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      throw new Error('Cannot access current tab');
    }
    
    const url = new URL(tab.url);
    const hostname = url.hostname;
    
    console.log('📍 Loading perfect analysis for:', hostname);
    
    // Request site status from background script
    const response = await chrome.runtime.sendMessage({
      action: 'get_site_status',
      hostname: hostname
    });
    
    if (response && !response.error) {
      currentSiteData = {
        hostname: hostname,
        ...response
      };
      console.log('✅ Perfect site data loaded:', currentSiteData);
    } else {
      console.warn('⚠️ No data received, using defaults');
      currentSiteData = getDefaultSiteData(hostname);
    }
    
  } catch (error) {
    console.error('❌ Failed to load site data:', error);
    currentSiteData = getDefaultSiteData('unknown');
  } finally {
    hideLoadingState();
  }
}

// ===== GET DEFAULT SITE DATA =====
function getDefaultSiteData(hostname) {
  return {
    hostname: hostname,
    finalScore: 75,
    riskLevel: 'SAFE',
    confidence: 70,
    heuristic: { score: 75, threats: [] },
    threatIntelligence: { overallThreat: false, sources: [], confidence: 0 },
    reputation: { score: 75, source: 'default' },
    processingTime: 0,
    threatsDetected: [],
    recommendedAction: 'allow',
    version: '8.0-perfect'
  };
}

// ===== UPDATE COMPLETE INTERFACE =====
function updateCompleteInterface() {
  try {
    if (!currentSiteData) return;
    
    updateBasicStatus();
    updateAdvancedAnalysis();
    updateThreatDetails();
    updateActionButtons();
    
    console.log('✅ Interface updated successfully');
    
  } catch (error) {
    console.error('❌ Failed to update interface:', error);
  }
}

// ===== UPDATE BASIC STATUS =====
function updateBasicStatus() {
  // Update hostname
  if (elements.currentSite) {
    elements.currentSite.textContent = currentSiteData.hostname || 'Unknown';
  }
  
  // Update status with enhanced styling
  if (elements.siteStatus) {
    const statusText = formatStatusText(currentSiteData.riskLevel);
    elements.siteStatus.textContent = statusText;
    elements.siteStatus.className = `site-status status-${getRiskLevelClass(currentSiteData.riskLevel)}`;
  }
  
  // Update score with visual indicator
  if (elements.scoreValue) {
    const score = Math.round(currentSiteData.finalScore || 0);
    elements.scoreValue.textContent = `${score}/100`;
    elements.scoreValue.className = `score-value ${getScoreClass(score)}`;
  }
  
  // Update confidence
  if (elements.confidenceLevel) {
    const confidence = Math.round(currentSiteData.confidence || 0);
    elements.confidenceLevel.textContent = `${confidence}%`;
  }
  
  // Update recommended action
  if (elements.recommendedAction) {
    const action = currentSiteData.recommendedAction || 'allow';
    elements.recommendedAction.textContent = formatActionText(action);
    elements.recommendedAction.className = `recommended-action action-${action}`;
  }
}

// ===== UPDATE ADVANCED ANALYSIS =====
function updateAdvancedAnalysis() {
  // Update heuristic score
  if (elements.heuristicScore) {
    const hScore = currentSiteData.heuristic?.score || 0;
    elements.heuristicScore.textContent = `${Math.round(hScore)}/100`;
    elements.heuristicScore.className = `analysis-score ${getScoreClass(hScore)}`;
  }
  
  // Update threat intelligence sources
  if (elements.threatIntelSources) {
    const sources = currentSiteData.threatIntelligence?.sources || [];
    if (sources.length > 0) {
      elements.threatIntelSources.textContent = sources.join(', ');
      elements.threatIntelSources.className = 'threat-sources detected';
    } else {
      elements.threatIntelSources.textContent = 'No threats detected';
      elements.threatIntelSources.className = 'threat-sources clean';
    }
  }
  
  // Update reputation score
  if (elements.reputationScore) {
    const repScore = currentSiteData.reputation?.score || 0;
    elements.reputationScore.textContent = `${Math.round(repScore)}/100`;
    elements.reputationScore.className = `analysis-score ${getScoreClass(repScore)}`;
  }
  
  // Update processing time
  if (elements.processingTime) {
    const time = Math.round(currentSiteData.processingTime || 0);
    elements.processingTime.textContent = `${time}ms`;
  }
}

// ===== UPDATE THREAT DETAILS =====
function updateThreatDetails() {
  const threats = currentSiteData.threatsDetected || [];
  
  // Update threat count
  if (elements.threatCount) {
    elements.threatCount.textContent = threats.length;
    elements.threatCount.className = `threat-count ${threats.length > 0 ? 'has-threats' : 'clean'}`;
  }
  
  // Update threat list
  if (elements.threatList) {
    if (threats.length === 0) {
      elements.threatList.innerHTML = '<div class="no-threats">✅ No threats detected</div>';
    } else {
      elements.threatList.innerHTML = threats.slice(0, 5).map(threat => 
        `<div class="threat-item">${escapeHtml(threat)}</div>`
      ).join('');
      
      if (threats.length > 5) {
        elements.threatList.innerHTML += `<div class="threat-more">... and ${threats.length - 5} more threats</div>`;
      }
    }
  }
  
  // Show/hide threat details section
  if (elements.threatDetails) {
    elements.threatDetails.style.display = threats.length > 0 ? 'block' : 'none';
  }
}

// ===== UPDATE ACTION BUTTONS =====
function updateActionButtons() {
  const riskLevel = currentSiteData.riskLevel;
  const score = currentSiteData.finalScore || 0;
  
  // Update whitelist button
  if (elements.whitelistBtn) {
    elements.whitelistBtn.disabled = (riskLevel === 'TRUSTED');
    elements.whitelistBtn.textContent = riskLevel === 'TRUSTED' ? 'Already Trusted' : '✅ Whitelist Site';
  }
  
  // Update report buttons based on current status
  if (elements.reportThreatBtn) {
    elements.reportThreatBtn.disabled = (riskLevel === 'CRITICAL');
    elements.reportThreatBtn.textContent = riskLevel === 'CRITICAL' ? 'Already Reported' : '🚨 Report Threat';
  }
  
  if (elements.reportSafeBtn) {
    elements.reportSafeBtn.disabled = (riskLevel === 'TRUSTED' || riskLevel === 'SAFE');
  }
}

// ===== EVENT HANDLERS =====
async function handleWhitelistSite() {
  try {
    showButtonLoading(elements.whitelistBtn);
    
    const response = await chrome.runtime.sendMessage({
      action: 'add_to_whitelist',
      hostname: currentSiteData.hostname
    });
    
    if (response.success) {
      showNotification('✅ Site whitelisted successfully!', 'success');
      await reloadCurrentSiteData();
    } else {
      throw new Error('Failed to whitelist site');
    }
    
  } catch (error) {
    console.error('Whitelist error:', error);
    showNotification('❌ Failed to whitelist site', 'error');
  } finally {
    hideButtonLoading(elements.whitelistBtn, '✅ Whitelist Site');
  }
}

async function handleReportSite(isThreat) {
  try {
    const button = isThreat ? elements.reportThreatBtn : elements.reportSafeBtn;
    showButtonLoading(button);
    
    const response = await chrome.runtime.sendMessage({
      action: 'report_threat',
      hostname: currentSiteData.hostname,
      isMalicious: isThreat
    });
    
    if (response.success) {
      const message = isThreat ? '🚨 Threat reported successfully!' : '✅ Marked as safe successfully!';
      showNotification(message, 'success');
      await reloadCurrentSiteData();
    } else {
      throw new Error('Failed to report site');
    }
    
  } catch (error) {
    console.error('Report error:', error);
    showNotification('❌ Failed to report site', 'error');
  } finally {
    const button = isThreat ? elements.reportThreatBtn : elements.reportSafeBtn;
    const originalText = isThreat ? '🚨 Report Threat' : '✅ Report Safe';
    hideButtonLoading(button, originalText);
  }
}

async function handleForceReanalyze() {
  try {
    showButtonLoading(elements.forceReanalyzeBtn);
    
    const response = await chrome.runtime.sendMessage({
      action: 'force_reanalyze',
      hostname: currentSiteData.hostname
    });
    
    if (response.success) {
      showNotification('🔄 Re-analysis initiated...', 'info');
      
      // Wait a moment then reload data
      setTimeout(async () => {
        await reloadCurrentSiteData();
        showNotification('✅ Analysis complete!', 'success');
      }, 2000);
    } else {
      throw new Error('Failed to trigger re-analysis');
    }
    
  } catch (error) {
    console.error('Re-analyze error:', error);
    showNotification('❌ Failed to re-analyze site', 'error');
  } finally {
    hideButtonLoading(elements.forceReanalyzeBtn, '🔄 Force Re-analyze');
  }
}

async function handleSaveApiKeys() {
  try {
    showButtonLoading(elements.saveApiKeysBtn);
    
    // Collect API keys from inputs
    const newKeys = {};
    Object.entries(elements.apiKeyInputs).forEach(([apiType, input]) => {
      if (input && input.value && !input.value.includes('***')) {
        newKeys[apiType] = input.value.trim();
      }
    });
    
    const response = await chrome.runtime.sendMessage({
      action: 'save_threat_api_keys',
      keys: newKeys
    });
    
    if (response.success) {
      currentApiKeys = { ...currentApiKeys, ...newKeys };
      showNotification('✅ API keys saved successfully!', 'success');
      updateApiKeyStatus();
      
      // Re-mask the inputs
      Object.entries(newKeys).forEach(([apiType, key]) => {
        const input = elements.apiKeyInputs[apiType];
        if (input) {
          input.value = maskApiKey(key);
        }
      });
    } else {
      throw new Error('Failed to save API keys');
    }
    
  } catch (error) {
    console.error('Save API keys error:', error);
    showNotification('❌ Failed to save API keys', 'error');
  } finally {
    hideButtonLoading(elements.saveApiKeysBtn, '💾 Save API Keys');
  }
}

async function handleTestApis() {
  try {
    showButtonLoading(elements.testApisBtn);
    
    const response = await chrome.runtime.sendMessage({
      action: 'test_threat_apis'
    });
    
    if (response.success) {
      showNotification('🧪 API test completed!', 'success');
      updateApiKeyStatus(response.results);
    } else {
      throw new Error('Failed to test APIs');
    }
    
  } catch (error) {
    console.error('Test APIs error:', error);
    showNotification('❌ Failed to test APIs', 'error');
  } finally {
    hideButtonLoading(elements.testApisBtn, '🧪 Test APIs');
  }
}

async function handleSettingsChange() {
  try {
    const settings = {};
    
    Object.entries(elements.settingsToggles).forEach(([setting, toggle]) => {
      if (toggle) {
        settings[setting] = toggle.checked;
      }
    });
    
    const response = await chrome.runtime.sendMessage({
      action: 'update_settings',
      settings
    });
    
    if (response.success) {
      showNotification('⚙️ Settings updated!', 'info');
    }
    
  } catch (error) {
    console.error('Settings update error:', error);
  }
}

// ===== UTILITY FUNCTIONS =====
async function reloadCurrentSiteData() {
  await loadCurrentSiteData();
  updateCompleteInterface();
}

function maskApiKey(key) {
  if (!key || key.length < 8) return key;
  return key.substring(0, 4) + '***' + key.substring(key.length - 4);
}

function updateApiKeyStatus(testResults = {}) {
  Object.entries(elements.apiStatusIndicators).forEach(([apiType, indicator]) => {
    if (indicator) {
      const hasKey = currentApiKeys[apiType] && currentApiKeys[apiType].trim();
      const testResult = testResults[apiType];
      
      if (testResult !== undefined) {
        // Use test results
        indicator.className = `api-status ${testResult ? 'connected' : 'error'}`;
        indicator.textContent = testResult ? '✅ Connected' : '❌ Failed';
      } else if (hasKey) {
        // Has key but not tested
        indicator.className = 'api-status configured';
        indicator.textContent = '🔑 Configured';
      } else {
        // No key
        indicator.className = 'api-status missing';
        indicator.textContent = '⚠️ Missing';
      }
    }
  });
}

function formatStatusText(riskLevel) {
  const statusMap = {
    'TRUSTED': 'TRUSTED',
    'SAFE': 'SAFE',
    'LOW_RISK': 'LOW RISK',
    'MEDIUM_RISK': 'MEDIUM RISK',
    'HIGH_RISK': 'HIGH RISK',
    'CRITICAL': 'CRITICAL'
  };
  return statusMap[riskLevel] || 'UNKNOWN';
}

function formatActionText(action) {
  const actionMap = {
    'allow': 'ALLOW',
    'caution': 'CAUTION',
    'warn': 'WARN',
    'block': 'BLOCK'
  };
  return actionMap[action] || 'UNKNOWN';
}

function getRiskLevelClass(riskLevel) {
  return riskLevel.toLowerCase().replace('_', '-');
}

function getScoreClass(score) {
  if (score >= 80) return 'excellent';
  if (score >= 60) return 'good';
  if (score >= 40) return 'warning';
  return 'danger';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ===== TOGGLE FUNCTIONS =====
function toggleSettings() {
  settingsVisible = !settingsVisible;
  const settingsPanel = document.getElementById('settings-panel');
  if (settingsPanel) {
    settingsPanel.style.display = settingsVisible ? 'block' : 'none';
  }
}

function toggleApiSettings() {
  apiConfigVisible = !apiConfigVisible;
  const apiPanel = document.getElementById('api-config-panel');
  if (apiPanel) {
    apiPanel.style.display = apiConfigVisible ? 'block' : 'none';
  }
}

// ===== LOADING STATES =====
function showLoadingState() {
  const loader = document.getElementById('loading-indicator');
  if (loader) loader.style.display = 'block';
}

function hideLoadingState() {
  const loader = document.getElementById('loading-indicator');
  if (loader) loader.style.display = 'none';
}

function showButtonLoading(button) {
  if (button) {
    button.disabled = true;
    button.innerHTML = '⏳ Loading...';
  }
}

function hideButtonLoading(button, originalText) {
  if (button) {
    button.disabled = false;
    button.innerHTML = originalText;
  }
}

// ===== NOTIFICATIONS =====
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.classList.add('show');
  }, 100);
  
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, 3000);
}

// ===== LOAD ANALYTICS =====
async function loadAnalytics() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'get_analytics' });
    if (response && response.analytics) {
      const analytics = response.analytics;
      
      if (elements.sitesScanned) {
        elements.sitesScanned.textContent = analytics.sitesScanned || 0;
      }
      
      if (elements.threatsBlocked) {
        elements.threatsBlocked.textContent = analytics.threatsBlocked || 0;
      }
      
      if (elements.accuracyRate) {
        elements.accuracyRate.textContent = `${analytics.accuracyRate || 0}%`;
      }
      
      if (elements.uptime) {
        const uptimeHours = Math.round((Date.now() - (analytics.startTime || Date.now())) / (1000 * 60 * 60));
        elements.uptime.textContent = `${uptimeHours}h`;
      }
    }
  } catch (error) {
    console.error('Failed to load analytics:', error);
  }
}

// ===== AUTO-REFRESH FOR REAL-TIME UPDATES =====
function setupAutoRefresh() {
  // Refresh data every 30 seconds for real-time updates
  setInterval(async () => {
    try {
      await reloadCurrentSiteData();
      await loadAnalytics();
    } catch (error) {
      console.warn('Auto-refresh error:', error);
    }
  }, 30000);
}

console.log('🎯 Perfect Phishing Protector Pro Popup v8.0 Loaded!');