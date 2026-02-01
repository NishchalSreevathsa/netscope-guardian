// NetScope Guardian Background Service Worker
const BACKEND_URL = 'http://localhost:8080'; // FIXED: Port 8080
let networkRequests = [];
let suspiciousActivity = [];

chrome.runtime.onInstalled.addListener(() => {
  console.log('NetScope Guardian installed');
  chrome.contextMenus.create({
    id: "analyze-indicator",
    title: "🛡️ Analyze with NetScope Guardian",
    contexts: ["selection"]
  });
  chrome.storage.local.set({ theme: 'dark', notifications: true, analysisHistory: [] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "analyze-indicator" && info.selectionText) {
    const indicator = info.selectionText.trim();
    console.log('Analyzing indicator:', indicator);
    try {
      const analysis = await analyzeIndicator(indicator);
      await chrome.storage.local.set({
        lastAnalysis: { indicator, analysis, timestamp: Date.now(), url: tab.url }
      });
      try {
        if (chrome.sidePanel && chrome.sidePanel.open) {
          await chrome.sidePanel.open({ tabId: tab.id });
        } else {
          await chrome.tabs.create({ url: chrome.runtime.getURL('sidebar/sidebar.html') });
        }
      } catch (err) {
        await chrome.tabs.create({ url: chrome.runtime.getURL('sidebar/sidebar.html') });
      }
      setTimeout(() => {
        chrome.runtime.sendMessage({
          type: 'ANALYSIS_RESULT',
          data: { indicator, analysis, timestamp: Date.now(), url: tab.url }
        }).catch(() => console.log('Message sent'));
      }, 1000);
    } catch (error) {
      console.error('Analysis failed:', error);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'NetScope Guardian',
        message: `Analysis failed: ${error.message}`
      });
    }
  }
});

chrome.webRequest.onBeforeRequest.addListener((details) => {
  const request = {
    url: details.url,
    method: details.method,
    timestamp: details.timeStamp,
    tabId: details.tabId,
    type: details.type
  };
  networkRequests.push(request);
  if (isSuspiciousRequest(request)) {
    suspiciousActivity.push({
      ...request,
      reason: getSuspiciousReason(request),
      severity: getSeverityLevel(request)
    });
  }
  if (networkRequests.length > 100) networkRequests = networkRequests.slice(-100);
  if (suspiciousActivity.length > 50) suspiciousActivity = suspiciousActivity.slice(-50);
}, { urls: ["<all_urls>"] }, ["requestBody"]);

async function analyzeIndicator(indicator) {
  try {
    const response = await fetch(`${BACKEND_URL}/threat-summary`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator })
    });
    if (!response.ok) throw new Error(`Backend error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return {
      indicator,
      type: detectIndicatorType(indicator),
      threat_score: 'Unknown',
      gemini_analysis: `Analysis unavailable: ${error.message}. Ensure backend is running at ${BACKEND_URL}`,
      reputation_data: { error: error.message },
      recommendations: ['Start backend: cd backend && python main.py', 'Check Gemini API key'],
      timestamp: new Date().toISOString(),
      sources: ['Manual verification needed']
    };
  }
}

async function analyzeSecurityHeadersForTab(tabId, url) {
  try {
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      throw new Error('Cannot analyze Chrome system pages');
    }
    const response = await fetch(`${BACKEND_URL}/headers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!response.ok) throw new Error(`Backend error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return {
      url,
      headers: {},
      missing_headers: ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options'],
      security_score: 0,
      gemini_analysis: `Unable to analyze: ${error.message}`,
      recommendations: ['Ensure backend is running', 'Check API key'],
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
}

function isSuspiciousRequest(request) {
  const url = request.url.toLowerCase();
  const safe = ['linkedin.com/li/track', 'google-analytics.com', 'doubleclick.net'];
  if (safe.some(p => url.includes(p))) return false;
  const suspicious = [/\/api\/(send|upload).*cred/i, /\.(tk|ml|ga)\/.*\.(exe|zip)/i, /keylog/i];
  return suspicious.some(p => p.test(url));
}

function getSuspiciousReason(request) {
  const url = request.url.toLowerCase();
  if (url.includes('cred')) return 'Potential credential harvesting';
  if (url.includes('keylog')) return 'Potential keylogger activity';
  return 'Pattern match on threat indicators';
}

function getSeverityLevel(request) {
  const url = request.url.toLowerCase();
  if (url.includes('cred') || url.includes('keylog')) return 'HIGH';
  return 'MEDIUM';
}

function detectIndicatorType(indicator) {
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(indicator)) return 'IP';
  if (/^https?:\/\/.+/.test(indicator)) return 'URL';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(indicator)) return 'EMAIL';
  if (/^[a-fA-F0-9]{32,64}$/.test(indicator)) return 'HASH';
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(indicator)) return 'DOMAIN';
  return 'UNKNOWN';
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background message:', request.type);
  if (request.type === 'GET_NETWORK_ACTIVITY') {
    sendResponse({ requests: networkRequests.slice(-20), suspicious: suspiciousActivity.slice(-10) });
  } else if (request.type === 'ANALYZE_HEADERS') {
    analyzeSecurityHeadersForTab(request.tabId, request.url).then(sendResponse);
    return true;
  } else if (request.type === 'ANALYZE_INDICATOR') {
    analyzeIndicator(request.indicator).then(sendResponse);
    return true;
  }
  return false;
});