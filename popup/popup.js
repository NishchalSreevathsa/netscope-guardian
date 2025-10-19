// NetScope Guardian Popup - COMPLETE WORKING VERSION
console.log('Popup script loading...');

class NetScopePopup {
  constructor() {
    this.backendUrl = 'http://localhost:8000';
    this.currentTab = null;
    console.log('NetScopePopup initialized');
    this.init();
  }
  
  async init() {
    console.log('Init started');
    await this.loadCurrentTab();
    this.setupEventListeners();
    this.checkBackendConnection();
    this.loadPageStats();
  }
  
  setupEventListeners() {
    console.log('Setting up event listeners');
    
    const openDashboard = document.getElementById('open-dashboard');
    if (openDashboard) {
      openDashboard.addEventListener('click', () => {
        console.log('Open Dashboard clicked');
        this.openDashboard();
      });
    }
    
    const analyzePage = document.getElementById('analyze-page');
    if (analyzePage) {
      analyzePage.addEventListener('click', () => {
        console.log('Analyze Page clicked');
        this.analyzePage();
      });
    }
    
    const quickScan = document.getElementById('quick-scan');
    if (quickScan) {
      quickScan.addEventListener('click', () => {
        console.log('Quick Scan clicked');
        this.quickScan();
      });
    }
  }
  
  async openDashboard() {
    try {
      console.log('Opening dashboard...');
      const tab = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab[0]) {
        try {
          if (chrome.sidePanel && chrome.sidePanel.open) {
            await chrome.sidePanel.open({ tabId: tab[0].id });
          } else {
            await chrome.tabs.create({ url: chrome.runtime.getURL('sidebar/sidebar.html') });
          }
        } catch (err) {
          await chrome.tabs.create({ url: chrome.runtime.getURL('sidebar/sidebar.html') });
        }
        window.close();
      }
    } catch (error) {
      console.error('Failed to open dashboard:', error);
      alert('Failed to open dashboard: ' + error.message);
    }
  }
  
  async analyzePage() {
    try {
      console.log('Analyzing page...');
      if (!this.currentTab || !this.currentTab.url) {
        alert('Cannot access current tab');
        return;
      }
      
      if (this.currentTab.url.startsWith('chrome://')) {
        alert('Cannot analyze Chrome system pages');
        return;
      }
      
      this.setButtonLoading('analyze-page', true);
      
      const response = await fetch(`${this.backendUrl}/headers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: this.currentTab.url })
      });
      
      if (!response.ok) {
        throw new Error(`Backend error: ${response.status}`);
      }
      
      const analysis = await response.json();
      this.showAnalysisResults(analysis);
      
    } catch (error) {
      console.error('Page analysis failed:', error);
      alert('Page analysis failed: ' + error.message);
    } finally {
      this.setButtonLoading('analyze-page', false);
    }
  }
  
  async quickScan() {
    try {
      console.log('Quick scanning...');
      if (!this.currentTab) {
        alert('Cannot access current tab');
        return;
      }
      
      this.setButtonLoading('quick-scan', true);
      
      const results = await chrome.scripting.executeScript({
        target: { tabId: this.currentTab.id },
        function: () => {
          const patterns = {
            IP: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
            DOMAIN: /\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z]{2,}\b/g,
            EMAIL: /\b[^\s@]+@[^\s@]+\.[^\s@]+\b/g
          };
          const text = document.body.textContent || '';
          const indicators = [];
          Object.entries(patterns).forEach(([type, pattern]) => {
            const matches = [...new Set(text.match(pattern) || [])].slice(0, 5);
            matches.forEach(m => indicators.push({ type, text: m }));
          });
          return { count: indicators.length, types: [...new Set(indicators.map(i => i.type))] };
        }
      });
      
      const result = results && results[0] && results[0].result ? results[0].result : { count: 0 };
      
      if (result.count > 0) {
        alert(`Found ${result.count} indicators: ${result.types.join(', ')}`);
      } else {
        alert('No security indicators found on this page');
      }
      
    } catch (error) {
      console.error('Quick scan failed:', error);
      alert('Quick scan failed: ' + error.message);
    } finally {
      this.setButtonLoading('quick-scan', false);
    }
  }
  
  async loadCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;
      console.log('Current tab loaded:', tab);
      
      if (tab && tab.url) {
        const url = new URL(tab.url);
        document.getElementById('page-url').textContent = url.hostname;
        this.updateSecurityBadge(tab.url);
      }
    } catch (error) {
      console.error('Failed to load tab:', error);
    }
  }
  
  updateSecurityBadge(url) {
    const badge = document.getElementById('security-badge');
    const status = document.getElementById('security-status');
    
    if (url.startsWith('https:')) {
      badge.className = 'security-badge secure';
      status.textContent = 'Secure';
    } else if (url.startsWith('http:')) {
      badge.className = 'security-badge warning';
      status.textContent = 'Not Secure';
    } else {
      badge.className = 'security-badge checking';
      status.textContent = 'System Page';
    }
  }
  
  async checkBackendConnection() {
    const indicator = document.getElementById('status-indicator');
    try {
      const response = await fetch(`${this.backendUrl}/health`, { method: 'GET' });
      if (response.ok) {
        indicator.className = 'status-indicator';
        indicator.title = 'Backend Connected';
      } else {
        throw new Error('Backend error');
      }
    } catch (error) {
      indicator.className = 'status-indicator disconnected';
      indicator.title = 'Backend Disconnected';
    }
  }
  
  async loadPageStats() {
    try {
      const data = await chrome.runtime.sendMessage({ type: 'GET_NETWORK_ACTIVITY' });
      if (data) {
        document.getElementById('request-count').textContent = data.requests?.length || 0;
        document.getElementById('threat-count').textContent = data.suspicious?.length || 0;
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }
  
  setButtonLoading(buttonId, loading) {
    const button = document.getElementById(buttonId);
    if (!button) return;
    
    const icon = button.querySelector('.btn-icon');
    const title = button.querySelector('.btn-title');
    
    if (loading) {
      button.disabled = true;
      button.style.opacity = '0.7';
      if (icon) icon.textContent = '⏳';
      if (title) title.textContent = 'Loading...';
    } else {
      button.disabled = false;
      button.style.opacity = '1';
      if (buttonId === 'analyze-page' && icon && title) {
        icon.textContent = '🔍';
        title.textContent = 'Analyze Page';
      } else if (buttonId === 'quick-scan' && icon && title) {
        icon.textContent = '⚡';
        title.textContent = 'Quick Scan';
      }
    }
  }
  
  showAnalysisResults(analysis) {
    const msg = `Security Analysis Complete!\n\nURL: ${analysis.url}\nSecurity Score: ${analysis.security_score}/100\n\n${analysis.gemini_analysis ? analysis.gemini_analysis.substring(0, 200) + '...' : 'Analysis completed'}`;
    alert(msg);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, creating popup');
  window.netScopePopup = new NetScopePopup();
});