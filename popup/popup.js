// NetScope Guardian Popup - FIXED VERSION
console.log('Popup script loading...');

class NetScopePopup {
  constructor() {
    this.backendUrl = 'http://localhost:8080'; // FIXED: Port 8080
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

      // Store analysis and open dashboard
      await chrome.storage.local.set({
        lastHeadersAnalysis: {
          url: this.currentTab.url,
          analysis: analysis,
          timestamp: Date.now()
        }
      });

      // Open dashboard to show results
      await this.openDashboard();

    } catch (error) {
      console.error('Page analysis failed:', error);
      alert('Analysis failed: ' + error.message + '\n\nMake sure backend is running at ' + this.backendUrl);
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
            DOMAIN: /\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b/g,
            EMAIL: /\b[^\s@]+@[^\s@]+\.[^\s@]+\b/g,
            HASH: /\b[a-fA-F0-9]{32,64}\b/g
          };

          const text = document.body.textContent || '';
          const found = {};
          const indicators = [];

          Object.entries(patterns).forEach(([type, pattern]) => {
            const matches = [...new Set(text.match(pattern) || [])];
            if (matches.length > 0) {
              found[type] = matches.slice(0, 5); // First 5 of each type
              indicators.push(...matches.slice(0, 5).map(m => ({ type, value: m })));
            }
          });

          return {
            count: indicators.length,
            types: Object.keys(found),
            indicators: indicators,
            found: found
          };
        }
      });

      const result = results && results[0] && results[0].result ? results[0].result : { count: 0 };

      if (result.count > 0) {
        // Create detailed message with found indicators
        let html = `<div class="scan-result-success">🔍 Found ${result.count} indicators:</div>`;
        html += '<ul class="scan-list">';

        Object.entries(result.found || {}).forEach(([type, values]) => {
          html += `<li><strong>${type}:</strong> ${values.length}</li>`;
          values.slice(0, 3).forEach(v => {
            html += `<li class="scan-item-value">${v}</li>`;
          });
        });
        html += '</ul><div class="scan-tip">💡 Tip: Open Dashboard to manage</div>';

        // Show in UI instead of alert
        const container = document.querySelector('.quick-actions');
        let resultDiv = document.getElementById('scan-results');
        if (!resultDiv) {
          resultDiv = document.createElement('div');
          resultDiv.id = 'scan-results';
          container.parentNode.insertBefore(resultDiv, container.nextSibling);
        }
        resultDiv.innerHTML = html;
        resultDiv.style.display = 'block';

      } else {
        const container = document.querySelector('.quick-actions');
        let resultDiv = document.getElementById('scan-results');
        if (!resultDiv) {
          resultDiv = document.createElement('div');
          resultDiv.id = 'scan-results';
          container.parentNode.insertBefore(resultDiv, container.nextSibling);
        }
        resultDiv.innerHTML = '<div class="scan-result-empty">✅ No sensitive indicators found.</div>';
        resultDiv.style.display = 'block';
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
        document.getElementById('page-url').textContent = url.hostname || url.href;
        this.updateSecurityBadge(tab.url);
      }
    } catch (error) {
      console.error('Failed to load tab:', error);
    }
  }

  // FIX #5: Better security status detection
  updateSecurityBadge(url) {
    const badge = document.getElementById('security-badge');
    const status = document.getElementById('security-status');

    if (url.startsWith('https:')) {
      // HTTPS doesn't automatically mean secure
      badge.className = 'security-badge checking';
      status.textContent = 'HTTPS';
    } else if (url.startsWith('http:')) {
      badge.className = 'security-badge danger';
      status.textContent = 'Not Secure';
    } else if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      badge.className = 'security-badge checking';
      status.textContent = 'System Page';
    } else {
      badge.className = 'security-badge checking';
      status.textContent = 'Unknown';
    }
  }

  async checkBackendConnection() {
    const indicator = document.getElementById('status-indicator');
    try {
      const response = await fetch(`${this.backendUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(3000) // 3 second timeout
      });
      if (response.ok) {
        indicator.className = 'status-indicator';
        indicator.title = '✅ Backend Connected';
      } else {
        throw new Error('Backend error');
      }
    } catch (error) {
      indicator.className = 'status-indicator disconnected';
      indicator.title = '❌ Backend Disconnected\n\nStart with: cd backend && python main.py';
      console.warn('Backend not available:', error.message);
    }
  }

  async loadPageStats() {
    try {
      const data = await chrome.runtime.sendMessage({ type: 'GET_NETWORK_ACTIVITY' });
      if (data) {
        document.getElementById('request-count').textContent = data.requests?.length || 0;

        // Show actual threat count from suspicious activity
        const threatCount = data.suspicious?.length || 0;
        const threatElement = document.getElementById('threat-count');
        threatElement.textContent = threatCount;

        // Color code the threat count
        if (threatCount > 0) {
          threatElement.style.color = '#ef4444'; // Red for threats
          threatElement.style.fontWeight = 'bold';
        } else {
          threatElement.style.color = '#10b981'; // Green for no threats
        }
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
      document.getElementById('request-count').textContent = '--';
      document.getElementById('threat-count').textContent = '--';
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
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, creating popup');
  window.netScopePopup = new NetScopePopup();
});