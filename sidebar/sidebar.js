// NetScope Guardian Sidebar - FULLY FIXED VERSION
console.log('Sidebar script loading...');

class NetScopeGuardian {
  constructor() {
    this.backendUrl = 'http://localhost:8080'; // FIXED: Port 8080
    this.currentTheme = 'dark';
    console.log('NetScopeGuardian initialized');
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadSettings();
    this.checkForStoredAnalysis();
    this.setupMessageListener();
  }

  setupEventListeners() {
    console.log('Setting up sidebar event listeners');

    // Search functionality
    const searchBtn = document.getElementById('search-btn');
    if (searchBtn) {
      searchBtn.addEventListener('click', () => this.performSearch());
    }

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') this.performSearch();
      });
    }

    // Quick action buttons - REMOVED "current-page" button
    document.querySelectorAll('.quick-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const action = e.target.dataset.action;
        console.log('Quick action:', action);
        if (action === 'network-monitor') this.showNetworkMonitor();
      });
    });

    // Theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => this.toggleTheme());
    }

    // Settings button
    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => this.showSettings());
    }

    // Logo click - return to welcome
    const logoSection = document.querySelector('.logo-section');
    if (logoSection) {
      logoSection.style.cursor = 'pointer';
      logoSection.addEventListener('click', () => this.returnToWelcome());
    }

    // Welcome screen analyze button
    const analyzeBtn = document.getElementById('analyze-current-btn');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => this.analyzeCurrentPage());
    }

    // Expandable sections
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('expand-btn')) {
        this.toggleExpandableSection(e.target);
      }
    });
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((request) => {
      console.log('Sidebar received:', request.type);
      if (request.type === 'ANALYSIS_RESULT') {
        this.displayAnalysisResult(request.data);
      }
    });
  }

  async checkForStoredAnalysis() {
    try {
      const result = await chrome.storage.local.get(['lastAnalysis', 'lastHeadersAnalysis']);

      // Check for Threat Analysis (Context Menu/Search)
      if (result.lastAnalysis && (Date.now() - result.lastAnalysis.timestamp) < 60000) {
        console.log('Found stored threat analysis');
        this.displayAnalysisResult(result.lastAnalysis);
        await chrome.storage.local.remove(['lastAnalysis']);
      }
      // Check for Headers Analysis (Popup 'Analyze Page')
      else if (result.lastHeadersAnalysis && (Date.now() - result.lastHeadersAnalysis.timestamp) < 60000) {
        console.log('Found stored headers analysis');
        this.displaySecurityHeaders(result.lastHeadersAnalysis.analysis);
        await chrome.storage.local.remove(['lastHeadersAnalysis']);
      }
      else {
        this.showWelcomeScreen();
      }
    } catch (error) {
      console.error('Storage error:', error);
      this.showWelcomeScreen();
    }
  }

  async performSearch() {
    const input = document.getElementById('search-input');
    const query = input.value.trim();

    if (!query) {
      this.showError('Please enter an indicator to analyze');
      return;
    }

    this.showLoading('Analyzing with Gemini AI...');

    try {
      const response = await fetch(`${this.backendUrl}/threat-summary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: query })
      });

      if (!response.ok) {
        throw new Error(`Backend error: ${response.status}`);
      }

      const analysis = await response.json();
      this.displayAnalysisResult({ indicator: query, analysis, timestamp: Date.now() });
      input.value = '';

    } catch (error) {
      this.hideLoading();
      this.showError(`Analysis failed: ${error.message}. Make sure backend is running at ${this.backendUrl}`);
    }
  }

  async analyzeCurrentPage() {
    this.showLoading('Analyzing current page...');

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];

      if (!tab || !tab.url) {
        throw new Error('Cannot access current tab. Please open a webpage first.');
      }

      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        throw new Error('Cannot analyze Chrome system pages');
      }

      const response = await fetch(`${this.backendUrl}/headers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      });

      if (!response.ok) {
        throw new Error(`Backend error: ${response.status}`);
      }

      const analysis = await response.json();
      this.hideLoading();
      this.displaySecurityHeaders(analysis);

    } catch (error) {
      this.hideLoading();
      this.showError(`Page analysis failed: ${error.message}`);
    }
  }

  async showNetworkMonitor() {
    this.showLoading('Loading network activity...');

    try {
      const data = await chrome.runtime.sendMessage({ type: 'GET_NETWORK_ACTIVITY' });
      this.hideLoading();
      if (data) this.displayNetworkActivity(data);
    } catch (error) {
      this.hideLoading();
      this.showError(`Failed to load network activity: ${error.message}`);
    }
  }

  displayAnalysisResult(data) {
    this.hideWelcomeScreen();
    this.hideLoading();

    const card = document.getElementById('threat-card');
    const analysis = data.analysis;

    // Update indicator info
    document.getElementById('indicator-text').textContent = data.indicator;
    document.getElementById('indicator-type').textContent = analysis.type || 'UNKNOWN';

    // FIX #1: Update threat score with PROPER COLORS
    const scoreElement = document.getElementById('threat-score');
    const score = (analysis.threat_score || 'UNKNOWN').toUpperCase();
    scoreElement.textContent = score;

    // Apply correct CSS classes for colors
    scoreElement.className = 'threat-score';
    if (score === 'CRITICAL') {
      scoreElement.classList.add('critical');
    } else if (score === 'HIGH') {
      scoreElement.classList.add('high');
    } else if (score === 'MEDIUM') {
      scoreElement.classList.add('medium');
    } else if (score === 'LOW') {
      scoreElement.classList.add('low');
    } else {
      scoreElement.classList.add('clean');
    }

    // Update Gemini AI analysis
    document.getElementById('gemini-analysis').textContent =
      analysis.gemini_analysis || 'Analysis not available';

    // FIX #2: Update external links with PROPER URLs
    const vtLink = document.getElementById('virustotal-link');
    const abuseLink = document.getElementById('abuseipdb-link');

    if (analysis.type === 'IP') {
      vtLink.href = `https://www.virustotal.com/gui/ip-address/${data.indicator}`;
      abuseLink.href = `https://www.abuseipdb.com/check/${data.indicator}`;
      vtLink.style.display = 'inline';
      abuseLink.style.display = 'inline';
    } else if (analysis.type === 'DOMAIN') {
      vtLink.href = `https://www.virustotal.com/gui/domain/${data.indicator}`;
      abuseLink.href = `https://www.abuseipdb.com/check/${data.indicator}`;
      vtLink.style.display = 'inline';
      abuseLink.style.display = 'inline';
    } else if (analysis.type === 'URL') {
      vtLink.href = `https://www.virustotal.com/gui/url/${btoa(data.indicator)}`;
      abuseLink.style.display = 'none';
      vtLink.style.display = 'inline';
    } else if (analysis.type === 'HASH') {
      vtLink.href = `https://www.virustotal.com/gui/file/${data.indicator}`;
      abuseLink.style.display = 'none';
      vtLink.style.display = 'inline';
    } else {
      vtLink.style.display = 'none';
      abuseLink.style.display = 'none';
    }

    // Update last seen timestamp
    const lastSeen = document.getElementById('last-seen');
    if (lastSeen) {
      lastSeen.textContent = `Analyzed: ${new Date(data.timestamp).toLocaleTimeString()}`;
    }

    // Update threat details
    const detailsList = document.getElementById('threat-details');
    detailsList.innerHTML = '';
    const details = analysis.reputation_data || {};

    if (Object.keys(details).length > 0) {
      Object.entries(details).forEach(([key, value]) => {
        if (value !== null && value !== undefined && typeof value !== 'object') {
          const li = document.createElement('li');
          // Format the key nicely
          const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          li.textContent = `${formattedKey}: ${value}`;
          detailsList.appendChild(li);
        } else if (Array.isArray(value) && value.length > 0) {
          const li = document.createElement('li');
          const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          li.textContent = `${formattedKey}: ${value.join(', ')}`;
          detailsList.appendChild(li);
        }
      });
    }

    // Always show basic info
    if (detailsList.children.length === 0) {
      const li = document.createElement('li');
      li.textContent = `Type: ${analysis.type || 'Unknown'}`;
      detailsList.appendChild(li);

      const li2 = document.createElement('li');
      li2.textContent = `Threat Level: ${score}`;
      detailsList.appendChild(li2);
    }

    // Update mitigation steps with emojis
    const stepsList = document.getElementById('mitigation-steps');
    stepsList.innerHTML = '';
    const steps = analysis.recommendations || ['Monitor this indicator', 'Check logs for related activity'];
    steps.forEach(step => {
      const li = document.createElement('li');
      li.textContent = step;
      stepsList.appendChild(li);
    });

    card.style.display = 'block';

    // Scroll to top of results
    document.querySelector('.results-container').scrollTop = 0;
  }

  displaySecurityHeaders(headers) {
    this.hideWelcomeScreen();

    const card = document.getElementById('headers-card');
    const grid = document.getElementById('headers-grid');
    grid.innerHTML = '';

    const importantHeaders = [
      'Content-Security-Policy',
      'Strict-Transport-Security',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy'
    ];

    importantHeaders.forEach(headerName => {
      const div = document.createElement('div');
      div.className = 'header-item';
      const present = headers.headers && headers.headers[headerName];
      div.innerHTML = `
        <div class="header-name">${headerName}</div>
        <div class="header-status ${present ? 'present' : 'missing'}">
          ${present ? '✅ Present' : '❌ Missing'}
        </div>
      `;
      grid.appendChild(div);
    });

    // FIX #4: Display full analysis with proper scrolling
    const analysisElement = document.getElementById('headers-analysis');
    analysisElement.textContent = headers.gemini_analysis || 'Analysis not available';

    // Make sure the analysis is scrollable
    analysisElement.style.maxHeight = '400px';
    analysisElement.style.overflowY = 'auto';

    card.style.display = 'block';

    // Scroll to top
    document.querySelector('.results-container').scrollTop = 0;
  }

  displayNetworkActivity(data) {
    this.hideWelcomeScreen();

    const card = document.getElementById('network-card');
    document.getElementById('total-requests').textContent = data.requests?.length || 0;
    document.getElementById('suspicious-requests').textContent = data.suspicious?.length || 0;

    const list = document.getElementById('network-list');
    list.innerHTML = '';

    // Show suspicious requests first
    if (data.suspicious && data.suspicious.length > 0) {
      data.suspicious.slice(0, 10).forEach(req => {
        const item = document.createElement('div');
        item.className = 'network-item suspicious';
        try {
          const url = new URL(req.url);
          item.innerHTML = `
            <div class="network-url">${url.hostname}${url.pathname}</div>
            <div class="network-meta">
              <div class="network-method">${req.method || 'GET'}</div>
              <div class="network-reason">${req.reason || 'Suspicious pattern'}</div>
            </div>
          `;
        } catch (e) {
          item.innerHTML = `
            <div class="network-url">${req.url.substring(0, 80)}...</div>
            <div class="network-meta">
              <div class="network-reason">${req.reason || 'Suspicious'}</div>
            </div>
          `;
        }
        list.appendChild(item);
      });
    }

    // Show regular requests
    if (data.requests && data.requests.length > 0) {
      data.requests.slice(0, 15).forEach(req => {
        const item = document.createElement('div');
        item.className = 'network-item';
        try {
          const url = new URL(req.url);
          item.innerHTML = `
            <div class="network-url">${url.hostname}${url.pathname}</div>
            <div class="network-meta">
              <div class="network-method">${req.method || 'GET'}</div>
              <span style="font-size: 10px; color: #9ca3af;">${new Date(req.timestamp).toLocaleTimeString()}</span>
            </div>
          `;
        } catch (e) {
          item.innerHTML = `<div class="network-url">${req.url.substring(0, 80)}...</div>`;
        }
        list.appendChild(item);
      });
    }

    if (list.children.length === 0) {
      list.innerHTML = '<div style="padding:20px;text-align:center;color:#9ca3af;">No network activity detected</div>';
    }

    card.style.display = 'block';

    // Scroll to top
    document.querySelector('.results-container').scrollTop = 0;
  }

  toggleExpandableSection(button) {
    const targetId = button.dataset.target;
    const content = document.getElementById(targetId);

    if (!content) {
      console.error('Expandable content not found:', targetId);
      return;
    }

    if (content.classList.contains('expanded')) {
      content.classList.remove('expanded');
      button.textContent = button.textContent.replace('▲', '▼');
    } else {
      content.classList.add('expanded');
      button.textContent = button.textContent.replace('▼', '▲');
    }
  }

  toggleTheme() {
    this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    // Fix: Apply class to body so CSS can target it
    document.body.className = this.currentTheme;
    document.body.setAttribute('data-theme', this.currentTheme);

    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.textContent = this.currentTheme === 'dark' ? '☀️' : '🌙';
    }

    chrome.storage.local.set({ theme: this.currentTheme });
  }

  showSettings() {
    const message = `NetScope Guardian Settings\n\n✅ Backend: ${this.backendUrl}\n🎨 Theme: ${this.currentTheme}\n📦 Version: 1.0.0\n\n⚙️ Advanced settings coming soon!`;
    alert(message);
  }

  returnToWelcome() {
    this.hideCards();
    this.showWelcomeScreen();
  }

  showLoading(message) {
    const loading = document.getElementById('loading-state');
    if (loading) {
      loading.querySelector('p').textContent = message;
      loading.style.display = 'flex';
    }
    this.hideWelcomeScreen();
    this.hideCards();
  }

  hideLoading() {
    const loading = document.getElementById('loading-state');
    if (loading) loading.style.display = 'none';
  }

  showWelcomeScreen() {
    const welcome = document.getElementById('welcome-screen');
    if (welcome) welcome.style.display = 'block';
    this.hideCards();
  }

  hideWelcomeScreen() {
    const welcome = document.getElementById('welcome-screen');
    if (welcome) welcome.style.display = 'none';
  }

  hideCards() {
    const cards = ['threat-card', 'headers-card', 'network-card'];
    cards.forEach(id => {
      const card = document.getElementById(id);
      if (card) card.style.display = 'none';
    });
  }

  showError(message) {
    this.hideLoading();
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ef4444;
      color: white;
      padding: 16px 20px;
      border-radius: 8px;
      font-size: 14px;
      z-index: 10000;
      max-width: 350px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      line-height: 1.4;
    `;
    errorDiv.textContent = '⚠️ ' + message;
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 6000);
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['theme']);
      if (result.theme) {
        this.currentTheme = result.theme;
        document.body.setAttribute('data-theme', this.currentTheme);
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
          themeToggle.textContent = this.currentTheme === 'dark' ? '☀️' : '🌙';
        }
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, creating sidebar');
  window.netScopeGuardian = new NetScopeGuardian();
});