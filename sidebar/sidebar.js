// NetScope Guardian Sidebar - FULLY FIXED VERSION
console.log('Sidebar script loading...');

class NetScopeGuardian {
  constructor() {
    this.backendUrl = 'http://localhost:8000';
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
    
    // Quick action buttons
    document.querySelectorAll('.quick-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const action = e.target.dataset.action;
        console.log('Quick action:', action);
        if (action === 'current-page') this.analyzeCurrentPage();
        else if (action === 'network-monitor') this.showNetworkMonitor();
      });
    });
    
    // Theme toggle - FIXED
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        console.log('Theme toggle clicked');
        this.toggleTheme();
      });
    }
    
    // Settings button - FIXED
    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => {
        console.log('Settings clicked');
        this.showSettings();
      });
    }
    
    // Logo click - FIXED (return to welcome)
    const logoSection = document.querySelector('.logo-section');
    if (logoSection) {
      logoSection.style.cursor = 'pointer';
      logoSection.addEventListener('click', () => {
        console.log('Logo clicked - returning to welcome');
        this.returnToWelcome();
      });
    }
    
    // Welcome screen analyze button
    const analyzeBtn = document.getElementById('analyze-current-btn');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => this.analyzeCurrentPage());
    }
    
    // Expandable sections - FIXED
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('expand-btn')) {
        console.log('Expand button clicked');
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
      const result = await chrome.storage.local.get(['lastAnalysis']);
      if (result.lastAnalysis && (Date.now() - result.lastAnalysis.timestamp) < 60000) {
        console.log('Found stored analysis');
        this.displayAnalysisResult(result.lastAnalysis);
        await chrome.storage.local.remove(['lastAnalysis']);
      } else {
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
      
      if (!response.ok) throw new Error(`Backend error: ${response.status}`);
      
      const analysis = await response.json();
      this.displayAnalysisResult({ indicator: query, analysis, timestamp: Date.now() });
      input.value = '';
      
    } catch (error) {
      this.hideLoading();
      this.showError(`Analysis failed: ${error.message}`);
    }
  }
  
  async analyzeCurrentPage() {
    this.showLoading('Analyzing current page...');
    
    try {
      // Get the active tab
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
      
      if (!response.ok) throw new Error(`Backend error: ${response.status}`);
      
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
    
    // Update threat score
    const scoreElement = document.getElementById('threat-score');
    const score = analysis.threat_score || 'Unknown';
    scoreElement.textContent = score;
    scoreElement.className = `threat-score ${score.toLowerCase()}`;
    
    // Update Gemini AI analysis
    document.getElementById('gemini-analysis').textContent = 
      analysis.gemini_analysis || 'Analysis not available';
    
    // Update external links
    const vtLink = document.getElementById('virustotal-link');
    const abuseLink = document.getElementById('abuseipdb-link');
    if (analysis.type === 'IP' || analysis.type === 'DOMAIN') {
      vtLink.href = `https://www.virustotal.com/gui/${analysis.type === 'IP' ? 'ip-address' : 'domain'}/${data.indicator}`;
      abuseLink.href = `https://www.abuseipdb.com/check/${data.indicator}`;
    }
    
    // Update threat details
    const detailsList = document.getElementById('threat-details');
    detailsList.innerHTML = '';
    const details = analysis.reputation_data || {};
    
    if (Object.keys(details).length > 0) {
      Object.entries(details).forEach(([key, value]) => {
        if (value && typeof value !== 'object') {
          const li = document.createElement('li');
          li.textContent = `${key}: ${value}`;
          detailsList.appendChild(li);
        }
      });
    } else {
      const li = document.createElement('li');
      li.textContent = 'Type: ' + (analysis.type || 'Unknown');
      detailsList.appendChild(li);
    }
    
    // Update mitigation steps
    const stepsList = document.getElementById('mitigation-steps');
    stepsList.innerHTML = '';
    const steps = analysis.recommendations || ['Monitor this indicator', 'Check logs for related activity'];
    steps.forEach(step => {
      const li = document.createElement('li');
      li.textContent = step;
      stepsList.appendChild(li);
    });
    
    card.style.display = 'block';
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
      const present = headers.headers && headers.headers[headerName.toLowerCase()];
      div.innerHTML = `
        <div class="header-name">${headerName}</div>
        <div class="header-status ${present ? 'present' : 'missing'}">
          ${present ? 'Present' : 'Missing'}
        </div>
      `;
      grid.appendChild(div);
    });
    
    document.getElementById('headers-analysis').textContent = 
      headers.gemini_analysis || 'Analysis not available';
    
    card.style.display = 'block';
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
      data.suspicious.slice(0, 5).forEach(req => {
        const item = document.createElement('div');
        item.className = 'network-item suspicious';
        try {
          const url = new URL(req.url);
          item.innerHTML = `
            <div class="network-url">${url.hostname}</div>
            <div class="network-meta">
              <div class="network-method">${req.method || 'GET'}</div>
              <div class="network-reason">${req.reason}</div>
            </div>
          `;
        } catch (e) {
          item.innerHTML = `<div class="network-url">${req.url.substring(0, 50)}...</div>`;
        }
        list.appendChild(item);
      });
    }
    
    // Show regular requests
    if (data.requests && data.requests.length > 0) {
      data.requests.slice(0, 10).forEach(req => {
        const item = document.createElement('div');
        item.className = 'network-item';
        try {
          const url = new URL(req.url);
          item.innerHTML = `
            <div class="network-url">${url.hostname}</div>
            <div class="network-meta">
              <div class="network-method">${req.method || 'GET'}</div>
            </div>
          `;
        } catch (e) {
          item.innerHTML = `<div class="network-url">${req.url.substring(0, 50)}...</div>`;
        }
        list.appendChild(item);
      });
    }
    
    if (list.children.length === 0) {
      list.innerHTML = '<div style="padding:20px;text-align:center;color:#9ca3af;">No network activity detected</div>';
    }
    
    card.style.display = 'block';
  }
  
  // FIXED: Toggle expandable sections
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
  
  // FIXED: Theme toggle
  toggleTheme() {
    this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', this.currentTheme);
    
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.textContent = this.currentTheme === 'dark' ? '☀️' : '🌙';
    }
    
    chrome.storage.local.set({ theme: this.currentTheme });
    console.log('Theme changed to:', this.currentTheme);
  }
  
  // FIXED: Settings modal
  showSettings() {
    const message = `NetScope Guardian Settings\n\nBackend URL: ${this.backendUrl}\nTheme: ${this.currentTheme}\nVersion: 1.0.0\n\nSettings panel coming soon!`;
    alert(message);
  }
  
  // FIXED: Return to welcome screen
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
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      z-index: 10000;
      max-width: 300px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;
    errorDiv.textContent = message;
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
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