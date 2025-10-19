// // NetScope Guardian Content Script - FIXED VERSION
// (function() {
//   'use strict';
  
//   console.log('NetScope Guardian content script loaded');
  
//   let isHighlighting = false;
//   let highlightOverlay = null;
  
//   // Initialize content script
//   function init() {
//     console.log('Initializing NetScope Guardian...');
//     createHighlightOverlay();
//     attachEventListeners();
//   }
  
//   // Create highlight overlay for indicators
//   function createHighlightOverlay() {
//     if (document.getElementById('netscope-overlay')) return;
    
//     highlightOverlay = document.createElement('div');
//     highlightOverlay.id = 'netscope-overlay';
//     highlightOverlay.style.cssText = `
//       position: fixed;
//       top: 0;
//       left: 0;
//       width: 100%;
//       height: 100%;
//       pointer-events: none;
//       z-index: 10000;
//       background: transparent;
//     `;
//     document.body.appendChild(highlightOverlay);
//   }
  
//   // Event listeners
//   function attachEventListeners() {
//     // Text selection highlighting
//     document.addEventListener('mouseup', handleTextSelection);
//     document.addEventListener('keyup', handleKeyboardSelection);
    
//     // Form submission monitoring
//     document.addEventListener('submit', handleFormSubmission);
//   }
  
//   // Handle text selection
//   function handleTextSelection(event) {
//     const selection = window.getSelection();
//     const selectedText = selection.toString().trim();
    
//     if (selectedText && selectedText.length > 3) {
//       const indicatorType = detectIndicator(selectedText);
//       if (indicatorType !== 'NONE') {
//         console.log('Indicator detected:', selectedText, 'Type:', indicatorType);
//         highlightSelection(selection, indicatorType);
//         // Don't show quick analysis popup - let context menu handle it
//       }
//     } else {
//       clearHighlights();
//     }
//   }
  
//   // Handle keyboard selection
//   function handleKeyboardSelection(event) {
//     if (event.ctrlKey && event.key === 'a') {
//       setTimeout(() => handleTextSelection(event), 100);
//     }
//   }
  
//   // Detect indicator types in selected text
//   function detectIndicator(text) {
//     const patterns = {
//       IP: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/,
//       DOMAIN: /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/,
//       URL: /^https?:\/\/.+/,
//       HASH: /^[a-fA-F0-9]{32,64}$/,
//       EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
//     };
    
//     for (const [type, pattern] of Object.entries(patterns)) {
//       if (pattern.test(text)) return type;
//     }
    
//     return 'NONE';
//   }
  
//   // Highlight selected indicator
//   function highlightSelection(selection, type) {
//     if (!selection.rangeCount) return;
    
//     const range = selection.getRangeAt(0);
//     const rect = range.getBoundingClientRect();
    
//     const highlight = document.createElement('div');
//     highlight.className = 'netscope-highlight';
//     highlight.style.cssText = `
//       position: absolute;
//       left: ${rect.left + window.scrollX}px;
//       top: ${rect.top + window.scrollY}px;
//       width: ${rect.width}px;
//       height: ${rect.height}px;
//       background: rgba(59, 130, 246, 0.2);
//       border: 1px solid #3b82f6;
//       border-radius: 2px;
//       pointer-events: none;
//       z-index: 9999;
//     `;
    
//     document.body.appendChild(highlight);
    
//     // Auto-remove after 3 seconds
//     setTimeout(() => {
//       if (highlight && highlight.parentNode) {
//         highlight.parentNode.removeChild(highlight);
//       }
//     }, 3000);
//   }
  
//   // Clear highlights
//   function clearHighlights() {
//     const highlights = document.querySelectorAll('.netscope-highlight');
//     highlights.forEach(h => h.remove());
//   }
  
//   // Handle form submissions for security monitoring
//   function handleFormSubmission(event) {
//     const form = event.target;
//     const hasPasswordField = form.querySelector('input[type="password"]') !== null;
//     const isHTTPS = window.location.protocol === 'https:';
    
//     if (hasPasswordField && !isHTTPS) {
//       chrome.runtime.sendMessage({
//         type: 'SECURITY_WARNING',
//         warning: {
//           type: 'INSECURE_FORM',
//           message: 'Password form submitted over HTTP',
//           severity: 'HIGH',
//           url: window.location.href
//         }
//       });
//     }
//   }
  
//   // Initialize when DOM is ready
//   if (document.readyState === 'loading') {
//     document.addEventListener('DOMContentLoaded', init);
//   } else {
//     init();
//   }
  
// })();
// NetScope Guardian Content Script
(function() {
  'use strict';
  console.log('NetScope Guardian content script loaded');
  
  function init() {
    console.log('Initializing NetScope Guardian...');
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();