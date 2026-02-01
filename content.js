// NetScope Guardian Content Script
(function () {
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