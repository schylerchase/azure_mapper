// DOM manipulation helper functions
// Extracted from index.html for modularization

/**
 * Show a toast notification
 * @param {string} msg - Message to display
 * @param {number} duration - Duration in ms (default: 3000)
 */
let _toastEl = null;
let _toastTimer = null;
export function showToast(msg, duration = 3000) {
  if (!_toastEl) {
    _toastEl = document.createElement('div');
    _toastEl.style.cssText = `
      position:fixed;bottom:60px;left:50%;transform:translateX(-50%);z-index:300;
      background:var(--accent-green);color:#000;padding:8px 20px;border-radius:6px;
      font-family:Segoe UI,system-ui,sans-serif;font-size:12px;font-weight:600;
      box-shadow:0 4px 12px rgba(0,0,0,.4);transition:opacity .3s
    `;
    document.body.appendChild(_toastEl);
  }
  clearTimeout(_toastTimer);
  _toastEl.textContent = msg;
  _toastEl.style.opacity = '1';
  _toastTimer = setTimeout(() => { _toastEl.style.opacity = '0'; }, duration);
}

/**
 * Toggle a CSS class on an element
 * @param {string|HTMLElement} el - Element ID or element
 * @param {string} className - Class name to toggle
 * @returns {boolean} True if class was added, false if removed
 */
export function toggleClass(el, className) {
  const element = typeof el === 'string' ? document.getElementById(el) : el;
  if (!element) return false;
  const hasClass = element.classList.contains(className);
  element.classList.toggle(className);
  return !hasClass;
}

/**
 * Set element visibility
 * @param {string|HTMLElement} el - Element ID or element
 * @param {boolean} visible - True to show, false to hide
 */
export function setVisible(el, visible) {
  const element = typeof el === 'string' ? document.getElementById(el) : el;
  if (!element) return;
  element.style.display = visible ? '' : 'none';
}

/**
 * Get element by ID with null safety
 * @param {string} id - Element ID
 * @returns {HTMLElement|null} Element or null
 */
export function getEl(id) {
  return document.getElementById(id);
}

/**
 * Query selector with null safety
 * @param {string} selector - CSS selector
 * @param {HTMLElement} parent - Parent element (default: document)
 * @returns {HTMLElement|null} First matching element or null
 */
export function qs(selector, parent = document) {
  return parent.querySelector(selector);
}

/**
 * Query selector all with array return
 * @param {string} selector - CSS selector
 * @param {HTMLElement} parent - Parent element (default: document)
 * @returns {HTMLElement[]} Array of matching elements
 */
export function qsa(selector, parent = document) {
  return Array.from(parent.querySelectorAll(selector));
}
