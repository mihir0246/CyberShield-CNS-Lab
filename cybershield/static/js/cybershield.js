/**
 * CyberShield Frontend Utility Suite
 * Provides unified AJAX communication, toast notifications, loading states, and clipboard utilities.
 */

// Global Toast Notification Helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const bgClass = {
    success: 'bg-success text-white',
    danger: 'bg-danger text-white',
    warning: 'bg-warning text-dark',
    info: 'bg-primary text-white'
  }[type] || 'bg-secondary text-white';

  const toastId = 'toast-' + Date.now();
  const toastHtml = `
    <div id="${toastId}" class="toast align-items-center ${bgClass} border-0 mb-2 shadow" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body d-flex align-items-center">
          <i class="bi bi-shield-check me-2 fs-5"></i>
          <div>${message}</div>
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>
  `;
  container.insertAdjacentHTML('beforeend', toastHtml);
  const toastElem = document.getElementById(toastId);
  const bsToast = new bootstrap.Toast(toastElem, { delay: 4500 });
  bsToast.show();
  toastElem.addEventListener('hidden.bs.toast', () => toastElem.remove());
}

// Unified API Caller with Loading State Management
async function apiCall(url, payload = null, btnElement = null, method = 'POST') {
  let originalBtnHtml = '';
  if (btnElement) {
    originalBtnHtml = btnElement.innerHTML;
    btnElement.disabled = true;
    btnElement.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...`;
  }

  try {
    const options = {
      method: method,
      headers: {
        'Accept': 'application/json'
      }
    };

    if (payload instanceof FormData) {
      options.body = payload;
    } else if (payload && method !== 'GET') {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(payload);
    }

    const response = await fetch(url, options);
    const result = await response.json();

    if (!response.ok || !result.success) {
      const errMsg = result.error || `Server responded with HTTP ${response.status}`;
      showToast(errMsg, 'danger');
      throw new Error(errMsg);
    }

    return result;
  } catch (err) {
    console.error('API Error:', err);
    throw err;
  } finally {
    if (btnElement) {
      btnElement.disabled = false;
      btnElement.innerHTML = originalBtnHtml;
    }
  }
}

// Copy to Clipboard Utility
function copyToClipboard(textOrElementId) {
  let content = textOrElementId;
  const elem = document.getElementById(textOrElementId);
  if (elem) {
    content = elem.value !== undefined ? elem.value : elem.innerText;
  }

  navigator.clipboard.writeText(content).then(() => {
    showToast('Copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Failed to copy to clipboard', 'danger');
  });
}

// Mobile Sidebar Toggle
document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('active');
    });
  }
});
