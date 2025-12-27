const GEMINI_KEY_STORAGE = 'mailmind_gemini_api_key';

function setStatus(text) {
  const s = document.getElementById('status');
  if (s) s.textContent = text || '';
}

function getActiveTab(cb) {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
    cb((tabs && tabs[0]) || null);
  });
}

function sendToActiveTab(payload) {
  getActiveTab((tab) => {
    if (!tab || !tab.id) {
      setStatus('No active tab. Open Gmail.');
      return;
    }
    chrome.tabs.sendMessage(tab.id, payload, () => {
      if (chrome.runtime.lastError) {
        setStatus('Could not reach Gmail tab. Open Gmail and try again.');
      } else {
        setStatus('Request sent. Check the overlay in Gmail.');
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const apiKeyInput = document.getElementById('apiKey');
  const saveBtn = document.getElementById('saveKey');
  const btnMulti = document.getElementById('btnMulti');
  const btnSingle = document.getElementById('btnSingle');
  const btnReply = document.getElementById('btnReply');

  chrome.storage.local.get([GEMINI_KEY_STORAGE], (items) => {
    const key = items && items[GEMINI_KEY_STORAGE];
    if (key && apiKeyInput) apiKeyInput.value = key;
  });

  saveBtn.addEventListener('click', () => {
    const key = (apiKeyInput && apiKeyInput.value) || '';
    chrome.storage.local.set({ [GEMINI_KEY_STORAGE]: key }, () => {
      setStatus('API key saved.');
    });
  });

  btnMulti.addEventListener('click', () => {
    sendToActiveTab({ type: 'mailmind_popup_action', action: 'multi' });
  });

  btnSingle.addEventListener('click', () => {
    sendToActiveTab({ type: 'mailmind_popup_action', action: 'single' });
  });

  btnReply.addEventListener('click', () => {
    sendToActiveTab({ type: 'mailmind_popup_action', action: 'reply' });
  });
});

