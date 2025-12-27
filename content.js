const MM_NS = "data-mailmind";
let panel;

function debounce(fn, wait) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
}

function ensurePanel() {
  if (panel && document.body.contains(panel)) return panel;
  panel = document.createElement("div");
  panel.setAttribute(MM_NS, "panel");
  panel.style.position = "fixed";
  panel.style.zIndex = "2147483647";
  panel.style.top = "80px";
  panel.style.right = "16px";
  panel.style.width = "380px";
  panel.style.maxHeight = "60vh";
  panel.style.overflow = "auto";
  panel.style.background = "#fff";
  panel.style.border = "1px solid #ddd";
  panel.style.padding = "8px";
  panel.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif";
  panel.style.fontSize = "13px";
  document.body.appendChild(panel);
  return panel;
}

function addLine(text, id) {
  const p = document.createElement("div");
  p.setAttribute(MM_NS, "line");
  p.style.whiteSpace = "pre-wrap";
  p.style.margin = "6px 0";
  p.textContent = id ? `${id}:\n${text}` : text;
  ensurePanel().appendChild(p);
}

function collectSelectedItems() {
  const items = [];
  const seen = new Set();
  const rows = Array.from(document.querySelectorAll('tr.zA'));
  for (const row of rows) {
    const selected = row.getAttribute('aria-selected') === 'true' || !!row.querySelector('div[role="checkbox"][aria-checked="true"]');
    if (!selected) continue;
    let messageId = null;
    const msgSpan = row.querySelector('span[data-legacy-message-id]');
    if (msgSpan) messageId = msgSpan.getAttribute('data-legacy-message-id');
    if (!messageId) messageId = row.getAttribute('data-legacy-message-id') || row.getAttribute('data-message-id');
    if (messageId && !seen.has('m:'+messageId)) {
      items.push({ kind: 'message', id: messageId });
      seen.add('m:'+messageId);
      continue;
    }
    let threadId = row.getAttribute('data-legacy-thread-id') || row.getAttribute('data-thread-id');
    if (!threadId) {
      const th = row.querySelector('[data-legacy-thread-id],[data-thread-id]');
      if (th) threadId = th.getAttribute('data-legacy-thread-id') || th.getAttribute('data-thread-id');
    }
    if (threadId && !seen.has('t:'+threadId)) {
      items.push({ kind: 'thread', id: threadId });
      seen.add('t:'+threadId);
    }
  }
  if (items.length === 0) {
    const rows2 = Array.from(document.querySelectorAll('div[role="row"]'));
    for (const r of rows2) {
      const selected = !!r.querySelector('div[role="checkbox"][aria-checked="true"]');
      if (!selected) continue;
      let messageId = r.getAttribute('data-legacy-message-id') || r.getAttribute('data-message-id');
      if (!messageId) {
        const msg = r.querySelector('[data-legacy-message-id],[data-message-id]');
        if (msg) messageId = msg.getAttribute('data-legacy-message-id') || msg.getAttribute('data-message-id');
      }
      if (messageId && !seen.has('m:'+messageId)) {
        items.push({ kind: 'message', id: messageId });
        seen.add('m:'+messageId);
        continue;
      }
      let threadId = r.getAttribute('data-legacy-thread-id') || r.getAttribute('data-thread-id');
      if (!threadId) {
        const th = r.querySelector('[data-legacy-thread-id],[data-thread-id]');
        if (th) threadId = th.getAttribute('data-legacy-thread-id') || th.getAttribute('data-thread-id');
      }
      if (threadId && !seen.has('t:'+threadId)) {
        items.push({ kind: 'thread', id: threadId });
        seen.add('t:'+threadId);
      }
    }
  }
  return items;
}

function getOpenEmailText() {
  const bodies = Array.from(document.querySelectorAll('.a3s'));
  const visible = bodies.filter((el) => el.offsetParent !== null);
  const node = visible[visible.length - 1] || bodies[bodies.length - 1];
  if (!node) return "";
  const clone = node.cloneNode(true);
  clone.querySelectorAll('script,style,noscript').forEach((n) => n.remove());
  return (clone.innerText || "").trim();
}

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'mailmind_popup_action') {
    if (msg.action === 'multi') {
      const items = collectSelectedItems();
      if (!items.length) addLine('No emails selected in inbox.');
      else {
        addLine(`Summarizing ${items.length} selected…`);
        chrome.runtime.sendMessage({ type: 'mailmind_multi_summarize_request', items });
      }
    } else if (msg.action === 'single') {
      const text = getOpenEmailText();
      if (!text) addLine('Could not find opened email body.');
      else chrome.runtime.sendMessage({ type: 'mailmind_single_summarize_request', body: text });
    } else if (msg.action === 'reply') {
      const text = getOpenEmailText();
      if (!text) addLine('Could not find opened email body.');
      else chrome.runtime.sendMessage({ type: 'mailmind_single_reply_request', body: text });
    }
  } else if (msg.type === 'mailmind_summary_result') {
    addLine(msg.summary, msg.messageId ? `Summary (${msg.source}) for ${msg.messageId}` : undefined);
  } else if (msg.type === 'mailmind_summary_error') {
    addLine(`Error for ${msg.messageId || ''}: ${msg.error}`);
  } else if (msg.type === 'mailmind_single_result') {
    addLine(msg.summary, msg.mode === 'reply' ? 'Draft Reply' : 'Summary');
  } else if (msg.type === 'mailmind_single_error') {
    addLine(`Error: ${msg.error}`);
  }
});

