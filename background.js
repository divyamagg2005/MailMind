const GMAIL_API_BASE = "https://www.googleapis.com/gmail/v1/users/me";
const GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta";
const GEMINI_MODEL = "gemini-2.5-flash";
const GEMINI_KEY_STORAGE = "mailmind_gemini_api_key";
const ID_CACHE_KEY = "mailmind_id_cache";
const HASH_CACHE_KEY = "mailmind_hash_cache";
const QUEUE_DELAY_MS = 1800;

let processing = false;
let queue = [];
let enqueued = new Set();

function log(...args) {
  console.log("[MailMind]", ...args);
}

function getFromStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (items) => resolve(items || {}));
  });
}

function setInStorage(obj) {
  return new Promise((resolve) => {
    chrome.storage.local.set(obj, () => resolve());
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function decodeGmailBody(data) {
  if (!data) return "";
  const b64 = data.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

function stripHtml(html) {
  if (!html) return "";
  return html
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractPlainTextFromMessage(message) {
  const payload = message && message.payload;
  if (!payload) return "";

  let textPlainCandidates = [];
  let textHtmlCandidates = [];

  function walk(node) {
    if (!node) return;
    const mime = node.mimeType || "";
    if (node.body && node.body.data) {
      if (mime.startsWith("text/plain")) {
        textPlainCandidates.push(decodeGmailBody(node.body.data));
      } else if (mime.startsWith("text/html")) {
        textHtmlCandidates.push(stripHtml(decodeGmailBody(node.body.data)));
      }
    }
    if (node.parts && Array.isArray(node.parts)) {
      for (const p of node.parts) walk(p);
    }
  }

  walk(payload);
  if (textPlainCandidates.length > 0) return textPlainCandidates.join("\n\n").trim();
  if (textHtmlCandidates.length > 0) return textHtmlCandidates.join("\n\n").trim();
  if (payload.body && payload.body.data) return decodeGmailBody(payload.body.data).trim();
  return "";
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getAuthToken(interactive) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(chrome.runtime.lastError || new Error("No token"));
      } else {
        resolve(token);
      }
    });
  });
}

async function getGmailAccessToken() {
  try {
    return await getAuthToken(false);
  } catch (e) {
    log("getAuthToken non-interactive failed, retrying interactively", e && e.message);
    return await getAuthToken(true);
  }
}

async function gmailFetch(path) {
  const token = await getGmailAccessToken();
  const res = await fetch(`${GMAIL_API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) {
    chrome.identity.getAuthToken({ interactive: false }, (t) => {
      if (t) chrome.identity.removeCachedAuthToken({ token: t }, () => {});
    });
  }
  return res;
}

async function fetchMessageById(messageId) {
  log("Gmail API fetch starts for message", messageId);
  const res = await gmailFetch(`/messages/${encodeURIComponent(messageId)}?format=full`);
  const data = await res.json();
  log("Gmail API response received for message", messageId, { status: res.status });
  if (!res.ok) throw new Error(`Gmail message get failed: ${res.status}`);
  return data;
}

async function fetchThreadById(threadId) {
  log("Gmail API fetch starts for thread", threadId);
  const res = await gmailFetch(`/threads/${encodeURIComponent(threadId)}?format=full`);
  const data = await res.json();
  log("Gmail API response received for thread", threadId, { status: res.status });
  if (!res.ok) throw new Error(`Gmail thread get failed: ${res.status}`);
  return data;
}

async function getGeminiApiKey() {
  const items = await getFromStorage([GEMINI_KEY_STORAGE]);
  return items[GEMINI_KEY_STORAGE] || "";
}

async function callGemini(promptText) {
  const apiKey = await getGeminiApiKey();
  if (!apiKey) throw new Error("Gemini API key not set in chrome.storage.local under 'mailmind_gemini_api_key'");
  log("Gemini API call starts");
  const url = `${GEMINI_API_BASE}/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const body = {
    contents: [
      {
        parts: [{ text: `Summarize the following email in 3–4 clear sentences:\n\n${promptText}` }],
      },
    ],
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  log("Gemini raw response", data);
  if (!res.ok) throw new Error(`Gemini API error ${res.status}`);
  const text =
    data &&
    data.candidates &&
    data.candidates[0] &&
    data.candidates[0].content &&
    data.candidates[0].content.parts &&
    data.candidates[0].content.parts[0] &&
    data.candidates[0].content.parts[0].text;
  if (!text) throw new Error("Gemini API returned no text");
  return String(text).trim();
}

async function callGeminiReply(emailText) {
  const apiKey = await getGeminiApiKey();
  if (!apiKey) throw new Error("Gemini API key not set in chrome.storage.local under 'mailmind_gemini_api_key'");
  log("Gemini API call starts (reply)");
  const url = `${GEMINI_API_BASE}/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const body = {
    contents: [
      {
        parts: [{ text: `Write a concise, professional reply to the following email:\n\n${emailText}` }],
      },
    ],
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  log("Gemini raw response (reply)", data);
  if (!res.ok) throw new Error(`Gemini API error ${res.status}`);
  const text =
    data &&
    data.candidates &&
    data.candidates[0] &&
    data.candidates[0].content &&
    data.candidates[0].content.parts &&
    data.candidates[0].content.parts[0] &&
    data.candidates[0].content.parts[0].text;
  if (!text) throw new Error("Gemini API returned no text");
  return String(text).trim();
}

async function getCaches() {
  const items = await getFromStorage([ID_CACHE_KEY, HASH_CACHE_KEY]);
  return {
    idCache: items[ID_CACHE_KEY] || {},
    hashCache: items[HASH_CACHE_KEY] || {},
  };
}

async function setCaches(idCache, hashCache) {
  await setInStorage({ [ID_CACHE_KEY]: idCache, [HASH_CACHE_KEY]: hashCache });
}

async function ensureSummaryCached(messageId, emailText) {
  const { idCache, hashCache } = await getCaches();
  const existing = idCache[messageId];
  if (existing && existing.summary && existing.bodyHash) {
    return { cached: true, summary: existing.summary, bodyHash: existing.bodyHash };
  }
  const bodyHash = await sha256(emailText);
  if (hashCache[bodyHash] && hashCache[bodyHash].summary) {
    const summary = hashCache[bodyHash].summary;
    idCache[messageId] = { summary, bodyHash, ts: Date.now() };
    await setCaches(idCache, hashCache);
    return { cached: true, summary, bodyHash };
  }
  return { cached: false, bodyHash };
}

function sendToTab(tabId, payload) {
  if (typeof tabId !== "number") return;
  chrome.tabs.sendMessage(tabId, payload, () => void 0);
}

async function processQueue() {
  if (processing) return;
  processing = true;
  log("Queue processing started. Size:", queue.length);
  while (queue.length > 0) {
    const item = queue.shift();
    if (!item) break;
    enqueued.delete(item.key);
    log("Processing queue item", { key: item.key, remaining: queue.length });
    try {
      const { idCache, hashCache } = await getCaches();
      const idEntry = idCache[item.messageId];
      if (idEntry && idEntry.summary && idEntry.bodyHash === item.bodyHash) {
        log("Cache hit by messageId during processing", item.messageId);
        sendToTab(item.tabId, {
          type: "mailmind_summary_result",
          messageId: item.messageId,
          summary: idEntry.summary,
          source: "cache",
        });
        await sleep(QUEUE_DELAY_MS);
        continue;
      }

      const summary = await callGemini(item.emailText);
      log("Final parsed summary", { messageId: item.messageId, length: summary.length });

      idCache[item.messageId] = { summary, bodyHash: item.bodyHash, ts: Date.now() };
      hashCache[item.bodyHash] = { summary, ts: Date.now(), messageId: item.messageId };
      await setCaches(idCache, hashCache);

      sendToTab(item.tabId, {
        type: "mailmind_summary_result",
        messageId: item.messageId,
        summary,
        source: "gemini",
      });
    } catch (e) {
      log("Queue item failed", { key: item && item.key, error: e && e.message });
      sendToTab(item.tabId, {
        type: "mailmind_summary_error",
        messageId: item && item.messageId,
        error: (e && e.message) || String(e),
      });
    }
    await sleep(QUEUE_DELAY_MS);
  }
  processing = false;
  log("Queue processing ended.");
}

async function handleMultiSummarizeRequest(items, tabId) {
  log("Email IDs received for multi summarize", items);
  for (const it of items) {
    try {
      if (!it || !it.kind || !it.id) continue;
      if (it.kind === "message") {
        const key = `message:${it.id}`;
        if (enqueued.has(key)) {
          log("Duplicate prevented (message)", it.id);
          continue;
        }
        const msg = await fetchMessageById(it.id);
        const text = extractPlainTextFromMessage(msg);
        const cacheCheck = await ensureSummaryCached(it.id, text);
        if (cacheCheck.cached) {
          sendToTab(tabId, {
            type: "mailmind_summary_result",
            messageId: it.id,
            summary: cacheCheck.summary,
            source: "cache",
          });
          continue;
        }
        const qItem = {
          key,
          messageId: it.id,
          bodyHash: cacheCheck.bodyHash,
          emailText: text,
          tabId,
        };
        queue.push(qItem);
        enqueued.add(key);
        log("Queue state changed: added", { key, size: queue.length });
      } else if (it.kind === "thread") {
        const t = await fetchThreadById(it.id);
        const messages = (t && t.messages) || [];
        if (!messages.length) continue;
        const last = messages[messages.length - 1];
        const msgId = last.id;
        const key = `message:${msgId}`;
        if (enqueued.has(key)) {
          log("Duplicate prevented (thread->message)", msgId);
          continue;
        }
        const text = extractPlainTextFromMessage(last);
        const cacheCheck = await ensureSummaryCached(msgId, text);
        if (cacheCheck.cached) {
          sendToTab(tabId, {
            type: "mailmind_summary_result",
            messageId: msgId,
            summary: cacheCheck.summary,
            source: "cache",
          });
          continue;
        }
        const qItem = {
          key,
          messageId: msgId,
          bodyHash: cacheCheck.bodyHash,
          emailText: text,
          tabId,
        };
        queue.push(qItem);
        enqueued.add(key);
        log("Queue state changed: added", { key, size: queue.length });
      }
    } catch (e) {
      log("Failed preparing item", it, e && e.message);
      sendToTab(tabId, {
        type: "mailmind_summary_error",
        messageId: it && it.id,
        error: (e && e.message) || String(e),
      });
    }
  }
  processQueue();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    if (msg && msg.type === "mailmind_multi_summarize_request") {
      const tabId = msg.tabId || (sender && sender.tab && sender.tab.id);
      handleMultiSummarizeRequest(Array.isArray(msg.items) ? msg.items : [], tabId);
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "mailmind_single_summarize_request") {
      const tabId = msg.tabId || (sender && sender.tab && sender.tab.id);
      (async () => {
        try {
          const summary = await callGemini(msg.body || "");
          log("Final parsed summary (single)", { length: summary.length });
          sendToTab(tabId, { type: "mailmind_single_result", mode: "summary", summary });
          sendResponse({ ok: true });
        } catch (e) {
          sendToTab(tabId, { type: "mailmind_single_error", mode: "summary", error: (e && e.message) || String(e) });
          sendResponse({ ok: false, error: (e && e.message) || String(e) });
        }
      })();
      return true;
    }
    if (msg && msg.type === "mailmind_single_reply_request") {
      const tabId = msg.tabId || (sender && sender.tab && sender.tab.id);
      (async () => {
        try {
          const reply = await callGeminiReply(msg.body || "");
          log("Final parsed reply (single)", { length: reply.length });
          sendToTab(tabId, { type: "mailmind_single_result", mode: "reply", summary: reply });
          sendResponse({ ok: true });
        } catch (e) {
          sendToTab(tabId, { type: "mailmind_single_error", mode: "reply", error: (e && e.message) || String(e) });
          sendResponse({ ok: false, error: (e && e.message) || String(e) });
        }
      })();
      return true;
    }
  } catch (e) {
    log("onMessage handler error", e && e.message);
  }
});

log("Service worker loaded");

