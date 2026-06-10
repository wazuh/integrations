/* ── State ── */
let lastCandidate = null;
const history = JSON.parse(localStorage.getItem('wds_history') || '[]');

/* ══ Navigation ══ */
document.querySelectorAll('.sidebar-item').forEach(item => {
  item.addEventListener('click', () => {
    const view = item.dataset.view;
    document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.section-view').forEach(v => v.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('view-' + view).classList.add('active');
  });
});

/* ══ OS_Regex sanitization — strip \. → . (Wazuh OS_Regex uses literal dots) ══ */
function sanitizeOsRegex(xml) {
  return xml;
}

/* ══ Tabs ══ */
// Removed decoder/rule generator tabs; keeping switchTab for future use
function switchTab(tabId) {
  const panel = document.getElementById(tabId);
  if (!panel) return;
  const container = panel.closest('.card');
  if (!container) return;
  container.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  container.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === tabId));
}

/* ══ Toast ══ */
function toast(type, title, msg = '') {
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<div class="toast-body"><div class="toast-title">${icons[type] || '•'} ${title}</div>${msg ? `<div class="toast-msg">${msg}</div>` : ''}</div>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => { el.classList.add('fade-out'); setTimeout(() => el.remove(), 320); }, 3500);
}

/* ══ Copy to clipboard ══ */
function copyText(text, label = 'Copied') {
  navigator.clipboard.writeText(text).then(() => toast('success', label));
}

document.getElementById('copyAiDecoderBtn').addEventListener('click', () =>
  copyText(document.getElementById('aiDecoderXml').textContent, 'AI Decoder copied'));
document.getElementById('copyAiRuleBtn').addEventListener('click', () =>
  copyText(document.getElementById('aiRuleXml').textContent, 'AI Rule copied'));

/* ══ Loading state on buttons ══ */
function setLoading(btn, loading) {
  if (loading) {
    btn.dataset.origText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:inline-block"></span> Working…';
    btn.disabled = true;
  } else {
    btn.innerHTML = btn.dataset.origText || btn.innerHTML;
    btn.disabled = false;
  }
}

/* ══ Read form payload ══ */
function readPayload() {
  const rawInput = document.getElementById('logsInput').value.trim();
  const extractFieldsInput = document.getElementById('extractFields').value.trim();
  const extractFields = extractFieldsInput
    ? extractFieldsInput.split(/[\s,]+/).map(f => f.trim()).filter(Boolean)
    : [];
  let logs;
  try { logs = JSON.parse(rawInput); } catch (_) {
    logs = rawInput.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => ({ raw_log: l }));
  }

  // Parse field hints
  const fieldHintsInput = document.getElementById('fieldHints')?.value.trim() || '';
  const field_hints = {};
  if (fieldHintsInput) {
    fieldHintsInput.split(/\r?\n/).forEach(line => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim();
        const value = parts.slice(1).join(':').trim();
        if (key && value) {
          field_hints[key] = value;
        }
      }
    });
  }

  return {
    app_name: document.getElementById('appName').value,
    logs,
    extract_fields: extractFields,
    field_hints: field_hints,
    install_mode: document.getElementById('installMode').value,
    split_decoders: document.getElementById('splitDecoders').checked,
    log_source_name: document.getElementById('logSourceName').value.trim() || null,
    generation_mode: document.getElementById('generationMode')?.value || 'auto',
    validate_with_logtest: document.getElementById('validateLogtest')?.checked ?? true,
  };
}



async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const body = await res.text();
  if (!res.ok) {
    try {
      const json = JSON.parse(body);
      throw new Error(json.message || json.detail || body);
    } catch (_) {
      throw new Error(body.length > 200 ? 'wazuh-logtest is not accessible' : body);
    }
  }
  try { return JSON.parse(body); } catch (_) { throw new Error(body); }
}

/* ══ XML syntax highlight ══ */
function highlightXml(xml) {
  if (!xml) return '';
  return xml
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/(&lt;\/?[\w-]+)/g, '<span style="color:#60a5fa">$1</span>')
    .replace(/([\w-]+=)(&quot;[^&]*&quot;)/g, '<span style="color:#a78bfa">$1</span><span style="color:#34d399">$2</span>');
}

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* ══ History ══ */
function saveHistory(entry) {
  history.unshift({ ...entry, ts: new Date().toLocaleTimeString() });
  if (history.length > 30) history.pop();
  localStorage.setItem('wds_history', JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('historyList');
  if (!history.length) { list.innerHTML = '<div class="empty-state"><p>No history yet.</p></div>'; return; }
  list.innerHTML = history.map((h, i) => `
    <div class="history-item" onclick="loadHistory(${i})">
      <div class="history-item-top">
        <span class="history-item-name">${escHtml(h.app_name || 'app')}</span>
        <span class="history-item-time">${h.ts}</span>
      </div>
      <div class="history-item-log">${escHtml((h.log || '').substring(0,100))}</div>
    </div>`).join('');
}

window.loadHistory = function(i) {
  const h = history[i];
  if (!h) return;
  if (h.app_name) document.getElementById('appName').value = h.app_name;
  if (h.log) document.getElementById('logsInput').value = h.log;
  document.querySelectorAll('.sidebar-item[data-view="ai"]')[0].click();
  toast('info', 'History loaded');
};

document.getElementById('clearHistoryBtn').addEventListener('click', () => {
  history.length = 0;
  localStorage.removeItem('wds_history');
  renderHistory();
  toast('info', 'History cleared');
});

renderHistory();

/* ══ Health check ══ */
async function checkHealth() {
  const pill = document.getElementById('healthPill');
  try {
    const res = await fetch('/health');
    const data = await res.json();
    const accessible = data.wazuh_logtest_accessible;
    pill.className = accessible ? 'status-pill online' : 'status-pill offline';
    pill.innerHTML = accessible
      ? `<span class="status-dot pulse"></span> Wazuh ${data.wazuh_remote_enabled ? 'Remote' : 'Local'}`
      : `<span class="status-dot"></span> Wazuh ${data.wazuh_remote_enabled ? 'Remote' : 'Local'} (unavailable)`;
    const mlPill = document.getElementById('mlPill');
    mlPill.className = data.ml_model_loaded ? 'status-pill online' : 'status-pill offline';
    mlPill.innerHTML = `<span class="status-dot"></span> ML ${data.ml_pattern_count || 0} patterns`;
  } catch (_) {
    pill.className = 'status-pill offline';
    pill.innerHTML = '<span class="status-dot"></span> Offline';
  }
}
checkHealth();

/* ══ Test: Install / Uninstall / Raw Logtest ══ */
let _installedFiles = JSON.parse(localStorage.getItem('wds_installed') || '[]');
let _lastAIDecoderXml = '';
let _lastAIRuleXml = '';

function updateInstallUI() {
  const info = document.getElementById('installInfo');
  const badge = document.getElementById('installStatusBadge');
  const uninstallBtn = document.getElementById('uninstallBtn');
  if (_installedFiles.length > 0) {
    badge.textContent = 'Installed';
    badge.style.background = 'var(--success)';
    info.style.display = 'block';
    info.textContent = 'Files:\n' + _installedFiles.map(f => '  ' + f).join('\n');
    uninstallBtn.style.display = 'inline-flex';
  } else {
    badge.textContent = 'Not installed';
    badge.style.background = 'var(--text-dim)';
    info.style.display = 'none';
    uninstallBtn.style.display = 'none';
  }
}

// Store AI XML when generated (called from AI handler)
function storeAIXml(decoderXml, ruleXml) {
  _lastAIDecoderXml = decoderXml;
  _lastAIRuleXml = ruleXml;
}

document.getElementById('installBtn').addEventListener('click', async () => {
  const decoderXml = document.getElementById('aiDecoderXml').textContent;
  const ruleXml = document.getElementById('aiRuleXml').textContent;
  if (!decoderXml || decoderXml === '— no decoder block found —') {
    toast('error', 'No AI decoder to install', 'Generate a decoder with AI first.');
    return;
  }
  const appName = document.getElementById('appName').value;
  const btn = document.getElementById('installBtn');
  setLoading(btn, true);
  try {
    const result = await postJson('/api/install', {
      decoder_xml: decoderXml,
      rule_xml: ruleXml || null,
      app_name: appName,
    });
    if (result.success) {
      _installedFiles = result.written_files;
      localStorage.setItem('wds_installed', JSON.stringify(_installedFiles));
      updateInstallUI();
      toast('success', 'Decoder installed to Wazuh', result.written_files.length + ' file(s) written');
    } else {
      toast('error', 'Install failed', result.errors.join('; '));
    }
  } catch (e) { toast('error', 'Install error', e.message); }
  finally { setLoading(btn, false); }
});

document.getElementById('uninstallBtn').addEventListener('click', async () => {
  if (!_installedFiles.length) return;
  const btn = document.getElementById('uninstallBtn');
  setLoading(btn, true);
  try {
    const result = await postJson('/api/uninstall', { file_paths: _installedFiles });
    _installedFiles = [];
    localStorage.removeItem('wds_installed');
    updateInstallUI();
    toast('success', 'Uninstalled', result.removed_files.length + ' file(s) removed');
  } catch (e) { toast('error', 'Uninstall error', e.message); }
  finally { setLoading(btn, false); }
});

document.getElementById('logtestRunBtn').addEventListener('click', async () => {
  const rawInput = document.getElementById('testLogsInput').value.trim();
  if (!rawInput) { toast('error', 'No logs', 'Paste log samples to test.'); return; }
  const logs = rawInput.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const btn = document.getElementById('logtestRunBtn');
  setLoading(btn, true);
  const outArea = document.getElementById('logtestOutputArea');
  const parsedArea = document.getElementById('logtestParsedArea');
  outArea.innerHTML = '<pre style="font-size:12px;font-family:JetBrains Mono,monospace;color:var(--text-dim);padding:8px;margin:0">Running wazuh-logtest…</pre>';
  parsedArea.style.display = 'none';

  try {
    const result = await postJson('/api/logtest/raw', { logs });
    let allStdout = '';
    let allParsed = [];

    result.results.forEach((r, i) => {
      if (i > 0) allStdout += '\n' + '-'.repeat(60) + '\n';
      allStdout += '[Log ' + (i + 1) + ']: ' + r.raw_log + '\n';
      if (r.available) {
        allStdout += r.stdout || '(no output)';
        if (r.stderr) allStdout += '\n[stderr]: ' + r.stderr;
      } else {
        allStdout += '[unavailable] ' + (r.stderr || 'wazuh-logtest not accessible');
      }
      if (r.parsed && Object.keys(r.parsed).length > 1) allParsed.push(r.parsed);
    });

    outArea.innerHTML = '<pre style="font-size:12px;font-family:JetBrains Mono,monospace;color:var(--text);padding:10px 14px;margin:0;background:var(--bg);border:1px solid var(--border);border-radius:6px;max-height:400px;overflow:auto;white-space:pre-wrap">' + escHtml(allStdout) + '</pre>';

    if (allParsed.length) {
      const rows = Object.entries(allParsed[0]).map(([k, v]) =>
        `<tr><td style="padding:5px 10px;font-size:12px;border-bottom:1px solid var(--border);color:var(--text-muted);white-space:nowrap">${escHtml(k)}</td><td style="padding:5px 10px;font-size:12px;font-family:JetBrains Mono,monospace;border-bottom:1px solid var(--border)">${escHtml(String(v))}</td></tr>`
      ).join('');
      document.getElementById('logtestParsedTable').innerHTML = '<table style="width:100%;border-collapse:collapse">' + rows + '</table>';
      parsedArea.style.display = 'block';
    }

    saveHistory({ app_name: document.getElementById('appName').value, log: logs[0] || '' });
    toast('success', 'wazuh-logtest completed');
  } catch (e) {
    outArea.innerHTML = '<pre style="font-size:12px;font-family:JetBrains Mono,monospace;color:var(--danger);padding:10px 14px;margin:0">Error: ' + escHtml(e.message) + '</pre>';
    toast('error', 'Logtest failed', e.message);
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById('logtestClearBtn').addEventListener('click', () => {
  document.getElementById('logtestOutputArea').innerHTML = '<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><p>Run wazuh-logtest to see output here.</p></div>';
  document.getElementById('logtestParsedArea').style.display = 'none';
});

document.getElementById('copyLogtestOutputBtn').addEventListener('click', () => {
  const pre = document.querySelector('#logtestOutputArea pre');
  if (pre) copyText(pre.textContent, 'Logtest output copied');
  else toast('info', 'Nothing to copy');
});

updateInstallUI();

document.getElementById('feedbackYesBtn').addEventListener('click', async () => {
  const btn = document.getElementById('feedbackYesBtn');
  setLoading(btn, true);
  try {
    const p = readPayload();
    const log = (p.logs[0] || {}).raw_log;
    if (!log) throw new Error('Provide at least one log sample.');
    const regex = document.getElementById('feedbackRegex').value.trim();
    const order = document.getElementById('feedbackOrder').value.trim().split(/[\s,]+/).filter(Boolean);
    if (!regex || !order.length) throw new Error('Regex and order are required.');
    const result = await postJson('/api/feedback', {
      approved: true, app_name: p.app_name, log, extract_fields: p.extract_fields,
      notes: document.getElementById('feedbackNotes').value.trim(),
      decoder: { name: lastCandidate?.decoder_name || `${p.app_name}-event`, parent: p.app_name, prematch: document.getElementById('feedbackPrematch').value.trim(), regex, order, source_file: `feedback/${p.app_name}.json` },
    });
    document.getElementById('feedbackOut').textContent = JSON.stringify(result, null, 2);
    toast('success', 'Feedback saved', result.trained ? 'Model retrained.' : 'Saved.');
    checkHealth();
  } catch (e) { toast('error', 'Feedback error', e.message); }
  finally { setLoading(btn, false); }
});

document.getElementById('feedbackNoBtn').addEventListener('click', async () => {
  const btn = document.getElementById('feedbackNoBtn');
  setLoading(btn, true);
  try {
    const p = readPayload();
    const log = (p.logs[0] || {}).raw_log;
    if (!log) throw new Error('Provide at least one log sample.');
    const result = await postJson('/api/feedback', { approved: false, app_name: p.app_name, log, extract_fields: p.extract_fields, notes: document.getElementById('feedbackNotes').value.trim() });
    document.getElementById('feedbackOut').textContent = JSON.stringify(result, null, 2);
    toast('info', 'Rejection saved');
  } catch (e) { toast('error', 'Feedback error', e.message); }
  finally { setLoading(btn, false); }
});

/* ══ ML ══ */
document.getElementById('mlStatusBtn').addEventListener('click', async () => {
  const btn = document.getElementById('mlStatusBtn');
  setLoading(btn, true);
  try {
    const res = await fetch('/api/ml/status');
    const data = await res.json();
    const out = document.getElementById('mlStatusOut');
    out.innerHTML = `<div class="ml-stat-grid">
      <div class="ml-stat"><div class="ml-stat-label">Status</div><div class="ml-stat-value" style="font-size:16px">${data.model_loaded ? '🟢 Loaded' : '🔴 Not loaded'}</div></div>
      <div class="ml-stat"><div class="ml-stat-label">Patterns</div><div class="ml-stat-value">${data.pattern_count}</div></div>
      <div class="ml-stat" style="grid-column:1/-1"><div class="ml-stat-label">Repo cache</div><div style="font-size:12px;font-family:JetBrains Mono,monospace;margin-top:4px;color:var(--text-dim)">${data.repo_cache_dir}</div></div>
      ${data.error ? `<div class="ml-stat" style="grid-column:1/-1;border-color:var(--danger)"><div class="ml-stat-label" style="color:var(--danger)">Error</div><div style="font-size:12px;color:var(--danger)">${escHtml(data.error)}</div></div>` : ''}
    </div>`;
    toast('success', `ML: ${data.pattern_count} patterns loaded`);
    checkHealth();
  } catch (e) { toast('error', 'ML status error', e.message); }
  finally { setLoading(btn, false); }
});

document.getElementById('mlRefreshBtn').addEventListener('click', async () => {
  const btn = document.getElementById('mlRefreshBtn');
  setLoading(btn, true);
  try {
    const result = await postJson('/api/ml/refresh', { force: false });
    toast(result.model_loaded ? 'success' : 'error', `ML refresh: ${result.pattern_count} patterns`, result.error || '');
    checkHealth();
  } catch (e) { toast('error', 'ML refresh failed', e.message); }
  finally { setLoading(btn, false); }
});

/* ══ AI Generate ══ */
async function checkExistingDecoder(payload) {
  try {
    // Only show warning if user hasn't explicitly disabled it or is just testing
    const analyzeRes = await postJson('/api/analyze', payload);
    if (analyzeRes && analyzeRes.wazuh_logtest_summary && analyzeRes.wazuh_logtest_summary.builtin_decoder_seen) {
      const decoderName = analyzeRes.wazuh_logtest_summary.decoder_name || "unknown";
      return confirm(`This log already matches an existing decoder: "${decoderName}".\nAre you sure you want to generate a new decoder for it?`);
    }
  } catch (e) {
    console.error("Failed to check existing decoders:", e);
  }
  return true;
}

document.getElementById('aiGenerateBtn').addEventListener('click', async () => {
  const btn = document.getElementById('aiGenerateBtn');
  setLoading(btn, true);
  const statusEl = document.getElementById('aiStatus');
  const xmlOut = document.getElementById('aiXmlOut');
  statusEl.style.display = 'block';
  xmlOut.style.display = 'none';

  try {
    const p = readPayload();
    
    const shouldProceed = await checkExistingDecoder(p);
    if (!shouldProceed) {
      statusEl.style.display = 'none';
      setLoading(btn, false);
      return;
    }

    const temperature = parseFloat(document.getElementById('aiTemperature').value);
    const extraContext = document.getElementById('aiExtraContext').value.trim();
    const genMode = document.getElementById('generationMode')?.value || 'auto';

    const ruleSection = document.getElementById('aiRuleSection');
    if (ruleSection) {
      ruleSection.style.display = genMode === 'decoder_only' ? 'none' : 'block';
    }

    const res = await fetch('/api/ai/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...p, temperature, extra_context: extraContext }),
    });

    if (!res.ok) throw new Error(await res.text());

    const fullText = await res.text();
    statusEl.style.display = 'none';

    // Extract XML blocks from AI response
    const decoderMatch = fullText.match(/```xml\s*([\s\S]*?decoder[\s\S]*?)```/i) || fullText.match(/<decoder[\s\S]*?<\/decoder>/i);
    const ruleMatch = fullText.match(/```xml\s*([\s\S]*?rule[\s\S]*?)```/i) || fullText.match(/<group[\s\S]*?<\/group>/i);

    const decoderXml = sanitizeOsRegex(decoderMatch ? (decoderMatch[1] || decoderMatch[0]).trim() : '');
    const ruleXml = sanitizeOsRegex(ruleMatch ? (ruleMatch[1] || ruleMatch[0]).trim() : '');

    if (decoderXml || ruleXml) {
      document.getElementById('aiDecoderXml').innerHTML = highlightXml(decoderXml || '— no decoder block found —');
      document.getElementById('aiRuleXml').innerHTML = highlightXml(ruleXml || '— no rule block found —');
      storeAIXml(decoderXml, ruleXml);
      xmlOut.style.display = 'block';
      toast('success', 'AI generation complete');
    } else {
      toast('info', 'No XML extracted', 'The AI response did not contain valid decoder/rule XML.');
    }
  } catch (e) {
    statusEl.style.display = 'none';
    toast('error', 'AI error', e.message);
  } finally {
    setLoading(btn, false);
  }
});

/* ══ AI Generate & Validate ══ */
document.getElementById('aiGenerateValidateBtn').addEventListener('click', async () => {
  const btn = document.getElementById('aiGenerateValidateBtn');
  setLoading(btn, true);
  const statusEl = document.getElementById('aiStatus');
  const xmlOut = document.getElementById('aiXmlOut');
  const validationOut = document.getElementById('aiValidationOut');
  const validationBadge = document.getElementById('validationBadge');
  const validationDetails = document.getElementById('validationDetails');
  statusEl.style.display = 'block';
  statusEl.querySelector('.ai-label').innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Generating & validating with wazuh-logtest…';
  xmlOut.style.display = 'none';
  validationOut.style.display = 'none';

  try {
    const p = readPayload();
    
    const shouldProceed = await checkExistingDecoder(p);
    if (!shouldProceed) {
      statusEl.style.display = 'none';
      setLoading(btn, false);
      return;
    }

    const temperature = parseFloat(document.getElementById('aiTemperature').value);
    const extraContext = document.getElementById('aiExtraContext').value.trim();
    const genMode = document.getElementById('generationMode')?.value || 'auto';

    const ruleSection = document.getElementById('aiRuleSection');
    if (ruleSection) {
      ruleSection.style.display = genMode === 'decoder_only' ? 'none' : 'block';
    }

    const result = await postJson('/api/ai/generate-validated', {
      ...p, temperature, extra_context: extraContext,
    });

    // Show validation results
    validationOut.style.display = 'block';
    const validated = result.validation?.validated;
    validationBadge.textContent = validated ? '✓ Passed' : '✗ Failed';
    validationBadge.style.background = validated ? 'var(--success)' : 'var(--danger)';
    let detailsText = `Attempts: ${result.attempts}\nValidation: ${result.validation?.reason || 'unknown'}\n`;
    if (result.validation?.results) {
      result.validation.results.forEach((r, i) => {
        detailsText += `\n[Log ${i+1}] ${r.matched ? '✓' : '✗'} decoder=${r.decoder_matched || 'none'}`;
        if (r.fields && Object.keys(r.fields).length) {
          detailsText += '\n  Fields: ' + Object.entries(r.fields).map(([k,v]) => `${k}=${v}`).join(', ');
        }
      });
    }
    validationDetails.textContent = detailsText;

    // Show XML output
    if (result.decoder_xml || result.rule_xml) {
      const decXml = sanitizeOsRegex(result.decoder_xml || '— no decoder —');
      const rulXml = sanitizeOsRegex(result.rule_xml || '— no rule —');
      document.getElementById('aiDecoderXml').innerHTML = highlightXml(decXml);
      document.getElementById('aiRuleXml').innerHTML = highlightXml(rulXml);
      storeAIXml(decXml, rulXml);
      xmlOut.style.display = 'block';
      toast(validated ? 'success' : 'info',
        validated ? 'Validated decoder generated!' : `Best attempt after ${result.attempts} tries`,
        validated ? 'Decoder confirmed working with wazuh-logtest' : 'Decoder may need manual adjustment'
      );
    }
    saveHistory({ app_name: p.app_name, log: (p.logs[0] || {}).raw_log || '' });
  } catch (e) {
    toast('error', 'Generate & Validate error', e.message);
  } finally {
    statusEl.style.display = 'none';
    setLoading(btn, false);
  }
});

document.getElementById('aiClearBtn').addEventListener('click', () => {
  document.getElementById('aiXmlOut').style.display = 'none';
  document.getElementById('aiStatus').style.display = 'none';
  const valOut = document.getElementById('aiValidationOut');
  if (valOut) valOut.style.display = 'none';
});



/* ── Spinner keyframe (injected) ── */
const s = document.createElement('style');
s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
document.head.appendChild(s);
