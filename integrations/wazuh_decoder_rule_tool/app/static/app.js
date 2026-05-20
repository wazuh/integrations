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

/* ══ Tabs ══ */
document.getElementById('outputTabs').addEventListener('click', e => {
  const btn = e.target.closest('.tab-btn');
  if (!btn) return;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(btn.dataset.tab).classList.add('active');
});

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === tabId));
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

document.getElementById('copyDecoderBtn').addEventListener('click', () =>
  copyText(document.getElementById('decoderOut').textContent, 'Decoder XML copied'));
document.getElementById('copyRuleBtn').addEventListener('click', () =>
  copyText(document.getElementById('ruleOut').textContent, 'Rule XML copied'));
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
    rule_id: Number(document.getElementById('ruleId').value),
    level: Number(document.getElementById('level').value),
    rule_requirement: document.getElementById('ruleRequirement').value.trim(),
    extract_fields: extractFields,
    field_hints: field_hints,
    install_mode: document.getElementById('installMode').value,
    split_decoders: document.getElementById('splitDecoders').checked,
    log_source_name: document.getElementById('logSourceName').value.trim() || null,
  };
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

/* ══ XML syntax highlight ══ */
function highlightXml(xml) {
  if (!xml) return '';
  return xml
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/(&lt;\/?[\w-]+)/g, '<span style="color:#60a5fa">$1</span>')
    .replace(/([\w-]+=)(&quot;[^&]*&quot;)/g, '<span style="color:#a78bfa">$1</span><span style="color:#34d399">$2</span>');
}

function showXml(preId, xml, fallback = 'None generated.') {
  const pre = document.getElementById(preId);
  if (xml) { pre.innerHTML = highlightXml(xml); } else { pre.textContent = fallback; }
}

/* ══ Analysis display ══ */
function showAnalysis(data) {
  const out = document.getElementById('analysisOut');
  if (!data) { out.innerHTML = '<div class="empty-state"><p>No data.</p></div>'; return; }
  const wlt = data.wazuh_logtest_summary || {};
  const available = wlt.available ? '🟢 Available' : '🔴 Unavailable';
  const decoderSeen = wlt.builtin_decoder_seen ? `✓ ${wlt.decoder_name}` : '✗ None matched';
  const items = [
    ['Log type', data.log_type], ['App name', data.app_name],
    ['Log source', data.log_source_name || data.program_name],
    ['Program name', data.program_name], ['Predecoded program', data.predecoded_program_name || '—'],
    ['Prematch', data.prematch], ['Regex', data.regex_display || data.regex],
    ['Order', (data.order || []).join(', ')], ['Logtest', available],
    ['Built-in decoder', decoderSeen], ['Missing fields', (data.missing_extract_fields || []).join(', ') || '—'],
  ];
  const rows = items.map(([k, v]) =>
    `<tr><td style="color:var(--text-muted);padding:5px 10px;font-size:12px;border-bottom:1px solid var(--border);white-space:nowrap">${k}</td><td style="padding:5px 10px;font-size:12px;font-family:JetBrains Mono,monospace;border-bottom:1px solid var(--border)">${v ?? '—'}</td></tr>`
  ).join('');
  let mlHtml = '';
  if (data.ml_suggestions && data.ml_suggestions.length) {
    const cards = data.ml_suggestions.slice(0,3).map(s =>
      `<div class="result-card" style="padding:10px 14px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="font-weight:700;color:var(--primary)">${s.name}</span>
          <span class="pass-badge">${(s.score*100).toFixed(0)}%</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);font-family:JetBrains Mono,monospace">${s.regex || '—'}</div>
      </div>`
    ).join('');
    mlHtml = `<div style="margin-top:16px"><div class="card-title" style="margin-bottom:8px">ML Suggestions</div>${cards}</div>`;
  }
  out.innerHTML = `<table style="width:100%;border-collapse:collapse">${rows}</table>${mlHtml}`;
  updateRegexPreview(data.regex || '');
}

/* ══ Regex preview ══ */
function updateRegexPreview(regex) {
  const preview = document.getElementById('regexPreview');
  const log = document.getElementById('logsInput').value.split('\n').find(l => l.trim()) || '';
  if (!regex || !log) { preview.innerHTML = '<span style="color:var(--text-muted)">Run Analyze…</span>'; return; }
  try {
    const pyToJs = regex.replace(/\\d/g,'\\d').replace(/\\S/g,'\\S').replace(/\\s/g,'\\s').replace(/\\.\\+/g,'[\\s\\S]+').replace(/\\.\\*/g,'[\\s\\S]*');
    const m = log.match(new RegExp(pyToJs));
    if (!m) { preview.innerHTML = `<span style="color:var(--text-muted)">${escHtml(log)}</span>`; return; }
    let out = escHtml(log.slice(0, m.index));
    out += `<span class="regex-match">${escHtml(m[0])}</span>`;
    out += escHtml(log.slice(m.index + m[0].length));
    preview.innerHTML = out;
  } catch (_) { preview.textContent = log; }
}

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* ══ Test results ══ */
function renderTestResults(results) {
  const out = document.getElementById('testOut');
  if (!results || !results.length) { out.innerHTML = '<div class="empty-state"><p>No results.</p></div>'; return; }
  out.innerHTML = results.map(r => {
    const ev = r.evaluation || {};
    const parsed = r.parsed || {};
    const pass = ev.pass;
    const fields = r.auto_fields || {};
    const stdout = (r.logtest || {}).stdout || '';
    const fieldRows = Object.entries(fields).map(([k,v]) => {
      const matched = stdout.includes(v);
      return `<tr><td class="field-name">${k}</td><td class="${matched?'field-match':'field-miss'}">${matched?'✓':'✗'} ${escHtml(v)}</td></tr>`;
    }).join('');
    return `<div class="result-card">
      <div class="result-card-header">
        <span class="result-card-log">${escHtml(r.raw_log)}</span>
        <span class="${pass?'pass-badge':'fail-badge'}">${pass?'PASS':'FAIL'} ${ev.score||0}/100</span>
      </div>
      <div class="result-card-body">
        <div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">
          Decoder: <strong>${parsed.decoder_name||'—'}</strong> &nbsp;|&nbsp; Rule: <strong>${parsed.rule_id||'—'}</strong>
        </div>
        ${fieldRows ? `<table class="field-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${fieldRows}</tbody></table>` : ''}
        ${stdout ? `<details style="margin-top:8px"><summary style="font-size:11px;color:var(--text-muted);cursor:pointer">Raw logtest output</summary><pre style="font-size:11px;margin-top:6px;max-height:150px;overflow:auto;color:var(--text-dim)">${escHtml(stdout)}</pre></details>` : ''}
      </div>
    </div>`;
  }).join('');
}

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
  document.querySelectorAll('.sidebar-item[data-view="generate"]')[0].click();
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
    pill.className = 'status-pill online';
    pill.innerHTML = `<span class="status-dot pulse"></span> Wazuh ${data.wazuh_remote_enabled ? 'Remote' : 'Local'}`;
    const mlPill = document.getElementById('mlPill');
    mlPill.className = data.ml_model_loaded ? 'status-pill online' : 'status-pill offline';
    mlPill.innerHTML = `<span class="status-dot"></span> ML ${data.ml_pattern_count || 0} patterns`;
  } catch (_) {
    pill.className = 'status-pill offline';
    pill.innerHTML = '<span class="status-dot"></span> Offline';
  }
}
checkHealth();

/* ══ Analyze ══ */
document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const btn = document.getElementById('analyzeBtn');
  setLoading(btn, true);
  try {
    const p = readPayload();
    const result = await postJson('/api/analyze', { app_name: p.app_name, logs: p.logs, rule_requirement: p.rule_requirement, extract_fields: p.extract_fields });
    showAnalysis(result);
    switchTab('tab-analysis');
    toast('success', 'Analysis complete');
  } catch (e) { toast('error', 'Analyze failed', e.message); }
  finally { setLoading(btn, false); }
});

/* ══ Generate ══ */
document.getElementById('generateBtn').addEventListener('click', async () => {
  const btn = document.getElementById('generateBtn');
  setLoading(btn, true);
  try {
    const p = readPayload();
    const result = await postJson('/api/generate', p);
    lastCandidate = result;
    showAnalysis(result.analysis);
    showXml('decoderOut', result.decoder_xml, result.decision?.decoder_skip_reason || 'No decoder XML.');
    showXml('ruleOut', result.rule_xml, result.decision?.rule_skip_reason || 'No rule XML.');
    syncFeedback(result);
    saveHistory({ app_name: p.app_name, log: (p.logs[0] || {}).raw_log || '' });
    switchTab('tab-decoder');
    toast('success', 'Decoder generated');
    if (result.decision?.regex_validation_errors?.length) toast('info', 'Regex warnings', result.decision.regex_validation_errors[0]);
  } catch (e) { toast('error', 'Generate failed', e.message); }
  finally { setLoading(btn, false); }
});

/* ══ Test ══ */
async function runTest(outputEl) {
  const p = readPayload();
  const result = await postJson('/api/test', {
    candidate: { app_name: p.app_name, logs: p.logs, rule_id: p.rule_id, level: p.level, rule_requirement: p.rule_requirement, extract_fields: p.extract_fields, log_source_name: p.log_source_name },
    install_mode: p.install_mode,
  });
  lastCandidate = result.candidate;
  showAnalysis(result.candidate.analysis);
  showXml('decoderOut', result.candidate.decoder_xml, result.candidate.decision?.decoder_skip_reason || 'No decoder XML.');
  showXml('ruleOut', result.candidate.rule_xml, result.candidate.decision?.rule_skip_reason || 'No rule XML.');
  renderTestResults(result.results);
  syncFeedback(result.candidate);
  saveHistory({ app_name: p.app_name, log: (p.logs[0] || {}).raw_log || '' });
  const pass = result.results.every(r => r.evaluation?.pass);
  toast(pass ? 'success' : 'error', pass ? 'All tests passed' : 'Some tests failed');
  return result;
}

document.getElementById('testBtn').addEventListener('click', async () => {
  const btn = document.getElementById('testBtn');
  setLoading(btn, true);
  try { await runTest('testOut'); switchTab('tab-test'); }
  catch (e) { toast('error', 'Test failed', e.message); }
  finally { setLoading(btn, false); }
});

document.getElementById('testBtn2').addEventListener('click', async () => {
  const btn = document.getElementById('testBtn2');
  setLoading(btn, true);
  try {
    const result = await runTest('testOut2');
    document.getElementById('testOut2').innerHTML = document.getElementById('testOut').innerHTML;
  }
  catch (e) { toast('error', 'Test failed', e.message); }
  finally { setLoading(btn, false); }
});

/* ══ Feedback sync ══ */
function syncFeedback(candidate) {
  lastCandidate = candidate;
  const a = candidate?.analysis || {};
  document.getElementById('feedbackPrematch').value = a.prematch || '';
  document.getElementById('feedbackRegex').value = a.regex || '';
  document.getElementById('feedbackOrder').value = (a.order || []).join(',');
}

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
document.getElementById('aiGenerateBtn').addEventListener('click', async () => {
  const btn = document.getElementById('aiGenerateBtn');
  setLoading(btn, true);
  const statusEl = document.getElementById('aiStatus');
  const outEl = document.getElementById('aiOut');
  const xmlOut = document.getElementById('aiXmlOut');
  statusEl.style.display = 'block';
  outEl.style.display = 'block';
  outEl.textContent = '';
  xmlOut.style.display = 'none';

  try {
    const p = readPayload();
    const temperature = parseFloat(document.getElementById('aiTemperature').value);
    const extraContext = document.getElementById('aiExtraContext').value.trim();

    const res = await fetch('/api/ai/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...p, temperature, extra_context: extraContext }),
    });

    if (!res.ok) throw new Error(await res.text());

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let fullText = '';
    let cursor = document.createElement('span');
    cursor.className = 'ai-cursor';
    outEl.appendChild(cursor);

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value);
      fullText += chunk;
      outEl.textContent = fullText;
      outEl.appendChild(cursor);
      outEl.scrollTop = outEl.scrollHeight;
    }

    cursor.remove();
    statusEl.style.display = 'none';

    // Extract XML blocks from AI response
    const decoderMatch = fullText.match(/```xml\s*([\s\S]*?decoder[\s\S]*?)```/i) || fullText.match(/<decoder[\s\S]*?<\/decoder>/i);
    const ruleMatch = fullText.match(/```xml\s*([\s\S]*?rule[\s\S]*?)```/i) || fullText.match(/<group[\s\S]*?<\/group>/i);

    const decoderXml = decoderMatch ? (decoderMatch[1] || decoderMatch[0]).trim() : '';
    const ruleXml = ruleMatch ? (ruleMatch[1] || ruleMatch[0]).trim() : '';

    if (decoderXml || ruleXml) {
      document.getElementById('aiDecoderXml').innerHTML = highlightXml(decoderXml || '— no decoder block found —');
      document.getElementById('aiRuleXml').innerHTML = highlightXml(ruleXml || '— no rule block found —');
      xmlOut.style.display = 'block';
      toast('success', 'AI generation complete');
    } else {
      toast('info', 'AI responded', 'No XML blocks extracted — check raw output above.');
    }
  } catch (e) {
    statusEl.style.display = 'none';
    toast('error', 'AI error', e.message);
    outEl.textContent = 'Error: ' + e.message;
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById('aiClearBtn').addEventListener('click', () => {
  document.getElementById('aiOut').style.display = 'none';
  document.getElementById('aiXmlOut').style.display = 'none';
  document.getElementById('aiStatus').style.display = 'none';
  document.getElementById('aiOut').textContent = '';
});

document.getElementById('applyAiBtn').addEventListener('click', () => {
  const decoderXml = document.getElementById('aiDecoderXml').textContent;
  const ruleXml = document.getElementById('aiRuleXml').textContent;
  document.getElementById('decoderOut').innerHTML = highlightXml(decoderXml);
  document.getElementById('ruleOut').innerHTML = highlightXml(ruleXml);
  document.querySelectorAll('.sidebar-item[data-view="generate"]')[0].click();
  switchTab('tab-decoder');
  toast('success', 'AI output applied to Generate view');
});

/* ── Spinner keyframe (injected) ── */
const s = document.createElement('style');
s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
document.head.appendChild(s);
