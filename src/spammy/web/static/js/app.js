/**
 * Spammy UI – single-page API client
 *
 * All data comes from /api/v1/.  HTML templates are minimal shells;
 * this script handles all rendering and interaction.
 */

/* -------------------------------------------------------------------------
 * API client (thin fetch wrapper with CSRF injection)
 * ---------------------------------------------------------------------- */
const SpammyClient = (() => {
  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  }

  async function get(url) {
    const resp = await fetch(url, {
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
    });
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
    return resp.json();
  }

  async function post(url, body) {
    const resp = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'X-CSRF-Token': csrfToken(),
        'Accept': 'application/json',
      },
      body,
    });
    if (!resp.ok) {
      let msg = `${resp.status} ${resp.statusText}`;
      try { const j = await resp.json(); msg = j.description || j.error || msg; } catch (_) {}
      throw new Error(msg);
    }
    return resp.json();
  }

  return { get, post, csrfToken };
})();


/* -------------------------------------------------------------------------
 * Dashboard page
 * ---------------------------------------------------------------------- */
const DashboardPage = (() => {
  function categoryBadge(cat) {
    const map = { high: 'badge--danger', medium: 'badge--warning', low: 'badge--success' };
    const cls = map[cat] || 'badge--neutral';
    return `<span class="badge ${cls}">${esc(cat) || '–'}</span>`;
  }

  function renderRow(m) {
    const date = new Date(m.created_at).toLocaleString('de-DE');
    return `<tr>
      <td>${esc(m.subject || '(kein Betreff)')}</td>
      <td class="mono">${esc(m.sender || '–')}</td>
      <td class="mono">${esc(m.recipient || '–')}</td>
      <td>${categoryBadge(m.category)}</td>
      <td class="muted">${date}</td>
      <td></td>
    </tr>`;
  }

  async function loadStats() {
    try {
      const data = await SpammyClient.get('/api/v1/stats');
      const j = data.jobs;
      const s = data.storage;
      function fmt(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      }
      fmt('stat-pending-val', j.pending);
      fmt('stat-running-val', j.running);
      fmt('stat-done-val', j.done);
      fmt('stat-total-val', j.total_submitted);
      fmt('stat-storage-val', s.total_messages);
      const h = Math.floor(j.uptime_seconds / 3600);
      const m = Math.floor((j.uptime_seconds % 3600) / 60);
      fmt('stat-uptime-val', `${h}h ${m}m`);
    } catch (_) { /* ignorieren – Stats sind optional */ }
  }

  async function loadHistory() {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    try {
      const messages = await SpammyClient.get('/api/v1/history?limit=25');
      if (!messages.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center muted">Noch keine Analysen vorhanden.</td></tr>';
      } else {
        tbody.innerHTML = messages.map(renderRow).join('');
      }
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center error">Fehler: ${esc(e.message)}</td></tr>`;
    }
  }

  function init() {
    if (!document.getElementById('history-tbody')) return;
    loadStats();
    loadHistory();
    setInterval(loadStats, 10000);
    setInterval(loadHistory, 5000);
  }

  return { init };
})();


/* -------------------------------------------------------------------------
 * Analyze page
 * ---------------------------------------------------------------------- */
const AnalyzePage = (() => {
  function showError(msg) {
    const el = document.getElementById('analyze-error');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function hideError() {
    const el = document.getElementById('analyze-error');
    if (el) el.style.display = 'none';
  }

  function setBusy(busy) {
    const btn = document.getElementById('submit-btn');
    if (!btn) return;
    btn.querySelector('.btn-text').hidden = busy;
    btn.querySelector('.btn-spinner').hidden = !busy;
    btn.disabled = busy;
  }

  function initTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('tab-btn--active'));
        btn.classList.add('tab-btn--active');
        const target = btn.dataset.tab;
        document.querySelectorAll('.tab-panel').forEach(p => {
          p.hidden = p.id !== `tab-${target}`;
        });
      });
    });
  }

  function initFileDrop() {
    const drop = document.getElementById('file-drop');
    const input = document.getElementById('eml_file');
    const nameEl = document.getElementById('file-name');
    if (!drop || !input) return;

    input.addEventListener('change', () => {
      if (input.files[0]) { nameEl.textContent = input.files[0].name; nameEl.hidden = false; }
    });

    ['dragover', 'dragenter'].forEach(ev => {
      drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('file-drop--active'); });
    });
    ['dragleave', 'drop'].forEach(ev => {
      drop.addEventListener(ev, () => drop.classList.remove('file-drop--active'));
    });
    drop.addEventListener('drop', e => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file) {
        const dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        nameEl.textContent = file.name;
        nameEl.hidden = false;
      }
    });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    hideError();

    const fileInput = document.getElementById('eml_file');
    const textInput = document.getElementById('raw_text');
    const activeTab = document.querySelector('.tab-btn--active')?.dataset.tab;

    const body = new FormData();
    if (activeTab === 'upload') {
      if (!fileInput?.files[0]) { showError('Bitte eine EML-Datei auswählen.'); return; }
      body.append('eml_file', fileInput.files[0]);
    } else {
      const txt = textInput?.value.trim();
      if (!txt) { showError('Bitte E-Mail-Quelltext einfügen.'); return; }
      body.append('raw_text', txt);
    }

    setBusy(true);
    try {
      const job = await SpammyClient.post('/api/v1/analyze', body);
      window.location.href = `/report/${job.job_id}`;
    } catch (err) {
      showError(err.message);
      setBusy(false);
    }
  }

  function init() {
    const form = document.getElementById('analyze-form');
    if (!form) return;
    initTabs();
    initFileDrop();
    form.addEventListener('submit', handleSubmit);
  }

  return { init };
})();


/* -------------------------------------------------------------------------
 * Report page – polling + full client-side rendering
 * ---------------------------------------------------------------------- */
const ReportPage = (() => {
  const POLL_INTERVAL = 2000;
  let pollTimer = null;

  function pct(v) { return Math.round((v || 0) * 100); }

  function scoreClass(total) {
    if (total >= 0.7) return 'score--high';
    if (total >= 0.4) return 'score--medium';
    return 'score--low';
  }

  function scoreLabel(total) {
    const p = pct(total);
    if (p >= 70) return `<span class="badge badge--danger">${p}\u202f% \u2013 Spam</span>`;
    if (p >= 40) return `<span class="badge badge--warning">${p}\u202f% \u2013 Verd\u00e4chtig</span>`;
    return `<span class="badge badge--success">${p}\u202f% \u2013 Unauff\u00e4llig</span>`;
  }

  function authBadge(result) {
    const cls = result === 'pass' ? 'badge--success' : result === 'fail' ? 'badge--danger' : 'badge--neutral';
    return `<span class="badge ${cls}">${esc(result || 'none')}</span>`;
  }

  function renderMetadata(meta) {
    const rows = [
      ['Betreff', meta.subject],
      ['Von', meta.sender],
      ['An', meta.recipient],
      ['Datum', meta.date],
      ['Message-ID', meta.message_id],
    ].filter(([, v]) => v).map(([k, v]) =>
      `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`
    ).join('');
    return `<section class="section">
      <h2 class="section-heading">Nachrichtendetails</h2>
      <table class="kv-table"><tbody>${rows}</tbody></table>
    </section>`;
  }

  function renderScore(score) {
    const t = score.total || 0;
    const items = [
      ['Header', score.header_score],
      ['Authentifizierung', score.auth_score],
      ['Body', score.body_score],
      ['URLs', score.url_score],
      ['Netzwerk', score.network_score],
    ].map(([label, v]) => `
      <div class="score-sub">
        <span class="score-sub__label">${label}</span>
        <div class="progress"><div class="progress__bar" style="width:${pct(v)}%"></div></div>
        <span class="score-sub__value">${pct(v)}\u202f%</span>
      </div>`).join('');

    const signals = (score.signals || []).map(s => `
      <tr>
        <td>${esc(s.name)}</td>
        <td class="muted">${esc(s.description || '')}</td>
        <td><span class="badge badge--cat-${esc(s.category || 'other')}">${esc(s.category || '')}</span></td>
        <td class="mono">${s.weight > 0 ? '+' : ''}${s.weight}</td>
      </tr>`).join('');

    return `<section class="section">
      <h2 class="section-heading">Spam-Score: ${scoreLabel(t)}</h2>
      <div class="score-gauge ${scoreClass(t)}">
        <div class="score-gauge__fill" style="width:${pct(t)}%"></div>
        <span class="score-gauge__label">${pct(t)}\u202f%</span>
      </div>
      <div class="score-breakdown">${items}</div>
      ${signals ? `<h3 class="section-subheading">Signale</h3>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>Signal</th><th>Beschreibung</th><th>Kategorie</th><th>Gewicht</th></tr></thead>
        <tbody>${signals}</tbody>
      </table></div>` : ''}
    </section>`;
  }

  function renderAuth(auth) {
    const cards = ['spf', 'dkim', 'dmarc'].map(proto => {
      const a = auth[proto] || {};
      return `<div class="auth-card">
        <div class="auth-card__proto">${proto.toUpperCase()}</div>
        <div class="auth-card__result">${authBadge(a.result)}</div>
        ${a.identity ? `<div class="auth-card__identity mono">${esc(a.identity)}</div>` : ''}
        ${a.detail ? `<div class="auth-card__detail muted">${esc(a.detail)}</div>` : ''}
      </div>`;
    }).join('');
    return `<section class="section">
      <h2 class="section-heading">Authentifizierung</h2>
      <div class="auth-grid">${cards}</div>
    </section>`;
  }

  function renderHops(hops) {
    if (!hops || !hops.length) return '';
    const rows = hops.map((h, i) => `<tr>
      <td class="muted">${i + 1}</td>
      <td class="mono">${esc(h.ip || '–')}</td>
      <td>${esc(h.hostname || '–')}</td>
      <td class="muted">${h.timestamp ? new Date(h.timestamp).toLocaleString('de-DE') : '–'}</td>
      <td class="muted small">${esc(h.raw || '')}</td>
    </tr>`).join('');
    return `<section class="section">
      <h2 class="section-heading">Mail-Route (Received-Header)</h2>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>#</th><th>IP</th><th>Hostname</th><th>Zeitstempel</th><th>Raw</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </section>`;
  }

  function renderAbuse(contacts) {
    if (!contacts || !contacts.length) return '';
    const rows = contacts.map(c => `<tr>
      <td class="mono">${esc(c.address)}</td>
      <td>${esc(c.source || '–')}</td>
      <td>${Math.round((c.confidence || 0) * 100)}\u202f%</td>
    </tr>`).join('');
    return `<section class="section">
      <h2 class="section-heading">Abuse-Kontakte</h2>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th>Adresse</th><th>Quelle</th><th>Konfidenz</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </section>`;
  }

  function renderDomain(dr) {
    if (!dr) return '';
    const rows = [
      ['Domain', dr.domain],
      ['Registrar', dr.registrar],
      ['Land', dr.country],
    ].filter(([, v]) => v).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');
    if (!rows) return '';
    return `<section class="section">
      <h2 class="section-heading">Domain-Information</h2>
      <table class="kv-table"><tbody>${rows}</tbody></table>
    </section>`;
  }

  function renderExportButtons(jobId) {
    const id = encodeURIComponent(jobId);
    return `<section class="section section--actions">
      <a href="/api/v1/reports/${id}/html" class="btn btn--secondary" download="report.html">
        HTML-Report herunterladen
      </a>
      <a href="/api/v1/reports/${id}/text" class="btn btn--secondary" download="report.txt">
        Text-Report herunterladen
      </a>
    </section>`;
  }

  function renderResult(jobId, result) {
    const root = document.getElementById('report-root');
    if (!root) return;
    const parts = [
      `<div class="page-header">
        <h1>Analyse-Report</h1>
        <span class="muted mono">${esc(jobId.slice(0, 8))}&hellip;</span>
       </div>`,
      renderMetadata(result.metadata || {}),
      result.spam_score ? renderScore(result.spam_score) : '',
      result.auth_summary ? renderAuth(result.auth_summary) : '',
      renderHops(result.received_hops),
      renderAbuse(result.abuse_contacts),
      renderDomain(result.domain_record),
      renderExportButtons(jobId),
    ];
    root.innerHTML = parts.join('');
  }

  function renderError(msg) {
    const root = document.getElementById('report-root');
    if (!root) return;
    root.innerHTML = `<div class="status-box status-box--error">
      <h2>Analyse fehlgeschlagen</h2>
      <p>${esc(msg)}</p>
    </div>`;
  }

  function renderPending(state) {
    const root = document.getElementById('report-root');
    if (!root) return;
    root.innerHTML = `<div class="status-box status-box--loading">
      <div class="spinner"></div>
      <p>${state === 'running' ? 'Analyse l\u00e4uft\u2026' : 'Analyse wird gestartet\u2026'}</p>
    </div>`;
  }

  async function poll(jobId) {
    try {
      const job = await SpammyClient.get(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
      if (job.state === 'done') {
        clearInterval(pollTimer);
        const result = await SpammyClient.get(`/api/v1/reports/${encodeURIComponent(jobId)}`);
        renderResult(jobId, result);
      } else if (job.state === 'error') {
        clearInterval(pollTimer);
        renderError(job.error || 'Unbekannter Fehler');
      } else {
        renderPending(job.state);
      }
    } catch (err) {
      clearInterval(pollTimer);
      renderError(err.message);
    }
  }

  function init() {
    const root = document.getElementById('report-root');
    if (!root) return;
    const jobId = root.dataset.jobId;
    if (!jobId) return;
    poll(jobId);
    pollTimer = setInterval(() => poll(jobId), POLL_INTERVAL);
  }

  return { init };
})();


/* -------------------------------------------------------------------------
 * Shared escape helper
 * ---------------------------------------------------------------------- */
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}


/* -------------------------------------------------------------------------
 * Bootstrap
 * ---------------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('history-tbody')) DashboardPage.init();
  if (document.getElementById('analyze-form'))   AnalyzePage.init();
  if (document.getElementById('report-root'))    ReportPage.init();
});
