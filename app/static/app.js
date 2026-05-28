'use strict';

// ── State ─────────────────────────────────────────────────────────────────────

let certData = [];
const selectedIds = new Set();

// ── DOM refs ──────────────────────────────────────────────────────────────────

const configForm      = document.getElementById('config-form');
const connectBtn      = document.getElementById('connect-btn');
const scanBtn         = document.getElementById('scan-btn');
const scanSpinner     = document.getElementById('scan-spinner');
const scanStatus      = document.getElementById('scan-status');
const resultsSection  = document.getElementById('results-section');
const noSha1Alert     = document.getElementById('no-sha1-alert');
const noSha1Msg       = document.getElementById('no-sha1-msg');
const sha1TableSection = document.getElementById('sha1-table-section');
const sha1Count       = document.getElementById('sha1-count');
const certsTbody      = document.getElementById('certs-tbody');
const selectAllCb     = document.getElementById('select-all-cb');
const selectionLabel  = document.getElementById('selection-label');
const selectedCount   = document.getElementById('selected-count');
const deleteBtn       = document.getElementById('delete-btn');
const connectionBadge = document.getElementById('connection-badge');
const badgeServer     = document.getElementById('badge-server');
const toastEl         = document.getElementById('toast');
const toastBody       = document.getElementById('toast-body');
const collapseIcon    = document.getElementById('collapse-icon');

const bsToast       = new bootstrap.Toast(toastEl, { delay: 4000 });
const deleteModal   = new bootstrap.Modal(document.getElementById('delete-modal'));
const detailModal   = new bootstrap.Modal(document.getElementById('detail-modal'));
const confirmBtn    = document.getElementById('confirm-delete-btn');

// ── Collapse chevron sync ─────────────────────────────────────────────────────

document.getElementById('connection-collapse').addEventListener('hide.bs.collapse', () => {
  collapseIcon.className = 'bi bi-chevron-up';
});
document.getElementById('connection-collapse').addEventListener('show.bs.collapse', () => {
  collapseIcon.className = 'bi bi-chevron-down';
});

// ── Auth type toggle ──────────────────────────────────────────────────────────

document.querySelectorAll('input[name="auth-type"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const token = document.querySelector('input[name="auth-type"]:checked').value === 'token';
    document.getElementById('token-fields').classList.toggle('d-none', !token);
    document.getElementById('creds-fields').classList.toggle('d-none', token);
  });
});

// ── Toast helper ──────────────────────────────────────────────────────────────

function showToast(type, message) {
  toastEl.classList.remove('text-bg-success', 'text-bg-danger', 'text-bg-warning');
  toastEl.classList.add(type === 'success' ? 'text-bg-success' : 'text-bg-danger');
  toastBody.textContent = message;
  bsToast.show();
}

// ── Init: pre-populate from server config ─────────────────────────────────────

async function init() {
  try {
    const res  = await fetch('/api/config');
    const data = await res.json();

    if (data.server)     document.getElementById('server').value = data.server;
    if (!data.verify_ssl) document.getElementById('verify-ssl').checked = false;

    if (data.auth_type === 'client_credentials') {
      document.querySelector('input[value="credentials"]').checked = true;
      document.getElementById('token-fields').classList.add('d-none');
      document.getElementById('creds-fields').classList.remove('d-none');
      if (data.client_id)     document.getElementById('client-id').value     = data.client_id;
      if (data.client_secret) document.getElementById('client-secret').value = data.client_secret;
    } else {
      if (data.api_token) document.getElementById('api-token').value = data.api_token;
    }

    if (data.configured) {
      setConnected(data.server);
    }
  } catch (_) { /* ignore — server may still be starting */ }
}

// ── Mark UI as connected ──────────────────────────────────────────────────────

function setConnected(serverUrl) {
  scanBtn.disabled = false;
  try {
    const url = new URL(serverUrl.startsWith('http') ? serverUrl : `https://${serverUrl}`);
    badgeServer.textContent = url.hostname;
  } catch (_) {
    badgeServer.textContent = serverUrl;
  }
  connectionBadge.classList.remove('d-none');
  bootstrap.Collapse.getOrCreateInstance(
    document.getElementById('connection-collapse')
  ).hide();
}

// ── Connection form submit ────────────────────────────────────────────────────

configForm.addEventListener('submit', async e => {
  e.preventDefault();
  connectBtn.disabled = true;
  connectBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Connecting…';

  const authType = document.querySelector('input[name="auth-type"]:checked').value;
  const body     = {
    server:     document.getElementById('server').value.trim(),
    verify_ssl: document.getElementById('verify-ssl').checked,
    api_token:    authType === 'token'
      ? (document.getElementById('api-token').value.trim() || null)
      : null,
    client_id:    authType === 'credentials'
      ? (document.getElementById('client-id').value.trim() || null)
      : null,
    client_secret: authType === 'credentials'
      ? (document.getElementById('client-secret').value.trim() || null)
      : null,
  };

  try {
    const res  = await fetch('/api/config', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Connection failed');
    setConnected(data.server);
    showToast('success', `Connected to ${data.server}`);
  } catch (err) {
    showToast('error', err.message);
  } finally {
    connectBtn.disabled = false;
    connectBtn.innerHTML = '<i class="bi bi-plug me-1"></i>Connect';
  }
});

// ── Scan ──────────────────────────────────────────────────────────────────────

scanBtn.addEventListener('click', async () => {
  scanBtn.disabled    = true;
  scanSpinner.style.display = 'inline-block';
  scanStatus.textContent    = 'Scanning trust list…';
  certData = [];
  selectedIds.clear();
  resultsSection.classList.add('d-none');

  try {
    const res  = await fetch('/api/scan');
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed');

    scanStatus.textContent = `Checked ${data.total_certs} certificate(s) — found ${data.sha1_count} SHA-1`;
    certData = data.certs;
    renderResults(data);
  } catch (err) {
    scanStatus.textContent = '';
    showToast('error', `Scan failed: ${err.message}`);
  } finally {
    scanBtn.disabled = false;
    scanSpinner.style.display = 'none';
  }
});

// ── Render results ────────────────────────────────────────────────────────────

function renderResults(data) {
  resultsSection.classList.remove('d-none');

  if (data.sha1_count === 0) {
    noSha1Msg.textContent = `No SHA-1 certificates found. All ${data.total_certs} trust list entries use stronger algorithms.`;
    noSha1Alert.classList.remove('d-none');
    sha1TableSection.classList.add('d-none');
    return;
  }

  noSha1Alert.classList.add('d-none');
  sha1TableSection.classList.remove('d-none');
  sha1Count.textContent = data.sha1_count;

  certsTbody.innerHTML = '';
  data.certs.forEach(cert => {
    const tr = document.createElement('tr');
    tr.className   = 'cert-row';
    tr.dataset.id  = cert.id;

    const subject = esc(cert.subject || cert.subject_dn || cert.common_name || 'Unknown Subject');
    const issuer  = esc(cert.issuer  || cert.issuer_dn  || 'Unknown Issuer');
    const expiry  = formatExpiry(cert.not_after || cert.valid_until || cert.expiry_date);
    const usage   = esc(cert.cert_usage || cert.usage || '—');
    const badge   = detectionBadge(cert._detected_by);

    tr.innerHTML = `
      <td class="ps-3">
        <input type="checkbox" class="form-check-input cert-checkbox" data-id="${cert.id}">
      </td>
      <td>
        <span class="d-inline-block text-truncate" style="max-width:220px" title="${subject}">${subject}</span>
      </td>
      <td>
        <span class="d-inline-block text-truncate text-muted small" style="max-width:200px" title="${issuer}">${issuer}</span>
      </td>
      <td>${expiry}</td>
      <td><span class="small">${usage}</span></td>
      <td>${badge}</td>
      <td class="pe-3">
        <button class="btn btn-outline-secondary btn-sm details-btn py-0 px-2" data-id="${cert.id}">
          <i class="bi bi-info-circle me-1"></i>Details
        </button>
      </td>
    `;
    certsTbody.appendChild(tr);
  });

  // Checkbox change
  certsTbody.querySelectorAll('.cert-checkbox').forEach(cb => {
    cb.addEventListener('change', syncSelection);
  });

  // Row click toggles checkbox
  certsTbody.querySelectorAll('.cert-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.classList.contains('details-btn') || e.target.closest('.details-btn')) return;
      const cb  = row.querySelector('.cert-checkbox');
      cb.checked = !cb.checked;
      syncSelection();
    });
  });

  // Details buttons
  certsTbody.querySelectorAll('.details-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      showDetails(btn.dataset.id);
    });
  });

  syncSelection();
}

// ── Selection management ──────────────────────────────────────────────────────

function syncSelection() {
  selectedIds.clear();
  const all = certsTbody.querySelectorAll('.cert-checkbox');
  all.forEach(cb => {
    cb.closest('tr').classList.toggle('selected', cb.checked);
    if (cb.checked) selectedIds.add(cb.dataset.id);
  });

  const n = selectedIds.size;
  selectedCount.textContent  = n;
  deleteBtn.disabled         = n === 0;
  selectAllCb.checked        = n === all.length && all.length > 0;
  selectAllCb.indeterminate  = n > 0 && n < all.length;
  selectionLabel.textContent = n > 0 ? `${n} of ${all.length} selected` : '';
}

selectAllCb.addEventListener('change', () => {
  certsTbody.querySelectorAll('.cert-checkbox').forEach(cb => {
    cb.checked = selectAllCb.checked;
  });
  syncSelection();
});

// ── Delete flow ───────────────────────────────────────────────────────────────

deleteBtn.addEventListener('click', () => {
  const list = document.getElementById('delete-list');
  list.innerHTML = '';

  selectedIds.forEach(id => {
    const cert    = certData.find(c => String(c.id) === String(id));
    const subject = cert
      ? esc(cert.subject || cert.subject_dn || cert.common_name || `ID ${id}`)
      : `ID ${id}`;
    const li = document.createElement('li');
    li.className = 'list-group-item py-2 small';
    li.innerHTML = `<i class="bi bi-file-earmark-x text-danger me-2"></i>${subject}
                    <span class="text-muted ms-1">(ID: ${id})</span>`;
    list.appendChild(li);
  });

  deleteModal.show();
});

confirmBtn.addEventListener('click', async () => {
  deleteModal.hide();
  const ids = Array.from(selectedIds);
  confirmBtn.disabled = true;

  try {
    const res  = await fetch('/api/certs/delete', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ids }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Delete failed');

    data.deleted.forEach(id => {
      certsTbody.querySelector(`tr[data-id="${id}"]`)?.remove();
      certData = certData.filter(c => String(c.id) !== String(id));
    });

    selectedIds.clear();
    sha1Count.textContent = certData.length;
    syncSelection();

    if (certData.length === 0) {
      sha1TableSection.classList.add('d-none');
      noSha1Msg.textContent = 'All SHA-1 certificates have been removed.';
      noSha1Alert.classList.remove('d-none');
    }

    const ok   = data.deleted.length;
    const fail = data.failed.length;
    if (fail === 0) {
      showToast('success', `Successfully deleted ${ok} certificate(s).`);
    } else {
      showToast('error', `Deleted ${ok}, failed ${fail}. See browser console.`);
      console.error('Failed deletions:', data.failed);
    }
  } catch (err) {
    showToast('error', `Delete failed: ${err.message}`);
  } finally {
    confirmBtn.disabled = false;
  }
});

// ── Certificate detail modal ──────────────────────────────────────────────────

function showDetails(id) {
  const cert = certData.find(c => String(c.id) === String(id));
  if (!cert) return;

  const SKIP = new Set(['cert_file', 'pem', 'certificate']);
  const rows = Object.entries(cert)
    .filter(([k]) => !SKIP.has(k))
    .map(([k, v]) => {
      const display = k === '_detected_by'
        ? detectionBadge(v)
        : `<span class="font-monospace small">${esc(String(v ?? '—'))}</span>`;
      return `<tr>
        <td class="text-secondary">${esc(k)}</td>
        <td style="word-break:break-all">${display}</td>
      </tr>`;
    })
    .join('');

  document.getElementById('detail-body').innerHTML = `
    <table class="table table-sm detail-table mb-0">${rows}</table>`;
  detailModal.show();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str)));
  return d.innerHTML;
}

function formatExpiry(raw) {
  if (!raw || raw === '—') return '<span class="text-muted">—</span>';
  try {
    const d    = new Date(raw);
    const now  = Date.now();
    const diff = d.getTime() - now;
    const label = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    if (diff < 0)          return `<span class="expiry-expired">${label}</span>`;
    if (diff < 30 * 864e5) return `<span class="expiry-soon">${label}</span>`;
    return `<span class="small">${label}</span>`;
  } catch (_) {
    return `<span class="small">${esc(raw)}</span>`;
  }
}

function detectionBadge(method) {
  if (!method) return '<span class="badge badge-unknown">unknown</span>';
  const cls = method.includes('meta') ? 'badge-meta' : method.includes('pars') ? 'badge-parse' : 'badge-unknown';
  return `<span class="badge ${cls}">${esc(method)}</span>`;
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

init();
