// dashboard.js — NSMS Security Dashboard Client
let socket = null;
let currentView = 'overview';

document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  switchView('overview');
  loadAll();
  setInterval(loadAll, 10000);
});

function initSocket() {
  socket = io();
  socket.on('connect', () => {
    document.getElementById('connectionStatus').classList.add('connected');
    document.getElementById('connectionText').innerText = 'Connected';
  });
  socket.on('disconnect', () => {
    document.getElementById('connectionStatus').classList.remove('connected');
    document.getElementById('connectionText').innerText = 'Disconnected';
  });
  socket.on('security:alert', (data) => {
    addLiveFeedItem(data);
    showToast(data);
    document.getElementById('liveIndicator').style.display = 'inline-flex';
    setTimeout(() => { document.getElementById('liveIndicator').style.display = 'none'; }, 5000);
    loadAll();
  });
}

function switchView(view) {
  currentView = view;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.getAttribute('data-view') === view);
  });
  const titles = { overview: 'Overview', alerts: 'Live Alerts', firewall: 'Firewall Rules', allowlist: 'IP Allowlist', assets: 'Network Assets' };
  const subs = { overview: 'Real-time security monitoring and threat mitigation', alerts: 'All detected security events and threat alerts', firewall: 'Active and expired IP blocking rules', allowlist: 'Protected IPs that cannot be blocked', assets: 'Discovered devices on the network' };
  document.getElementById('pageTitle').innerText = titles[view] || view;
  document.getElementById('pageSubtitle').innerText = subs[view] || '';
}

function loadAll() {
  loadStats();
  loadAlerts();
  loadFirewallRules();
  loadAllowlist();
  loadAssets();
}

async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const d = await res.json();
    document.getElementById('statTotalAlerts').innerText = d.totalAlerts || 0;
    document.getElementById('statActiveRules').innerText = d.activeRules || 0;
    document.getElementById('statBlockedIps').innerText = d.blockedIps || 0;
    document.getElementById('statAllowlisted').innerText = d.allowlistedIps || 0;
    document.getElementById('statAlerts24h').innerText = d.alertsLast24h || 0;
  } catch (e) { console.error('Stats error:', e); }
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const d = await res.json();
    const alerts = d.alerts || [];

    // Recent (overview)
    document.getElementById('recentAlertsBody').innerHTML = alerts.length === 0
      ? '<tr><td colspan="3" class="empty-state">No alerts yet</td></tr>'
      : alerts.slice(0, 10).map(a => `<tr>
          <td class="mono">${fmtTime(a.created_at)}</td>
          <td><span class="severity-badge severity-${a.severity}">${a.severity}</span></td>
          <td>${esc(a.message)}</td>
        </tr>`).join('');

    // All alerts view
    document.getElementById('allAlertsBody').innerHTML = alerts.length === 0
      ? '<tr><td colspan="4" class="empty-state">No alerts recorded</td></tr>'
      : alerts.map(a => `<tr>
          <td class="mono" style="font-size:10px">${a.id ? a.id.substring(0,8) : ''}</td>
          <td class="mono">${fmtTime(a.created_at)}</td>
          <td><span class="severity-badge severity-${a.severity}">${a.severity}</span></td>
          <td>${esc(a.message)}</td>
        </tr>`).join('');

    // Pre-populate Live Threat Feed on startup if empty
    const feed = document.getElementById('liveFeed');
    if (feed && feed.querySelector('.feed-empty') && alerts.length > 0) {
      feed.innerHTML = '';
      alerts.slice(0, 15).forEach(a => {
        const item = document.createElement('div');
        item.className = 'feed-item';
        const isBlock = a.message.includes('BLOCK') || a.message.includes('BLOCKED');
        const isAllow = a.message.includes('ALLOW');
        const color = isBlock ? '#F06B75' : isAllow ? '#35C995' : '#648CFF';
        const status = isBlock ? 'BLOCKED' : isAllow ? 'ALLOWED' : 'INFO';
        item.innerHTML = `
          <span class="feed-time">${fmtTime(a.created_at)}</span>
          <span class="severity-badge severity-${a.severity || 'low'}">${a.severity || 'info'}</span>
          <span class="feed-text">
            <strong style="color:${color}">${status}</strong> — ${esc(a.message)}
          </span>`;
        feed.appendChild(item);
      });
    }

    const badge = document.getElementById('alertCountBadge');
    if (alerts.length > 0) { badge.style.display = 'inline'; badge.innerText = alerts.length; }
  } catch (e) { console.error('Alerts error:', e); }
}

async function loadFirewallRules() {
  try {
    const res = await fetch('/api/firewall-rules');
    const d = await res.json();
    const rules = d.rules || [];
    const renderRows = (rows) => rows.length === 0
      ? '<tr><td colspan="7" class="empty-state">No firewall rules</td></tr>'
      : rows.map(r => {
          const expired = new Date(r.expires_at) < new Date();
          const active = r.active && !expired;
          return `<tr>
            <td class="mono" style="font-size:10px">${r.id ? r.id.substring(0,8) + '...' : ''}</td>
            <td class="mono">${r.source_ip}</td>
            <td class="mono">${r.target_ip}</td>
            <td>${esc(r.rule)}</td>
            <td class="mono">${fmtTime(r.created_at)}</td>
            <td class="mono">${fmtTime(r.expires_at)}</td>
            <td>
              <span class="${active ? 'status-active' : 'status-inactive'}">${active ? '● ACTIVE' : '○ Expired'}</span>
              ${active ? `<button class="btn btn-danger" style="padding:2px 6px; font-size:10px; margin-left:6px;" onclick="unblockRule('${r.id}')">Unblock</button>` : ''}
            </td>
          </tr>`;
        }).join('');

    document.getElementById('overviewRulesBody').innerHTML = renderRows(rules.slice(0, 5));
    document.getElementById('allRulesBody').innerHTML = renderRows(rules);
  } catch (e) { console.error('Rules error:', e); }
}

async function unblockRule(id) {
  if (!confirm('Unblock this firewall rule immediately?')) return;
  try {
    await fetch('/api/firewall-rules/' + id, { method: 'DELETE' });
    loadFirewallRules();
    loadStats();
  } catch (e) { alert('Failed to unblock: ' + e.message); }
}

async function loadAllowlist() {
  try {
    const res = await fetch('/api/allowlist');
    const d = await res.json();
    const entries = d.entries || [];
    document.getElementById('allowlistBody').innerHTML = entries.length === 0
      ? '<tr><td colspan="4" class="empty-state">No allowlisted IPs</td></tr>'
      : entries.map(e => `<tr>
          <td class="mono">${esc(e.ip)}</td>
          <td>${esc(e.description || '-')}</td>
          <td class="mono">${fmtTime(e.created_at)}</td>
          <td><button class="btn btn-danger" onclick="deleteAllowlistEntry('${e.id}')">Remove</button></td>
        </tr>`).join('');
  } catch (e) { console.error('Allowlist error:', e); }
}

async function addAllowlistEntry() {
  const ip = document.getElementById('allowlistIpInput').value.trim();
  const desc = document.getElementById('allowlistDescInput').value.trim();
  if (!ip) return alert('IP address is required');
  try {
    await fetch('/api/allowlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, description: desc })
    });
    document.getElementById('allowlistIpInput').value = '';
    document.getElementById('allowlistDescInput').value = '';
    loadAllowlist();
    loadStats();
  } catch (e) { alert('Failed: ' + e.message); }
}

async function deleteAllowlistEntry(id) {
  if (!confirm('Remove this IP from the allowlist?')) return;
  try {
    await fetch('/api/allowlist/' + id, { method: 'DELETE' });
    loadAllowlist();
    loadStats();
  } catch (e) { alert('Failed: ' + e.message); }
}

async function loadAssets() {
  try {
    const res = await fetch('/api/assets');
    const d = await res.json();
    const assets = d.assets || [];
    document.getElementById('assetsBody').innerHTML = assets.length === 0
      ? '<tr><td colspan="4" class="empty-state">No assets discovered yet</td></tr>'
      : assets.map(a => `<tr>
          <td class="mono">${esc(a.ip)}</td>
          <td class="mono">${esc(a.mac || '-')}</td>
          <td>${esc(a.os || '-')}</td>
          <td class="mono">${fmtTime(a.discovered_at)}</td>
        </tr>`).join('');
  } catch (e) { console.error('Assets error:', e); }
}

function addLiveFeedItem(data) {
  const feed = document.getElementById('liveFeed');
  if (!feed) return;
  const empty = feed.querySelector('.feed-empty');
  if (empty) empty.remove();

  const statusColors = { blocked: '#F06B75', allowed: '#35C995', ignored: '#F0B45A' };
  const item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML = `
    <span class="feed-time">${new Date().toLocaleTimeString()}</span>
    <span class="severity-badge severity-${data.severity || 'low'}">${data.severity || 'info'}</span>
    <span class="feed-text">
      <strong style="color:${statusColors[data.status] || '#648CFF'}">${(data.status || '').toUpperCase()}</strong>
      — ${data.threatType || 'traffic'} from <span class="mono">${esc(data.sourceIp)}</span>
      ${data.detail ? '<span style="color:var(--text-secondary); margin-left:6px; font-size:11px;">(' + esc(data.detail) + ')</span>' : ''}
      ${data.ruleId ? ' | Rule: <span class="mono">' + data.ruleId.substring(0,8) + '</span>' : ''}
    </span>`;
  feed.insertBefore(item, feed.firstChild);
  // Keep max 50
  while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function showToast(data) {
  if (data.severity === 'info' || data.threatType === 'normal_traffic') return;
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast ' + (data.severity || 'low');
  toast.innerHTML = `🚨 <strong>${(data.status || '').toUpperCase()}</strong> — ${data.threatType} from ${data.sourceIp}`;
  container.appendChild(toast);
  setTimeout(() => { toast.remove(); }, 5000);
}

function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleString('en-IN', { hour12: false });
}

function esc(text) {
  if (!text) return '';
  return String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
