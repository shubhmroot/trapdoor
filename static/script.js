const input = document.getElementById('messageInput');
const count = document.getElementById('charCount');
const button = document.getElementById('analyzeButton');
const errorBox = document.getElementById('errorMessage');
const results = document.getElementById('results');
const report = document.getElementById('reportContent');
const tinyfishToggle = document.getElementById('tinyfishEnabled');
const tinyfishStatus = document.getElementById('tinyfishStatus');
const examples = {
  safe: 'Hi Alex, the library has received your book return. No action is needed. You can check your account by visiting the library website you normally use.',
  suspicious: 'URGENT: Your PayPal account will be blocked today. Verify your account immediately at http://paypal-security-check.example.test/login to avoid suspension.'
};

input.addEventListener('input', () => { count.textContent = `${input.value.length.toLocaleString()} / 20,000`; errorBox.textContent = ''; });
document.querySelectorAll('.example-chip').forEach((chip) => chip.addEventListener('click', () => {
  input.value = examples[chip.dataset.example];
  input.dispatchEvent(new Event('input'));
  input.focus();
}));

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function render(data) {
  const tone = ['CRITICAL_RISK', 'HIGH_RISK'].includes(data.verdict) ? 'high' : data.verdict === 'MEDIUM_RISK' ? 'medium' : data.verdict === 'LOW_RISK' ? 'low' : 'clear';
  const findings = data.findings.length ? data.findings.map((item) => `
    <article class="finding"><div class="finding-icon ${escapeHtml(item.severity)}">${item.severity === 'high' ? '!' : '◇'}</div><div><b>${escapeHtml(item.title)}</b><p>${escapeHtml(item.evidence)}</p><div class="finding-source">${escapeHtml(item.source)} · ${escapeHtml(item.severity)} signal</div></div></article>`).join('') : '<div class="empty-findings">No obvious warning signs matched these rules. If you expected this link and the address is the site you meant to visit, it is likely okay to open.</div>';
  const recommendations = data.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const urls = data.urls.length ? `<div class="reputation-line">Destination${data.urls.length > 1 ? 's' : ''}: ${data.urls.map((item) => `<code>${escapeHtml(item.host || item.value)}</code>`).join(' · ')}</div>` : '';
  const emails = data.emails?.length ? `<div class="reputation-line">Email address${data.emails.length > 1 ? 'es' : ''}: ${data.emails.map((item) => `<code>${escapeHtml(item.value)}</code>`).join(' · ')}</div>` : '';
  const coverage = (data.coverage_notes || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const live = data.live_inspection || { status: 'not_requested', detail: 'Live page inspection was not requested.', pages: [] };
  const pageCards = (live.pages || []).map((page) => page.status === 'checked'
    ? `<article class="tinyfish-page"><b>${escapeHtml(page.title || 'Page title unavailable')}</b><div><span>Requested:</span> <code>${escapeHtml(page.url)}</code></div><div><span>Final page:</span> <code>${escapeHtml(page.final_url)}</code></div>${page.description ? `<p>${escapeHtml(page.description)}</p>` : ''}${page.text_excerpt ? `<details><summary>Fetched page text</summary><p class="tinyfish-excerpt">${escapeHtml(page.text_excerpt)}</p></details>` : ''}</article>`
    : `<article class="tinyfish-page unavailable"><b>Page not fetched</b><div><code>${escapeHtml(page.url)}</code></div><p>${escapeHtml(page.detail || 'TinyFish could not fetch this page.')}</p></article>`).join('');
  const tinyfishReport = `<section class="tinyfish-report"><div class="tinyfish-report-head"><h3>TinyFish live page inspection</h3><span class="tinyfish-badge ${escapeHtml(live.status)}">${escapeHtml(live.status.replaceAll('_', ' '))}</span></div><p>${escapeHtml(live.detail)}</p>${pageCards}</section>`;
  report.innerHTML = `<div class="decision-banner ${tone}"><span class="decision-label">${escapeHtml(data.action_label || 'Review this result')}</span><p>${escapeHtml(data.recommended_action || data.summary)}</p></div><p class="report-summary">${escapeHtml(data.summary)}</p>${tinyfishReport}<div class="report-grid">
    <section class="verdict-card ${tone}"><div class="verdict-top">LOCAL RULES + LIVE EVIDENCE</div><div class="verdict-label">${escapeHtml(data.label)}</div><div class="score-line"><span class="score-value">${data.risk_score}</span> / 100 matched-signal points</div><div class="meter"><span style="width:${data.risk_score}%"></span></div><div class="disclaimer-small">Points count matching rules; they are not a phishing probability.</div><div class="reputation-line">Reputation: not checked · ${escapeHtml(data.reputation.detail)}</div>${urls}${emails}</section>
    <section class="findings-card"><h3>Evidence found <span style="color:#a3ada7;font-weight:400">(${data.findings.length})</span></h3>${findings}</section>
  </div><section class="recommend-card"><h3>Safer next steps</h3><ul>${recommendations}</ul><details class="coverage-details"><summary>What this checker cannot confirm</summary><ul>${coverage}</ul></details></section>`;
  results.hidden = false;
  results.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' });
}

button.addEventListener('click', async () => {
  if (!input.value.trim()) { errorBox.textContent = 'Paste a URL, email, or text message to start your investigation.'; input.focus(); return; }
  button.disabled = true;
  button.innerHTML = `<span class="button-icon">◌</span> ${tinyfishToggle.checked ? 'Checking with TinyFish…' : 'Investigating…'}`;
  errorBox.textContent = '';
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: input.value, input_type: document.getElementById('inputType').value, tinyfish_enabled: tinyfishToggle.checked }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The investigation could not be completed.');
    render(data);
  } catch (error) {
    errorBox.textContent = error.message || 'Could not reach the local analysis service. Please try again.';
  } finally {
    button.disabled = false;
    button.innerHTML = '<span class="button-icon">↗</span> Analyze message';
  }
});

document.getElementById('resetButton').addEventListener('click', () => {
  input.value = '';
  input.dispatchEvent(new Event('input'));
  results.hidden = true;
  input.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
document.querySelector('.help-button').addEventListener('click', () => {
  const toast = document.getElementById('toast');
  toast.textContent = 'Local rules inspect pasted text. When enabled, TinyFish fetches extracted URLs without submitting forms.';
  toast.classList.add('show');
  window.setTimeout(() => toast.classList.remove('show'), 3000);
});

fetch('/api/health').then((response) => response.json()).then((health) => {
  tinyfishStatus.textContent = health.tinyfish_configured ? 'TinyFish key configured' : 'TinyFish key needed for live checks';
  tinyfishStatus.classList.toggle('configured', Boolean(health.tinyfish_configured));
}).catch(() => { tinyfishStatus.textContent = 'TinyFish setup status unavailable'; });

