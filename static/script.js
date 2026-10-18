const input = document.getElementById('messageInput');
const count = document.getElementById('charCount');
const button = document.getElementById('analyzeButton');
const errorBox = document.getElementById('errorMessage');
const results = document.getElementById('results');
const report = document.getElementById('reportContent');
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
  report.innerHTML = `<div class="decision-banner ${tone}"><span class="decision-label">${escapeHtml(data.action_label || 'Review this result')}</span><p>${escapeHtml(data.recommended_action || data.summary)}</p></div><p class="report-summary">${escapeHtml(data.summary)}</p><div class="report-grid">
    <section class="verdict-card ${tone}"><div class="verdict-top">RULE CHECK RESULT</div><div class="verdict-label">${escapeHtml(data.label)}</div><div class="score-line"><span class="score-value">${data.risk_score}</span> / 100 matched-signal points</div><div class="meter"><span style="width:${data.risk_score}%"></span></div><div class="disclaimer-small">Points count matching rules; they are not a phishing probability.</div><div class="reputation-line">Reputation: not checked · ${escapeHtml(data.reputation.detail)}</div>${urls}${emails}</section>
    <section class="findings-card"><h3>Evidence found <span style="color:#a3ada7;font-weight:400">(${data.findings.length})</span></h3>${findings}</section>
  </div><section class="recommend-card"><h3>Safer next steps</h3><ul>${recommendations}</ul><details class="coverage-details"><summary>What this checker cannot confirm</summary><ul>${coverage}</ul></details></section>`;
  results.hidden = false;
  results.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' });
}

button.addEventListener('click', async () => {
  if (!input.value.trim()) { errorBox.textContent = 'Paste a URL, email, or text message to start your investigation.'; input.focus(); return; }
  button.disabled = true;
  button.innerHTML = '<span class="button-icon">◌</span> Investigating…';
  errorBox.textContent = '';
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: input.value, input_type: document.getElementById('inputType').value }) });
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
  toast.textContent = 'Trapdoor checks for explainable patterns. No submitted links are opened.';
  toast.classList.add('show');
  window.setTimeout(() => toast.classList.remove('show'), 3000);
});

