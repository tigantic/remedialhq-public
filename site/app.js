const launchDate = Date.UTC(2026, 10, 19);
const campaignStartDate = Date.UTC(2026, 7, 29);
const dayMilliseconds = 86400000;

function localCalendarDateUtc(date) {
  return Date.UTC(date.getFullYear(), date.getMonth(), date.getDate());
}

function updateClock() {
  const today = localCalendarDateUtc(new Date());
  const remaining = Math.max(0, launchDate - today);
  const days = Math.ceil(remaining / dayMilliseconds);
  const dateReached = today >= launchDate;
  document.querySelector('#days').textContent = String(days);
  const total = launchDate - campaignStartDate;
  const elapsed = Math.min(total, Math.max(0, today - campaignStartDate));
  document.querySelector('#progress').style.width = `${(elapsed / total) * 100}%`;
  document.querySelector('#clock').textContent = dateReached ? 'DATE REACHED' : 'DATE TRACKER';
  document.querySelector('#countdown-label').textContent = dateReached
    ? 'ROCKSTAR-SCHEDULED DATE REACHED'
    : 'DAYS UNTIL NOV 19, 2026';
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, char => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;'
  })[char]);
}

function latestRetrievedDate(claim) {
  const dates = (claim.source_ids || [])
    .map(sourceId => sources.get(sourceId)?.retrieved_at)
    .filter(Boolean)
    .sort();
  if (!dates.length) return 'check date unavailable';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC'
  }).format(new Date(dates[dates.length - 1]));
}

function claimCard(claim) {
  const validStates = new Set(['CONFIRMED', 'OBSERVED', 'REPORTED', 'INFERRED', 'PENDING', 'REJECTED']);
  const state = validStates.has(claim.state) ? claim.state : 'PENDING';
  const claimId = escapeHtml(claim.claim_id);
  const wording = escapeHtml(claim.public_wording);
  const sourceCount = claim.source_ids?.length || 0;
  return `<article class="claim-card" data-state="${state}" data-claim-id="${claimId}" tabindex="0" role="button" aria-label="Open ${claimId}: ${wording}">
    <div class="claim-card-topline"><span class="claim-state">${state}</span><span class="claim-open">OPEN ↗</span></div>
    <h3>${wording}</h3>
    <div class="claim-meta"><span>${claimId}</span><span>${sourceCount} source${sourceCount === 1 ? '' : 's'} · checked ${escapeHtml(latestRetrievedDate(claim))}</span></div>
  </article>`;
}

let claims = [];
let sources = new Map();
let activeFilter = 'ALL';

async function loadLedger() {
  try {
    const [claimResponse, sourceResponse] = await Promise.all([
      fetch('data/claims.json'),
      fetch('data/sources.json')
    ]);
    if (!claimResponse.ok) throw new Error(`claims HTTP ${claimResponse.status}`);
    if (!sourceResponse.ok) throw new Error(`sources HTTP ${sourceResponse.status}`);
    claims = await claimResponse.json();
    const sourceRecords = await sourceResponse.json();
    sources = new Map(sourceRecords.map(source => [source.source_id, source]));
    document.querySelector('#claims-total').textContent = String(claims.length);
    const boundSourceIds = new Set(
      claims.flatMap(claim => claim.source_ids || []).filter(sourceId => sources.has(sourceId))
    );
    document.querySelector('#sources-total').textContent = String(boundSourceIds.size);
    renderClaims(activeFilter);
  } catch {
    document.querySelector('#claim-grid').innerHTML = '<article class="claim-card" data-state="PENDING"><span class="claim-state">TEMPORARILY UNAVAILABLE</span><h3>The public claim ledger could not be loaded. The latest source-linked brief remains available.</h3><div class="claim-meta"><span>LEDGER</span><span><a href="/gta-vi-official-state">READ THE BRIEF ↗</a></span></div></article>';
  }
}

function renderClaims(filter) {
  activeFilter = filter;
  const visible = filter === 'ALL' ? claims : claims.filter(claim => claim.state === filter);
  document.querySelector('#claim-grid').innerHTML = visible.map(claimCard).join('');
  document.querySelector('#empty-state').hidden = visible.length > 0;
  document.querySelector('#ledger-status').textContent = `${visible.length} claim records shown.`;
}

function safeHttpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

function sourceRow(sourceId) {
  const source = sources.get(sourceId);
  if (!source) {
    return `<div class="source-row"><span>${escapeHtml(sourceId)}</span><small>Source record unavailable</small></div>`;
  }
  const body = `<span>${escapeHtml(source.publisher)}</span><strong>${escapeHtml(source.title)}</strong><small>${escapeHtml(source.source_tier)} · retrieved ${escapeHtml(source.retrieved_at.slice(0, 10))}</small>`;
  const href = safeHttpsUrl(source.href);
  if (href) {
    return `<a class="source-row" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${body}<b>↗</b></a>`;
  }
  return `<div class="source-row">${body}<b>DATA</b></div>`;
}

function openClaim(claimId) {
  const claim = claims.find(item => item.claim_id === claimId);
  if (!claim) return;
  const dialog = document.querySelector('#claim-dialog');
  dialog.dataset.state = claim.state;
  document.querySelector('#claim-dialog-state').textContent = claim.state;
  document.querySelector('#claim-dialog-id').textContent = claim.claim_id;
  document.querySelector('#claim-dialog-title').textContent = claim.public_wording;
  document.querySelector('#claim-dialog-proposition').textContent = claim.proposition;
  document.querySelector('#claim-dialog-checked').textContent = latestRetrievedDate(claim);
  document.querySelector('#claim-dialog-source-count').textContent = String(claim.source_ids.length);
  document.querySelector('#claim-dialog-sources').innerHTML = claim.source_ids.map(sourceRow).join('');
  dialog.showModal();
}

document.querySelectorAll('[data-filter]').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('[data-filter]').forEach(item => {
      item.classList.remove('active');
      item.setAttribute('aria-pressed', 'false');
    });
    button.classList.add('active');
    button.setAttribute('aria-pressed', 'true');
    renderClaims(button.dataset.filter);
  });
});

document.querySelector('#claim-grid').addEventListener('click', event => {
  const card = event.target.closest('[data-claim-id]');
  if (card) openClaim(card.dataset.claimId);
});
document.querySelector('#claim-grid').addEventListener('keydown', event => {
  if (!['Enter', ' '].includes(event.key)) return;
  const card = event.target.closest('[data-claim-id]');
  if (!card) return;
  event.preventDefault();
  openClaim(card.dataset.claimId);
});

document.querySelectorAll('[data-close-target]').forEach(button => {
  button.addEventListener('click', () => document.querySelector(`#${button.dataset.closeTarget}`).close());
});
document.querySelectorAll('dialog').forEach(dialog => {
  dialog.addEventListener('click', event => {
    if (event.target === dialog) dialog.close();
  });
});

document.querySelector('#briefing-form').addEventListener('submit', event => {
  event.preventDefault();
  const address = document.querySelector('#email').value.trim();
  const subject = encodeURIComponent('Join the ReMediaLHQ signal brief');
  const body = encodeURIComponent(`Please add ${address} to the ReMediaLHQ signal brief interest list.\n\nI understand this email opens in my mail app and automated newsletter delivery is not active yet.`);
  window.location.href = `mailto:support@remedialhq.com?subject=${subject}&body=${body}`;
});

updateClock();
setInterval(updateClock, 60000);
loadLedger();
