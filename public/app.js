'use strict';

const toast = document.getElementById('toast');
let toastTimer;
function announce(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 4000);
}

// Fragment tokens stay out of HTTP URLs, referrers, server logs and the final address bar.
if (location.hash) {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token && document.getElementById('invitation-form')) {
    history.replaceState(null, '', location.pathname);
    document.getElementById('invitation').value = token;
    document.getElementById('invitation-form').requestSubmit();
  }
}

async function copyText(value, input) {
  try {
    await navigator.clipboard.writeText(value);
    announce('Copied. A little secret, ready to share.');
  } catch {
    if (input) {
      input.focus();
      input.select();
      announce('Select and copy this link using your keyboard or device menu.');
    } else announce('Clipboard access is unavailable. Use Save link bundle instead.');
  }
}

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.copy);
    copyText(input.value, input);
  });
});

const bundle = document.getElementById('link-bundle');
if (bundle) {
  const links = [...bundle.querySelectorAll('.participant-link')].map(row => ({
    participant: row.dataset.participant,
    url: row.querySelector('input').value,
  }));
  document.getElementById('copy-all').addEventListener('click', () => {
    copyText(links.map(link => `${link.participant}\n${link.url}`).join('\n\n'));
  });
  document.getElementById('download-links').addEventListener('click', () => {
    const contents = { version: 1, drawId: bundle.dataset.drawId, expiresAt: bundle.dataset.expiresAt, links };
    const blob = new Blob([JSON.stringify(contents, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `secret-santa-links-${bundle.dataset.drawId.slice(0, 8)}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    announce('Link bundle saved. Keep it somewhere private.');
  });
}

const participants = document.getElementById('participants');
if (participants) {
  const updateCount = () => {
    const count = participants.value.split(/[,\r\n]+/u).filter(name => name.trim()).length;
    document.getElementById('participant-count').textContent = `${count} ${count === 1 ? 'person' : 'people'} on the list`;
  };
  participants.addEventListener('input', updateCount);
  updateCount();
}

document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', () => {
    const button = form.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    }
  });
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('button[aria-busy]').forEach(button => {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  });
});
