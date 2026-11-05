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

const wishesInput = document.getElementById('wishes');
if (wishesInput) {
  const updateWishCount = () => {
    document.getElementById('wish-count').textContent = `${wishesInput.value.length} / ${wishesInput.maxLength}`;
  };
  wishesInput.addEventListener('input', updateWishCount);
  updateWishCount();
}

const recipientWishes = document.getElementById('recipient-wishes');
if (recipientWishes) {
  const text = document.getElementById('recipient-wishes-text');
  const empty = document.getElementById('recipient-wishes-empty');
  const status = document.getElementById('wishlist-sync-status');
  document.getElementById('wishlist-live-note').hidden = false;
  let refreshing = false;
  async function refreshWishes() {
    if (document.visibilityState === 'hidden' || refreshing) return;
    refreshing = true;
    try {
      const response = await fetch('/wishes/recipient', {
        credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      if (response.status === 401) {
        status.textContent = 'Abre tu invitación de nuevo para seguir viendo los deseos.';
        return;
      }
      if (!response.ok) throw new Error('Wish refresh failed.');
      const data = await response.json();
      if (typeof data.text !== 'string') throw new Error('Invalid wish response.');
      // Gift ideas are always plain text, including anything resembling HTML.
      if (text.textContent !== data.text) text.textContent = data.text;
      text.hidden = !data.text;
      empty.hidden = Boolean(data.text);
      status.textContent = 'Los deseos se actualizan automáticamente mientras estás aquí.';
    } catch {
      status.textContent = 'No pudimos actualizar los deseos. Volveremos a intentarlo en unos momentos.';
    } finally {
      refreshing = false;
    }
  }
  setInterval(refreshWishes, 30000);
  document.addEventListener('visibilitychange', refreshWishes);
  window.addEventListener('focus', refreshWishes);
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
