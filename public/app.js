'use strict';

const pageLoader = document.getElementById('page-loader');
if (pageLoader) {
  const video = document.getElementById('page-loader-video');
  const content = document.querySelector('.site-shell');
  document.body.classList.add('page-loading');
  if (content) content.inert = true;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) video.pause();
  else video.play().catch(() => {}); // Autoplay restrictions must never block the page.
  const finishLoading = () => {
    pageLoader.hidden = true;
    video.pause();
    document.body.classList.remove('page-loading');
    if (content) content.inert = false;
  };
  // Always reveal the page after two seconds, even if the video fails to load.
  setTimeout(finishLoading, 2000);
  window.addEventListener('pageshow', event => {
    if (event.persisted) finishLoading();
  });
}

const toast = document.getElementById('toast');
let toastTimer;
function announce(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 4000);
}

// Fragment tokens stay out of HTTP URLs, referrers, server logs and the final address bar.
function openInvitationFromFragment() {
  if (!location.hash) return;
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token && document.getElementById('invitation-form')) {
    history.replaceState(null, '', location.pathname);
    document.getElementById('invitation').value = token;
    document.getElementById('invitation-form').requestSubmit();
  }
}
openInvitationFromFragment();
window.addEventListener('hashchange', openInvitationFromFragment);

async function copyText(value, input) {
  try {
    await navigator.clipboard.writeText(value);
    announce('Copied. A little secret, ready to share.');
  } catch {
    if (input) {
      input.focus();
      input.select();
      announce('Select and copy this link using your keyboard or device menu.');
    } else announce('Clipboard access is unavailable. Select and copy the link manually.');
  }
}

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.copy);
    copyText(input.value, input);
  });
});

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
  let sessionChanged = false;
  async function refreshWishes() {
    if (document.visibilityState === 'hidden' || refreshing || sessionChanged) return;
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
      if (data.viewer?.name !== recipientWishes.dataset.viewer || data.viewer?.drawId !== recipientWishes.dataset.drawId) {
        sessionChanged = true;
        status.textContent = 'Elegiste otro nombre en otra pestaña. Recarga esta página antes de continuar.';
        document.querySelector('#wishes-form button[type="submit"]').disabled = true;
        return;
      }
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
