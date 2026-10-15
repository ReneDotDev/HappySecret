import { encryptSecret, decryptSecret, decodeKey, MAX_BYTES } from './crypto.js';
const $ = id => document.getElementById(id);
const form = $('create-form');
const message = $('message');
const feedback = $('feedback');
function notify(text, error = false) {
  feedback.textContent = text;
  feedback.classList.toggle('error', error);
  feedback.hidden = !text;
}
function selectPanel(id) {
  for (const panel of ['create-form', 'created-panel', 'reveal-panel']) $(panel).hidden = id !== panel;
}
function localDate(date) {
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function updateDates() {
  const now = Date.now();
  $('expiry-date').min = localDate(new Date(now + 60000));
  $('expiry-date').max = localDate(new Date(now + 7 * 86400000 - 60000));
}
updateDates();
$('expiry-date').value = localDate(new Date(Date.now() + 86400000));
$('expiry').addEventListener('change', () => {
  $('custom-expiry').hidden = $('expiry').value !== 'custom';
  $('expiry-date').required = $('expiry').value === 'custom';
  updateDates();
});
message.addEventListener('input', () => {
  const size = new TextEncoder().encode(message.value).length;
  $('byte-count').textContent = `${(size/1024).toFixed(1)} / 32 KiB`;
  message.setCustomValidity(size > MAX_BYTES ? 'The secret must be no larger than 32 KiB.' : '');
});
async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = 'Copied!';
    setTimeout(() => { button.textContent = label; }, 1800);
    notify('Copied to your clipboard.');
  } catch { notify('Clipboard access is unavailable. Select and copy the text manually.', true); }
}
async function responseJson(response) {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request failed. Please try again.');
  return data;
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('create-button');
  button.disabled = true;
  button.textContent = 'Encrypting…';
  notify('');
  try {
    const expiry = $('expiry').value;
    const expires = expiry === 'custom' ? new Date($('expiry-date').value).getTime() : Date.now() + Number(expiry) * 1000;
    if (!Number.isFinite(expires) || expires < Date.now() + 5000 || expires > Date.now() + 7 * 86400000) throw new Error('Choose an expiration in the future, within the next 7 days.');
    const expiresAt = new Date(expires).toISOString();
    const maxViews = Number($('views').value);
    const { id, key, envelope } = await encryptSecret(message.value, { expiresAt, maxViews });
    button.textContent = 'Creating link…';
    await responseJson(await fetch(`/api/v1/secrets/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope), cache: 'no-store', referrerPolicy: 'no-referrer' }));
    $('share-link').value = `${location.origin}/s/${id}#${key}`;
    $('created-details').textContent = `${maxViews} ${maxViews === 1 ? 'view' : 'views'} · Expires ${new Date(expiresAt).toLocaleString()}`;
    message.value = '';
    message.dispatchEvent(new Event('input'));
    selectPanel('created-panel');
    $('copy-link').focus();
  } catch (error) { notify(error.message || 'Unable to create this secret. Please try again.', true); }
  finally { button.disabled = false; button.textContent = 'Create a secret link ↗'; }
});
$('copy-link').addEventListener('click', () => copy($('share-link').value, $('copy-link')));
$('share-link').addEventListener('click', () => $('share-link').select());
$('copy-secret').addEventListener('click', () => copy($('revealed-message').value, $('copy-secret')));
$('another').addEventListener('click', () => { $('share-link').value = ''; selectPanel('create-form'); notify(''); message.focus(); });
const match = /^\/s\/([a-f0-9]{64})$/.exec(location.pathname);
if (match) {
  selectPanel('reveal-panel');
  $('intro').hidden = true;
  document.querySelector('.secret-card').classList.add('recipient-card');
  document.title = 'A secret for you — HappySecret';
  const id = match[1];
  let encodedKey = location.hash.slice(1);
  try { decodeKey(encodedKey); }
  catch (error) { $('reveal-button').hidden = true; $('reveal-title').textContent = 'This link is incomplete.'; $('reveal-description').textContent = 'Ask the sender for the complete link, including the part after #. No view has been used.'; notify(error.message, true); }
  $('reveal-button').addEventListener('click', async () => {
    const button = $('reveal-button');
    button.disabled = true;
    button.textContent = 'Opening your secret…';
    notify('');
    try {
      const response = await fetch(`/api/v1/secrets/${id}/consume`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 410) {
        button.hidden = true;
        $('reveal-title').textContent = 'This secret has disappeared.';
        $('reveal-description').textContent = 'It has expired, reached its view limit, or never existed. Ask the sender to create a new link.';
        encodedKey = '';
        history.replaceState(null, '', location.pathname);
        return;
      }
      const envelope = await responseJson(response);
      button.hidden = true;
      let plaintext;
      try { plaintext = await decryptSecret(id, encodedKey, envelope); }
      catch { throw new Error('The secret could not be authenticated or decrypted. This view has been used. Check the complete link with the sender.'); }
      $('revealed-message').value = plaintext;
      $('revealed-content').hidden = false;
      $('reveal-title').textContent = 'Just between you and the sender.';
      $('reveal-description').textContent = 'Decrypted here, on your device.';
      $('remaining-details').textContent = envelope.remainingViews === 0 ? 'Last view · Ciphertext removed from active storage.' : `${envelope.remainingViews} ${envelope.remainingViews === 1 ? 'view' : 'views'} left · Expires ${new Date(envelope.expiresAt).toLocaleString()}`;
      encodedKey = '';
      history.replaceState(null, '', location.pathname);
    } catch (error) {
      notify(error.message === 'Failed to fetch' ? 'The connection failed. A view may have been used; retrying will request another view.' : error.message, true);
      button.disabled = false;
      button.textContent = 'Try to reveal again';
    }
  });
}
window.addEventListener('pagehide', () => { message.value = ''; $('revealed-message').value = ''; $('share-link').value = ''; });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
