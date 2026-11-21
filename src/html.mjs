import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const styles = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
export const styleHash = createHash('sha256').update(styles).digest('base64');

const escape = (text) => text.replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

export function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)} · Lilauth</title>
<style>${styles}</style></head>
<body><a class="skip" href="#main">Skip to content</a>
<header class="masthead"><div class="masthead-inner"><a class="brand" href="/"><span class="mark" aria-hidden="true">*</span> lilco / lilauth</a><span class="masthead-label">Agent access</span></div></header>
<main id="main" class="shell"><div class="page-heading"><div><span class="eyebrow">Credential operations</span><h1>${escape(title)}</h1></div></div>${body}
<p class="footer">A lilco tool · Tokens are shown once and never stored by Lilauth.</p></main></body></html>`;
}

export function login(message = '') {
  return page('Sign in to Lilauth', `<section class="panel login-panel" aria-label="Sign in">
<div class="panel-head"><h2>Welcome back</h2></div><div class="panel-body">
${message ? `<p class="notice" role="alert">${escape(message)}</p>` : '<p class="hint">Sign in to manage agent credentials for lilboard and lilvault.</p>'}
<form action="/login" method="post">
<label>Username <input name="username" autocomplete="username" maxlength="80" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form></div></section>`);
}

const hidden = (name, value) => `<input type="hidden" name="${name}" value="${escape(value)}">`;

export function dashboard(csrf, views) {
  const csrfField = hidden('csrf', csrf);
  const names = views.map(({ label }) => label);
  const options = (names.length === 2 ? [...names, 'both'] : names)
    .map((name) => `<option value="${escape(name)}">${name === 'both' ? 'Both backends' : escape(name)}</option>`).join('');
  const vaultFields = names.includes('lilvault') ? `<label>lilvault grants (one per line)
<textarea name="permissions" rows="4" placeholder="agents:read-write"></textarea>
<small>Use <code>vault-name:read</code> or <code>vault-name:read-write</code> for existing vaults. Leave blank for lilboard only.</small></label>` : '';
  const lists = views.map(({ label, entries, warning }) => `<section class="panel" aria-label="${escape(label)} credentials">
<div class="panel-head registry-title"><h2>${escape(label)} credentials</h2>${entries ? `<span class="count">${entries.length} agents</span>` : ''}</div>
${warning ? `<p class="notice" role="alert">${escape(warning)}</p>` : ''}${
    !entries ? '<p class="empty">Could not load credentials from this backend.</p>' : !entries.length ? '<p class="empty">No credentials found.</p>' :
    `<div class="table-wrap"><table><thead><tr><th scope="col">Name</th><th scope="col">Grants</th><th scope="col">Action</th></tr></thead>
<tbody>${entries.map(({ name, grants, revocable }) => `<tr><th scope="row">${escape(name)}</th><td class="grants">${escape(grants)}</td><td class="actions">${
      revocable ? `<form method="post" action="/revoke">${csrfField}${hidden('target', label)}${hidden('name', name)}
<button class="quiet small" type="submit" aria-label="Revoke ${escape(name)} on ${escape(label)}"${warning ? ' disabled' : ''}>Revoke</button></form>` : '<span class="badge">Not managed here</span>'
    }</td></tr>`).join('')}</tbody></table></div>`}</section>`).join('');
  return page('Lilauth', `<div class="layout"><section class="panel">
<div class="panel-head"><h2>Mint an agent credential</h2></div><div class="panel-body">
<p class="hint">Use a new name. Existing credentials are not rotated. When minting on both backends, one backend may succeed while the other fails.</p>
<form method="post" action="/mint">${csrfField}
<label>Backend <select name="target">${options}</select></label>
<label>Agent name <input name="name" pattern="[A-Za-z0-9_\\-]{1,64}" required></label>
${names.includes('lilboard') ? '<p class="hint">lilboard agents can write to all boards; reads do not require an agent token.</p>' : ''}
${vaultFields}<button type="submit">Mint token</button>
</form></div></section><div class="registry">${lists}</div></div>
<p class="hint">Revocation disables the selected credential immediately on its backend.</p>
<form action="/logout" method="post">${csrfField}<button class="quiet" type="submit">Sign out</button></form>`);
}

export function actionResult(create, name, results) {
  return page(`${create ? 'Mint' : 'Revoke'} result`, `<p class="lede">Agent: <strong>${escape(name)}</strong></p>
<div class="result-list">${results.map(({ label, message, token }) => `<section class="panel"><div class="panel-head"><h2>${escape(label)}</h2></div><div class="panel-body">${token ?
    `<p>Copy this new token now. Lilauth cannot show it again.</p><code class="token">${escape(token)}</code>` :
    `<p class="notice" role="alert">${escape(message)}</p>`}</div></section>`).join('')}</div>
<p class="footer"><a href="/">Return to credential list</a></p>`);
}
