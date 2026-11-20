const escape = (text) => text.replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

export function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)} · Lilauth</title></head>
<body><main><h1>${escape(title)}</h1>${body}</main></body></html>`;
}

export function login(message = '') {
  return page('Sign in to Lilauth', `${message && `<p role="alert">${escape(message)}</p>`}
<form action="/login" method="post">
  <p><label>Username <input name="username" autocomplete="username" maxlength="80" required></label></p>
  <p><label>Password <input name="password" type="password" autocomplete="current-password" required></label></p>
  <button>Sign in</button>
</form>`);
}

const hidden = (name, value) => `<input type="hidden" name="${name}" value="${escape(value)}">`;

export function dashboard(csrf, views) {
  const csrfField = hidden('csrf', csrf);
  const names = views.map(({ label }) => label);
  const options = (names.length === 2 ? [...names, 'both'] : names)
    .map((name) => `<option value="${name}">${name === 'both' ? 'Both backends' : name}</option>`).join('');
  const vaultFields = names.includes('lilvault') ? `<p><label>lilvault grants (one per line)<br>
<textarea name="permissions" rows="4"></textarea></label><br>
Use <code>vault-name:read</code> or <code>vault-name:read-write</code> for existing vaults. Leave blank for lilboard only.</p>` : '';
  const lists = views.map(({ label, entries, warning }) => `<section><h2>${label} credentials</h2>
${warning && `<p role="alert">${escape(warning)}</p>`}${
    !entries ? '<p>Could not load credentials from this backend.</p>' : !entries.length ? '<p>No credentials found.</p>' :
    `<table><thead><tr><th scope="col">Name</th><th scope="col">Grants</th><th scope="col">Action</th></tr></thead>
<tbody>${entries.map(({ name, grants, revocable }) => `<tr><th scope="row">${escape(name)}</th><td>${escape(grants)}</td><td>${
      revocable ? `<form method="post" action="/revoke">${csrfField}${hidden('target', label)}${hidden('name', name)}
<button aria-label="Revoke ${escape(name)} on ${label}"${warning ? ' disabled' : ''}>Revoke</button></form>` : 'Not managed here'
    }</td></tr>`).join('')}</tbody></table>`}</section>`).join('');
  return page('Lilauth', `<form action="/logout" method="post">${csrfField}<button>Sign out</button></form>
<section><h2>Mint an agent credential</h2>
<p>Use a new name. Existing credentials are not rotated. When minting on both backends, one backend may succeed while the other fails.</p>
<form method="post" action="/mint">${csrfField}
  <p><label>Backend <select name="target">${options}</select></label></p>
  <p><label>Agent name <input name="name" pattern="[A-Za-z0-9_\\-]{1,64}" required></label></p>
  ${names.includes('lilboard') ? '<p>lilboard agents can write to all boards; reads do not require an agent token.</p>' : ''}
  ${vaultFields}
  <button>Mint</button>
</form></section>
<p>Revocation disables the selected credential immediately on its backend.</p>${lists}`);
}

export function actionResult(create, name, results) {
  return page(`${create ? 'Mint' : 'Revoke'} result`, `<p>Agent: <strong>${escape(name)}</strong></p>
${results.map(({ label, message, token }) => `<section><h2>${label}</h2>${token ?
    `<p>Copy this new token now. Lilauth cannot show it again.</p><p><code>${escape(token)}</code></p>` :
    `<p>${escape(message)}</p>`}</section>`).join('')}
<p><a href="/">Return to credential list</a></p>`);
}
