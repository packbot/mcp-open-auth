function escapeHtml(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
export function renderForm(serviceName, fields, pendingId, errorMessage, previousValues) {
    const errorHtml = errorMessage
        ? `<div class="error">${escapeHtml(errorMessage)}</div>`
        : "";
    const fieldsHtml = fields
        .map((f) => {
        const required = f.required !== false ? " required" : "";
        const value = f.type !== "password" && previousValues?.[f.name]
            ? ` value="${escapeHtml(previousValues[f.name])}"`
            : "";
        const placeholder = f.placeholder ? ` placeholder="${escapeHtml(f.placeholder)}"` : "";
        return `      <label for="${escapeHtml(f.name)}">${escapeHtml(f.label)}</label>
      <input type="${escapeHtml(f.type)}" id="${escapeHtml(f.name)}" name="${escapeHtml(f.name)}"${placeholder}${value}${required}>`;
    })
        .join("\n");
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(serviceName)} - Connect</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f0f; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 2rem; width: 100%; max-width: 420px; }
    h1 { font-size: 1.25rem; margin-bottom: 0.25rem; }
    .subtitle { color: #888; font-size: 0.875rem; margin-bottom: 1.5rem; }
    label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; }
    input { width: 100%; padding: 0.5rem 0.75rem; background: #111; border: 1px solid #333; border-radius: 6px; color: #e0e0e0; font-size: 0.875rem; margin-bottom: 1rem; }
    input:focus { outline: none; border-color: #666; }
    button { width: 100%; padding: 0.625rem; background: #e0e0e0; color: #111; border: none; border-radius: 6px; font-size: 0.875rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #fff; }
    .error { background: #2a1515; border: 1px solid #5a2020; color: #ff6b6b; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Connect to ${escapeHtml(serviceName)}</h1>
    <p class="subtitle">Enter your credentials to continue.</p>
    ${errorHtml}
    <form method="POST" action="/authorize/complete">
      <input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}">
${fieldsHtml}
      <button type="submit">Connect</button>
    </form>
  </div>
</body>
</html>`;
}
//# sourceMappingURL=form.js.map