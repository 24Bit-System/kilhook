// Pure helpers used by App.svelte. Keeping the decision logic here makes it
// testable without a WebView or a Wails bridge.

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// isUnsafeMethod reports whether fuzzing this method can create or modify
// server state. GET, HEAD and OPTIONS are treated as safe by convention.
export function isUnsafeMethod(method) {
  return UNSAFE_METHODS.has(String(method ?? '').toUpperCase());
}

// pickSelection keeps the current file selected when it still exists in the
// workspace, otherwise falls back to the first file. It returns the input
// object itself so callers can compare by identity.
export function pickSelection(files, selected) {
  if (!Array.isArray(files) || files.length === 0) return null;
  if (selected && files.some((f) => f.path === selected.path)) return selected;
  return files[0];
}

// refreshSelected re-resolves the current selection against a fresh Discover
// result. pickSelection intentionally returns the old object when the path
// still exists, which leaves a stale method/name after a save — and a stale
// method defeats the unsafe-method confirmation. When the same file is still
// present, return its fresh Workfile and mark the change as metadata-only:
// the editor does not need to reload.
export function refreshSelected(files, selected) {
  const fresh = selected && Array.isArray(files) ? files.find((f) => f.path === selected.path) : null;
  if (fresh) return { next: fresh, refreshOnly: true };
  return { next: pickSelection(files, null), refreshOnly: false };
}

// envForRun returns the environment name only when its YAML file exists. An
// unbacked typed name would make the engine fail on a missing env file.
export function envForRun(env, envs) {
  return Array.isArray(envs) && envs.includes(env) ? env : '';
}

// selectionUnchanged reports whether an async save/run still applies to the
// file the user has selected now. A null target means nothing was selected when
// the operation started, so there is nothing to invalidate.
export function selectionUnchanged(targetPath, selectedPath) {
  return !targetPath || selectedPath === targetPath;
}

// canRun is the Run button's enabled state, excluding the method guard that
// needs a confirmation.
export function canRun(selected, running) {
  return !!selected && !running && !selected.error;
}

// filterPalette ranks exact label prefixes first, then substring label hits,
// then keyword hits. Ties keep the caller's natural order.
export function filterPalette(items, query) {
  const q = String(query ?? '').trim().toLowerCase();
  if (!q) return items;
  return items
    .map((it, order) => {
      const label = String(it.label ?? '').toLowerCase();
      const text = String(it.text ?? '').toLowerCase();
      const score = label.startsWith(q) ? 0 : label.includes(q) ? 1 : text.includes(q) ? 2 : -1;
      return score < 0 ? null : { it, score, order };
    })
    .filter(Boolean)
    .sort((a, b) => a.score - b.score || a.order - b.order)
    .map((s) => s.it);
}

export function severityCounts(findings) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings ?? []) {
    const s = String(f?.severity ?? '').toLowerCase();
    if (s === 'high' || s === 'medium' || s === 'low') c[s]++;
  }
  return c;
}

export function severityPct(counts, n) {
  const total = (counts?.high ?? 0) + (counts?.medium ?? 0) + (counts?.low ?? 0);
  return total ? Math.round((n / total) * 100) : 0;
}

export function shortURL(url) {
  return String(url ?? '').replace(/^https?:\/\//, '');
}

export function methodClass(method) {
  return `m-${String(method ?? '').toLowerCase()}`;
}

// statusTone is a semantic class, not an inline colour: 2xx settles, 4xx/5xx
// warn, 3xx is informational.
export function statusTone(code) {
  if (!code) return '';
  if (code >= 500) return 'tone-bad';
  if (code >= 400) return 'tone-warn';
  if (code >= 300) return 'tone-info';
  return 'tone-good';
}

export function fmtMS(ms) {
  if (ms == null) return '—';
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

export function fmtBytes(n) {
  if (n == null) return '—';
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${n} B`;
}

export function fmtWhen(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d
    .toLocaleString(undefined, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
    .replace(',', '');
}

// findingText is the clipboard representation of one finding. It is deliberately
// plain text: the report is local, but the copy target is usually a ticket,
// chat message or notes field.
export function findingText(f) {
  const lines = [
    `[${f?.severity ?? 'unknown'}] ${f?.kind ?? 'finding'} | ${f?.target ?? 'unknown target'}`,
    `payload: ${f?.payload ?? ''}`,
  ];
  if (f?.status_code) {
    lines.push(`status: ${f.status_code}${f.baseline_status ? ` (baseline ${f.baseline_status})` : ''}`);
  }
  if (f?.duration_ms) lines.push(`duration: ${f.duration_ms}ms`);
  if (f?.count > 1) lines.push(`hits: ${f.count}`);
  lines.push(`evidence: ${f?.evidence ?? ''}`);
  return lines.join('\n');
}

// violationText is the clipboard representation of one contract violation.
export function violationText(v) {
  const lines = [
    `path: ${v?.path ?? 'response'}`,
    `message: ${v?.message ?? ''}`,
  ];
  if (v?.operation) lines.push(`operation: ${v.operation}`);
  if (v?.status) lines.push(`status: ${v.status}`);
  return lines.join('\n');
}

// lastPathKey extracts the field name a JSON-path violation points at:
// "response.users[0].email" -> "email", "response.items[0]" -> "items",
// "response[0].id" -> "id". The response root itself has no key.
export function lastPathKey(path) {
  const stripped = String(path ?? '').replace(/^response(?:\.|$)/, '');
  const parts = stripped.split('.').filter(Boolean);
  const last = parts[parts.length - 1] ?? '';
  return last.replace(/\[\d+\]/g, '');
}
