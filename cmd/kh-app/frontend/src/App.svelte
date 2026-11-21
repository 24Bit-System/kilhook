<script>
  import { onMount, onDestroy, tick } from 'svelte';
  import { Clipboard, Events, Window as WailsWindow } from '@wailsio/runtime';
  import * as Workspace from '../bindings/kilhook/cmd/kh-app/workspace.js';
  import Editor from './lib/Editor.svelte';
  import {
    canRun,
    envForRun,
    filterPalette,
    findingText,
    fmtBytes,
    fmtMS,
    fmtWhen,
    isUnsafeMethod,
    lastPathKey,
    methodClass,
    refreshSelected,
    selectionUnchanged,
    severityCounts,
    severityPct,
    shortURL,
    statusTone,
    violationText,
  } from './lib/logic.js';

  let version = $state('');
  let dir = $state('');
  let env = $state('dev');
  let files = $state([]);
  let selected = $state(null);
  let result = $state(null);
  let html = $state('');
  let error = $state('');
  let progress = $state('');
  let running = $state(false);
  let toast = $state('');
  let loaded = $state(false);
  let tab = $state('report');
  let doc = $state(null);
  let docKey = $state(0);
  let saving = $state(false);
  let envs = $state([]);
  let diskChanged = $state(false);
  let maximised = $state(false);
  let editorDirty = $state(false);
  let docLoading = $state(false);
  let creating = $state(false);
  let openSeq = $state(0);
  let nonLocalPrompt = $state(false);
  let nonLocalText = $state('');
  let unsafePrompt = $state(false);
  let unsafeText = $state('');

  function confirmNonLocal() {
    if (nonLocalText.trim().toLowerCase() !== 'allow') {
      flash('type "allow" to confirm non-localhost fuzzing');
      return;
    }
    opts.allowNonLocal = true;
    nonLocalPrompt = false;
    nonLocalText = '';
    flash('non-localhost fuzzing enabled');
  }

  function confirmUnsafe() {
    if (unsafeText.trim().toLowerCase() !== 'allow') {
      flash('type "allow" to confirm fuzzing a method that can change data');
      return;
    }
    opts.allowUnsafeMethods = true;
    unsafePrompt = false;
    unsafeText = '';
    flash('unsafe-method fuzzing enabled for this session');
  }

  // External-edit detection: the selected file's mtime as a string, and a poll
  // that flags when a text editor changes the file behind the window's back.
  let selectedMtime = '';
  let diskPoll;
  let toastTimer;

  function flash(msg) {
    toast = msg;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 4200);
  }

  // The Wails bridge owns the system clipboard in the packaged app; the browser
  // APIs keep copy working in Vite dev and in a plain-browser fallback.
  async function copyText(text, label = 'copied') {
    try {
      await Clipboard.SetText(text);
      flash(label);
      return;
    } catch {
      // no Wails bridge: fall through
    }
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '-1000px';
        document.body.appendChild(area);
        try {
          area.select();
          const ok = document.execCommand('copy');
          if (!ok) throw new Error('clipboard unavailable');
        } finally {
          // execCommand can throw; without finally the off-screen textarea
          // stays attached with the copied credential still in its value.
          area.remove();
        }
      }
      flash(label);
    } catch (e) {
      flash(`copy failed: ${String(e?.message ?? e)}`);
    }
  }

  // JSON-path navigation: find the violated field in the response preview,
  // highlight it, and scroll the preview to it. The preview is plain text, so
  // the last path segment is the only reliable anchor.
  let responsePre = $state();
  let pathMark = null;
  let pathTimer;

  function clearPathHighlight() {
    window.clearTimeout(pathTimer);
    if (!pathMark) return;
    const parent = pathMark.parentNode;
    if (parent) {
      parent.replaceChild(document.createTextNode(pathMark.textContent ?? ''), pathMark);
      parent.normalize();
    }
    pathMark = null;
  }

  function locateViolation(v) {
    clearPathHighlight();
    const pre = responsePre;
    const key = lastPathKey(v?.path);
    if (!pre || !key) {
      flash('there is no locatable field in the response preview');
      return;
    }
    const text = pre.textContent ?? '';
    const quoted = text.indexOf(`"${key}"`);
    const at = quoted >= 0 ? quoted : text.indexOf(key);
    if (at < 0) {
      flash(`"${key}" is not in the response preview`);
      return;
    }
    const span = quoted >= 0 ? key.length + 2 : key.length;
    let offset = 0;
    let node = null;
    let start = 0;
    for (const child of pre.childNodes) {
      if (child.nodeType !== Node.TEXT_NODE) continue;
      const len = child.nodeValue?.length ?? 0;
      if (at <= offset + len) {
        node = child;
        start = at - offset;
        break;
      }
      offset += len;
    }
    if (!node) {
      flash('the response preview cannot be highlighted');
      return;
    }
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, Math.min(node.nodeValue.length, start + span));
    const mark = document.createElement('mark');
    mark.className = 'path-hit';
    try {
      range.surroundContents(mark);
    } catch {
      flash('the response preview cannot be highlighted');
      return;
    }
    pathMark = mark;
    mark.scrollIntoView({ block: 'center', behavior: 'smooth' });
    pathTimer = window.setTimeout(clearPathHighlight, 3200);
  }

  // Custom titlebar: the window is frameless, so minimize/maximize/close are
  // DOM buttons driving the Wails runtime. maximised tracks the icon state.
  async function syncMaximised() {
    try {
      maximised = await WailsWindow.IsMaximised();
    } catch {
      // window API unreachable (e.g. running in a plain browser)
    }
  }

  const winMinimise = () => WailsWindow.Minimise().catch(() => {});
  const winClose = () => WailsWindow.Close().catch(() => {});
  async function winToggleMaximise() {
    try { await WailsWindow.ToggleMaximise(); } catch { /* noop */ }
    await syncMaximised();
  }

  // Global shortcuts: Ctrl/Cmd+Enter runs the loop, Ctrl/Cmd+K opens the
  // command palette, Escape closes it. (The editor's Ctrl+S save is handled
  // inside the Editor component.)
  function globalKeys(event) {
    const mod = event.ctrlKey || event.metaKey;
    if (mod && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      if (paletteOpen) closePalette();
      else openPalette();
      return;
    }
    if (event.key === 'Escape' && paletteOpen) {
      closePalette();
      return;
    }
    if (mod && event.key === 'Enter') {
      if (paletteOpen) return; // the palette owns Enter while it is open
      event.preventDefault();
      run();
      return;
    }
    // Keep focus inside the palette while it is open.
    if (paletteOpen && event.key === 'Tab') {
      event.preventDefault();
    }
  }

  // ---------- command palette (Ctrl+K) ----------
  // One keyboard surface for everything: jump to a request, run the loop,
  // switch env or tab, save the report, drive the window. Items that cannot
  // run right now (no result to save, run already in flight) stay off the list
  // instead of sitting there disabled.
  let paletteOpen = $state(false);
  let paletteQuery = $state('');
  let paletteIndex = $state(0);
  let paletteInputEl = $state();

  const paletteItems = $derived.by(() => {
    const items = [];
    for (const f of files) {
      if (running) continue;
      items.push({
        id: `file:${f.path}`,
        group: 'Requests',
        label: f.name,
        method: f.method ?? '',
        text: `${f.name} ${f.method ?? ''} open request jump go`.toLowerCase(),
        run: () => selectFile(f),
      });
    }
    const push = (id, group, label, action, opt = {}) => {
      if (opt.when !== undefined && !opt.when) return;
      items.push({
        id,
        group,
        label,
        hint: opt.hint ?? '',
        text: `${label} ${opt.keywords ?? ''}`.toLowerCase(),
        run: action,
      });
    };
    push('act:run', 'Actions', 'Run loop', run, { when: selected && !running, hint: 'Ctrl+Enter', keywords: 'run start send execute fuzz check' });
    push('act:stop', 'Actions', 'Stop run', stop, { when: running, keywords: 'stop cancel abort' });
    push('act:new', 'Actions', 'New request', createFile, { when: !running && !creating, keywords: 'new create add request file' });
    push('act:save', 'Actions', 'Save HTML report', saveHTML, { when: !!html, keywords: 'save export download html report' });
    push('act:reload', 'Actions', 'Reload workspace', load, { when: !running, keywords: 'reload refresh rescan workspace files' });
    push('act:browse', 'Actions', 'Browse for workspace folder…', browse, { when: !running, keywords: 'browse folder open directory choose workspace' });
    push('nav:report', 'Go to', 'Report tab', () => (tab = 'report'), { keywords: 'report results findings tab view go' });
    push('nav:editor', 'Go to', 'Editor tab', () => (tab = 'editor'), { when: !!doc, keywords: 'editor edit request tab view go' });
    for (const name of envOptions) {
      push(`env:${name}`, 'Environment', `Switch to ${name}`, () => (env = name), { when: !running && env !== name, keywords: 'env environment switch change' });
    }
    push('win:max', 'Window', maximised ? 'Restore window' : 'Maximize window', winToggleMaximise, { keywords: 'window maximize restore zoom' });
    push('win:min', 'Window', 'Minimize window', winMinimise, { keywords: 'window minimize hide' });

    return filterPalette(items, paletteQuery);
  });

  // Keep the highlighted row valid as the query filters the list down.
  $effect(() => {
    paletteQuery;
    paletteIndex = 0;
  });
  $effect(() => {
    if (paletteIndex >= paletteItems.length) paletteIndex = Math.max(0, paletteItems.length - 1);
  });

  async function openPalette() {
    paletteQuery = '';
    paletteIndex = 0;
    paletteOpen = true;
    await tick();
    paletteInputEl?.focus();
  }

  function closePalette() {
    paletteOpen = false;
  }

  function execPalette(item) {
    closePalette();
    item.run?.();
  }

  async function movePalette(delta) {
    const n = paletteItems.length;
    if (!n) return;
    paletteIndex = (paletteIndex + delta + n) % n;
    await tick();
    document.querySelector('.palette-item.is-active')?.scrollIntoView({ block: 'nearest' });
  }

  function paletteKeys(event) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      movePalette(1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      movePalette(-1);
    } else if (event.key === 'Enter' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      const item = paletteItems[paletteIndex];
      if (item) execPalette(item);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      closePalette();
    }
  }

  let opts = $state({
    noFuzz: false,
    noSpec: false,
    noDiff: false,
    timing: false,
    allowNonLocal: false,
    allowUnsafeMethods: false,
    updateBaseline: false,
  });

  const findings = $derived(result?.fuzz?.findings ?? []);
  const advisory = $derived(result?.fuzz?.advisory ?? []);
  const violations = $derived(result?.spec?.violations ?? []);
  const changes = $derived(result?.diff?.changes ?? []);
  const warnings = $derived(result?.warnings ?? []);
  const clean = $derived(result !== null && result.exit_code === 0);

  // Severity distribution for the findings bar (advisory is not a severity).
  const sevCounts = $derived(severityCounts(findings));

  function sevPct(n) {
    return severityPct(sevCounts, n);
  }

  // The hero states what actually ran, so "Clean" can never imply a check that
  // was switched off for this run.
  const phases = $derived(
    [result?.fuzz ? 'fuzz' : null, result?.spec ? 'contract' : null, result?.diff ? 'diff' : null].filter(Boolean),
  );

  const verdictNote = $derived.by(() => {
    if (!result) return '';
    if (clean) {
      return phases.length ? `passed ${phases.join(' · ')}` : 'no checks enabled for this run';
    }
    const parts = [];
    if (findings.length) parts.push(`${findings.length} finding${findings.length === 1 ? '' : 's'}`);
    if (violations.length) parts.push(`${violations.length} violation${violations.length === 1 ? '' : 's'}`);
    return parts.join(' · ') || `exit ${result.exit_code}`;
  });

  // Section numbers only advance for sections that render, so a run without a
  // baseline never shows a gap where "04" should be.
  const nums = $derived.by(() => {
    const out = { response: '01', contract: '02', fuzz: '03', diff: '', notices: '' };
    let n = 4;
    if (result?.diff) out.diff = String(n++).padStart(2, '0');
    if (warnings.length) out.notices = String(n++).padStart(2, '0');
    return out;
  });

  let progressOff;
  onMount(async () => {
    // Wire listeners and polling first so a rejected bootstrap (e.g. running
    // in a plain browser with no IPC bridge) cannot leave the window without
    // Ctrl+K, polling or progress events.
    progressOff = Events.On('run:progress', (event) => {
      progress = event.data?.phase ?? '';
    });
    diskPoll = setInterval(checkDisk, 2000);
    window.addEventListener('resize', syncMaximised);
    window.addEventListener('keydown', globalKeys);
    await syncMaximised();
    try {
      version = await Workspace.Version();
      dir = await Workspace.Home();
      await load();
    } catch (e) {
      error = String(e?.message ?? e);
    }
  });

  onDestroy(() => {
    clearPathHighlight();
    if (progressOff) progressOff();
    clearInterval(diskPoll);
    clearTimeout(toastTimer);
    window.removeEventListener('resize', syncMaximised);
    window.removeEventListener('keydown', globalKeys);
  });

  async function load() {
    error = '';
    try {
      files = (await Workspace.Discover(dir)) ?? [];
      envs = (await Workspace.Environments(dir)) ?? [];
      loaded = true;
      const { next, refreshOnly } = refreshSelected(files, selected);
      if (refreshOnly) {
        selected = next;
      } else if (next !== selected) {
        await selectFile(next);
      }
    } catch (e) {
      error = String(e?.message ?? e);
      files = [];
    }
  }

  async function selectFile(file) {
    if (running) {
      flash('a run is in progress — stop it first');
      return;
    }
    error = '';
    const seq = ++openSeq;
    selected = file;
    doc = null;
    docLoading = !!file;
    diskChanged = false;
    selectedMtime = '';
    // A report belongs to the file that produced it. Leaving the previous
    // result mounted while the header shows a different file is misleading.
    result = null;
    html = '';
    if (!file) {
      docLoading = false;
      return;
    }
    if (file.error) {
      // Discover already refused to parse it (oversized or malformed). Do not
      // ask Open to read it: the list can show the reason without touching
      // the file again.
      docLoading = false;
      error = file.error;
      return;
    }
    try {
      const opened = await Workspace.Open(file.path);
      if (seq !== openSeq || selected?.path !== file.path) return;
      doc = opened;
      docKey++;
      docLoading = false;
      await noteMtime();
    } catch (e) {
      if (seq !== openSeq) return;
      error = String(e?.message ?? e);
      docLoading = false;
    }
  }

  async function noteMtime() {
    if (!selected?.path) return;
    try {
      selectedMtime = await Workspace.Modified(selected.path);
    } catch {
      selectedMtime = '';
    }
  }

  async function checkDisk() {
    if (!selected?.path || !selectedMtime || diskChanged || saving) return;
    try {
      if (await Workspace.Modified(selected.path) !== selectedMtime) diskChanged = true;
    } catch {
      // The file vanished; opening or running it will report that.
    }
  }

  async function reloadFromDisk() {
    await selectFile(selected);
  }

  async function keepEditing() {
    diskChanged = false;
    await noteMtime();
  }

  async function createFile() {
    if (creating) return;
    creating = true;
    error = '';
    try {
      const path = await Workspace.Create(dir);
      await load();
      const created = files.find((f) => f.path === path);
      if (created) {
        await selectFile(created);
        tab = 'editor';
        flash(`created ${path}`);
      }
    } catch (e) {
      error = String(e?.message ?? e);
    } finally {
      creating = false;
    }
  }

  async function saveDoc(next) {
    saving = true;
    error = '';
    const targetPath = selected?.path;
    try {
      const saved = await Workspace.Save(next);
      if (!selectionUnchanged(targetPath, selected?.path)) return false;
      doc = saved;
      docKey++;
      flash(`saved ${doc.path}`);
      diskChanged = false;
      await noteMtime();
      await load();
      return true;
    } catch (e) {
      error = String(e?.message ?? e);
      return false;
    } finally {
      saving = false;
    }
  }

  async function saveAndRun(next) {
    const before = selected?.path;
    const saved = await saveDoc(next);
    // A failed save must never run the previously saved file while claiming
    // success; saveDoc reports failure without throwing.
    if (!saved || !selectionUnchanged(before, selected?.path)) return;
    await run();
  }

  async function run() {
    if (!selected || running) return;
    if (selected.error) {
      flash(selected.error);
      return;
    }
    // Fuzzing a write method can create or modify server state. Require one
    // explicit typed confirmation per session before the loop starts.
    if (!opts.noFuzz && isUnsafeMethod(selected.method) && !opts.allowUnsafeMethods) {
      unsafePrompt = true;
      flash(`${selected.method} can change data — confirm before fuzzing`);
      return;
    }
    running = true;
    error = '';
    toast = '';
    progress = 'sending request…';
    // Flash after clearing the previous toast, otherwise the warning is
    // wiped one line later and the user never sees that saved bytes were used.
    if (editorDirty) {
      flash('unsaved editor changes — this run uses the saved file');
    }
    try {
      envs = (await Workspace.Environments(dir)) ?? [];
      const envName = envForRun(env, envs);
      const res = await Workspace.Run(selected.path, { ...opts, envName });
      clearPathHighlight();
      result = JSON.parse(res.json);
      html = res.html;
      tab = 'report';
    } catch (e) {
      error = String(e?.message ?? e);
      // A failed run has no result: keep the verdict and the enabled "Save
      // HTML" button from describing a previous successful run.
      result = null;
      html = '';
    } finally {
      // Overwriting a baseline is a one-shot destructive action, never a
      // sticky preference that quietly applies to every later run/file.
      opts.updateBaseline = false;
      running = false;
      progress = '';
    }
  }

  async function stop() {
    try {
      await Workspace.Cancel();
    } catch {
      // cancelling is best-effort
    }
    progress = 'stopping after the requests already in flight…';
  }

  async function saveHTML() {
    if (!html) return;
    error = '';
    try {
      const out = await Workspace.ChooseSavePath('kilhook-report.html');
      if (!out) return; // cancelled: nothing to do
      const path = await Workspace.SaveHTML(html, out);
      flash(`saved ${path}`);
    } catch (e) {
      error = String(e?.message ?? e);
    }
  }

  async function browse() {
    error = '';
    try {
      const chosen = await Workspace.ChooseFolder();
      if (!chosen) return;
      dir = chosen;
      await load();
    } catch (e) {
      error = String(e?.message ?? e);
    }
  }

  // The env in use may not exist yet (a fresh workspace, or a name typed before
  // the file was created), so keep it selectable instead of silently dropping it.
  const envOptions = $derived(env && !envs.includes(env) ? [env, ...envs] : envs);
</script>

<div class="app">
  <header class="rail">
    <div class="brand">
      <span class="mark">
        <img src="/icon.png" alt="" />
      </span>
      <b>kilhook</b><span class="ver">{version}</span>
    </div>

    <div class="src">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>
      <input bind:value={dir} spellcheck="false" placeholder="workspace folder" aria-label="workspace folder" />
      <button class="icon-btn" onclick={browse} disabled={running} title="Choose a folder" aria-label="Choose a folder">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
      </button>
      <button class="icon-btn" onclick={load} disabled={running} title="Reload the file list" aria-label="Reload the file list">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.64-6.36" /><path d="M21 3v6h-6" /></svg>
      </button>
    </div>

    <div class="rail-drag" aria-hidden="true"></div>

    <button class="palette-trigger" onclick={openPalette} title="Command palette (Ctrl+K)" aria-label="Open command palette">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></svg>
      <span>Search</span>
      <span class="kbd">Ctrl K</span>
    </button>

    <label class="env-chip">
      <span class="env-dot"></span>
      <select bind:value={env} disabled={running} aria-label="environment">
        {#each envOptions as name (name)}
          <option value={name}>{name}</option>
        {/each}
        {#if envOptions.length === 0}
          <option value="">no env files</option>
        {/if}
      </select>
    </label>

    <div class="actions">
      {#if running}
        <button class="stop has-ico" onclick={stop}>
          <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6.5" y="6.5" width="11" height="11" rx="2" fill="currentColor" /></svg>
          Stop
        </button>
      {/if}
      <button class="primary has-ico" onclick={run} disabled={!canRun(selected, running)} title="Run loop (Ctrl+Enter)">
        {#if running}
          <span class="spin"></span>Running…
        {:else}
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 4.8v14.4L19.5 12z" fill="currentColor" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" /></svg>
          Run loop
        {/if}
      </button>
    </div>

    <div class="win-controls">
      <button class="win-btn win-min" onclick={winMinimise} aria-label="Minimize" title="Minimize" tabindex="-1">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14" /></svg>
      </button>
      <button class="win-btn win-max" onclick={winToggleMaximise} aria-label={maximised ? 'Restore' : 'Maximize'} title={maximised ? 'Restore down' : 'Maximize'} tabindex="-1">
        {#if maximised}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="9" width="10" height="10" rx="1.5" /><path d="M9 5h10v10" /></svg>
        {:else}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="5" y="5" width="14" height="14" rx="1.5" /></svg>
        {/if}
      </button>
      <button class="win-btn win-close" onclick={winClose} aria-label="Close" title="Close" tabindex="-1">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg>
      </button>
    </div>
  </header>

  <div class="shell">
    <aside class="collection">
      <div class="side-head">
        <h2>Requests</h2>
        <span class="count">{files.length}</span>
        <button class="link-btn" onclick={createFile} disabled={running} title="Create a new request file">+ New</button>
      </div>

      <ul class="files">
        {#each files as file (file.path)}
          <li>
            <button
              class="file {selected?.path === file.path ? 'is-active' : ''}"
              onclick={() => selectFile(file)}
              disabled={running}
              title={file.error ? `${file.path} — ${file.error}` : file.path}
            >
              <span class="method {methodClass(file.method)}">{file.method ?? '—'}</span>
              <span class="fname">{file.name}</span>
              {#if file.error}
                <span class="file-error" aria-label="This file cannot be opened">!</span>
              {/if}
            </button>
          </li>
        {/each}
        {#if loaded && files.length === 0}
          <li class="files-empty">No .kh files in this folder.</li>
        {/if}
      </ul>

      <div class="side-foot">
        <div class="group-label">Pipeline</div>
        <label class="switch">
          <span>Fuzzing</span>
          <input
            type="checkbox"
            checked={!opts.noFuzz}
            onchange={(e) => (opts.noFuzz = !e.currentTarget.checked)}
            aria-label="Fuzz declared targets"
          />
        </label>
        <label class="switch">
          <span>Contract</span>
          <input
            type="checkbox"
            checked={!opts.noSpec}
            onchange={(e) => (opts.noSpec = !e.currentTarget.checked)}
            aria-label="Validate against the OpenAPI contract"
          />
        </label>
        <label class="switch">
          <span>Baseline diff</span>
          <input
            type="checkbox"
            checked={!opts.noDiff}
            onchange={(e) => (opts.noDiff = !e.currentTarget.checked)}
            aria-label="Diff against the stored baseline"
          />
        </label>

        <div class="group-label spaced">Options</div>
        <label class="switch">
          <span>Timing hints</span>
          <input type="checkbox" bind:checked={opts.timing} aria-label="Timing hints" />
        </label>
        <div class="group-label spaced">Non-localhost</div>
        {#if !nonLocalPrompt}
          <button class="link-btn" onclick={() => (nonLocalPrompt = true)} disabled={running || opts.allowNonLocal} title="Confirm before fuzzing a host that is not localhost">
            {opts.allowNonLocal ? 'Allowed' : 'Allow non-localhost…'}
          </button>
        {:else}
          <div class="confirm-row">
            <input
              bind:value={nonLocalText}
              placeholder='type "allow" to confirm'
              spellcheck="false"
              aria-label="typed confirmation for non-localhost fuzzing"
            />
            <button class="primary" onclick={confirmNonLocal} disabled={running}>Confirm</button>
            <button class="ghost" onclick={() => { nonLocalPrompt = false; nonLocalText = ''; }}>Cancel</button>
          </div>
        {/if}
        {#if selected && isUnsafeMethod(selected.method)}
          <div class="group-label spaced">Unsafe method</div>
          {#if !unsafePrompt}
            <button class="link-btn" onclick={() => (unsafePrompt = true)} disabled={running || opts.allowUnsafeMethods} title="Fuzzing POST, PUT, PATCH or DELETE can create or modify server state">
              {opts.allowUnsafeMethods ? 'Allowed' : 'Allow write-method fuzzing…'}
            </button>
          {:else}
            <div class="confirm-row">
              <input
                bind:value={unsafeText}
                placeholder='type "allow" to confirm'
                spellcheck="false"
                aria-label="typed confirmation for write-method fuzzing"
              />
              <button class="primary" onclick={confirmUnsafe} disabled={running}>Confirm</button>
              <button class="ghost" onclick={() => { unsafePrompt = false; unsafeText = ''; }}>Cancel</button>
            </div>
          {/if}
        {/if}
        <label class="switch">
          <span>Update baseline</span>
          <input type="checkbox" bind:checked={opts.updateBaseline} aria-label="Overwrite the baseline with this run" />
        </label>
      </div>
    </aside>

    <main class="main">
      <div class="main-head">
        <div class="tabs">
          <button class="tab {tab === 'report' ? 'is-active' : ''}" onclick={() => (tab = 'report')}>Report</button>
          <button class="tab {tab === 'editor' ? 'is-active' : ''}" onclick={() => (tab = 'editor')} disabled={!doc}>
            Editor
          </button>
        </div>
        {#if selected}
          <span class="head-context"><span>{selected.name}</span></span>
        {/if}
      </div>

      <div class="main-scroll">
        {#if error}
          <div class="banner err">{error}</div>
        {/if}
        {#if diskChanged}
          <div class="banner warn row">
            <span>{selected?.name ?? 'This file'} was modified on disk.</span>
            <button class="mini" onclick={reloadFromDisk}>Reload</button>
            <button class="mini ghost" onclick={keepEditing}>Keep this view</button>
          </div>
        {/if}
        {#if running && progress}
          <div class="run-strip"><span class="spin"></span>{progress}</div>
        {/if}

        <div class="tab-panel" hidden={tab !== 'editor' || !selected}>
          {#if selected}
            {#if doc}
              {#key docKey}
                <Editor {doc} busy={saving || running || paletteOpen || nonLocalPrompt || unsafePrompt} bind:dirty={editorDirty} onSave={saveDoc} onSaveAndRun={saveAndRun} onDiscard={() => (toast = '')} />
              {/key}
            {:else if docLoading}
              <div class="blank">
                <span class="eyebrow">opening</span>
                <h2>Opening…</h2>
                <p>Loading {selected?.name ?? 'this file'}.</p>
              </div>
            {:else}
              <div class="blank">
                <div class="blank-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
                    <path d="M12 9v4" />
                    <path d="M12 17h.01" />
                  </svg>
                </div>
                <h2>Cannot open this file</h2>
                <p>{error || 'The request file could not be parsed.'}</p>
                <div class="blank-actions">
                  <button onclick={reloadFromDisk}>Retry</button>
                </div>
              </div>
            {/if}
          {/if}
        </div>
        <div class="tab-panel" hidden={tab !== 'report'}>
          {#if !result}
            <div class="blank">
            <img class="blank-logo" src="/logo.png" alt="kilhook" />
            <span class="eyebrow">no run yet</span>
            <h2>Send the first request</h2>
            <p>
              {selected
                ? `${selected.name} is ready. Run sends it, validates the response against its OpenAPI spec, fuzzes the declared targets and diffs against the stored baseline.`
                : 'Pick a .kh file on the left, or point the workspace box at a folder that has one.'}
            </p>
            <div class="blank-actions">
              <button class="primary" onclick={run} disabled={!canRun(selected, running)}>Run loop</button>
              <button onclick={createFile} disabled={running}>+ New request</button>
            </div>
          </div>
        {:else}
          <section class="hero {clean ? 'is-clean' : 'is-issues'}">
            <div class="hero-top">
              <span class="eyebrow">{fmtWhen(result.generated) || 'run result'}</span>
              <span class="eyebrow">{result.tool} · v{result.version}</span>
            </div>

            <div class="hero-main">
              <div class="hero-verdict">
                <h1>{clean ? 'Clean' : 'Needs attention'}</h1>
                <p class="hero-note">{verdictNote}</p>
              </div>
              <div class="hero-status">
                <span class="status-num {statusTone(result.response?.status)}">{result.response?.status ?? '—'}</span>
                <span class="status-label">status</span>
              </div>
            </div>

            <div class="hero-target">
              <span class="method {methodClass(result.request?.method)}">{result.request?.method}</span>
              <span class="url" title={result.request?.url}>{shortURL(result.request?.url)}</span>
            </div>

            <div class="metrics">
              <div class="metric">
                <span class="m-label">Findings</span>
                <span class="m-value {findings.length ? 'tone-warn' : ''}">{findings.length}</span>
              </div>
              <div class="metric">
                <span class="m-label">Contract</span>
                <span class="m-value {violations.length ? 'tone-bad' : ''}">
                  {result.spec ? `${violations.length}` : '—'}
                </span>
              </div>
              <div class="metric">
                <span class="m-label">Baseline</span>
                <span class="m-value">{result.diff ? changes.length : '—'}</span>
              </div>
              <div class="metric">
                <span class="m-label">Total time</span>
                <span class="m-value">{fmtMS(result.duration_ms)}</span>
              </div>
            </div>
          </section>

          <section class="sheet">
            <div class="sheet-row">
              <div class="sheet-lbl"><span class="num">{nums.response}</span>Response</div>
              <div class="cell">
                <div class="facts">
                  <div class="fact">
                    <span>status</span>
                    <b class={statusTone(result.response?.status)}>{result.response?.status ?? '—'}</b>
                  </div>
                  <div class="fact">
                    <span>time</span>
                    <b>{fmtMS(result.response?.duration_ms)}</b>
                  </div>
                  <div class="fact">
                    <span>size</span>
                    <b>{fmtBytes(result.response?.size_bytes)}{result.response?.truncated ? ' (cut)' : ''}</b>
                  </div>
                  <div class="fact">
                    <span>type</span>
                    <b>{result.response?.content_type || '—'}</b>
                  </div>
                </div>
                {#if result.response?.body_preview}
                  <pre class="code" bind:this={responsePre}>{result.response.body_preview}</pre>
                {/if}
              </div>
            </div>

            <div class="sheet-row">
              <div class="sheet-lbl"><span class="num">{nums.contract}</span>Contract</div>
              <div class="cell">
                {#if !result.spec}
                  <p class="note">This file does not declare a spec, or the check was skipped.</p>
                {:else if violations.length === 0}
                  <p class="pass">Response matches the contract</p>
                  <div class="facts">
                    <div class="fact">
                      <span>operation</span>
                      <b>{result.spec.operation || '—'}</b>
                    </div>
                    <div class="fact">
                      <span>status rule</span>
                      <b>{result.spec.status_key || '—'}</b>
                    </div>
                    <div class="fact">
                      <span>media type</span>
                      <b>{result.spec.media_type || '—'}</b>
                    </div>
                  </div>
                {:else}
                  <ul class="list">
                    {#each violations as v}
                      <li class="violation">
                        <button
                          class="path-btn"
                          onclick={() => locateViolation(v)}
                          title="Locate this field in the response preview"
                        >{v.path}</button>
                        <span class="msg">{v.message}</span>
                        <button
                          class="mini ghost copy-violation"
                          onclick={() => copyText(violationText(v), 'violation copied')}
                          title="Copy this violation"
                          aria-label="Copy this violation"
                        >Copy</button>
                      </li>
                    {/each}
                  </ul>
                {/if}
                {#if result.spec?.skipped}
                  <p class="note">{result.spec.skipped}</p>
                {/if}
              </div>
            </div>

            <div class="sheet-row">
              <div class="sheet-lbl"><span class="num">{nums.fuzz}</span>Fuzzing</div>
              <div class="cell">
                {#if !result.fuzz}
                  <p class="note">Fuzzing was skipped for this run.</p>
                {:else}
                  <div class="facts">
                    <div class="fact">
                      <span>requests</span>
                      <b>{result.fuzz.requests}</b>
                    </div>
                    <div class="fact">
                      <span>skipped</span>
                      <b>{result.fuzz.skipped}</b>
                    </div>
                    <div class="fact">
                      <span>errors</span>
                      <b class={result.fuzz.transport_errors ? 'tone-warn' : ''}>{result.fuzz.transport_errors ?? 0}</b>
                    </div>
                    <div class="fact">
                      <span>duration</span>
                      <b>{fmtMS(result.fuzz.duration_ms)}</b>
                    </div>
                    <div class="fact">
                      <span>rate</span>
                      <b>{result.fuzz.rate_limit ? `${result.fuzz.rate_limit}/s` : '—'}</b>
                    </div>
                  </div>

                  {#if findings.length > 0}
                    <div class="sevbar" aria-hidden="true">
                      <span class="sb-high" style="width:{sevPct(sevCounts.high)}%"></span>
                      <span class="sb-medium" style="width:{sevPct(sevCounts.medium)}%"></span>
                      <span class="sb-low" style="width:{sevPct(sevCounts.low)}%"></span>
                    </div>
                    <div class="sevbar-legend">
                      <span><i class="dot-high"></i>{sevCounts.high} high</span>
                      <span><i class="dot-medium"></i>{sevCounts.medium} medium</span>
                      <span><i class="dot-low"></i>{sevCounts.low} low</span>
                    </div>
                  {/if}

                  {#if findings.length > 0}
                    <table class="findings">
                      <thead>
                        <tr><th>Severity</th><th>Kind</th><th>Target</th><th>Evidence</th><th class="hits">Hits</th><th>Copy</th></tr>
                      </thead>
                      <tbody>
                        {#each findings as f}
                          <tr>
                            <td><span class="sev sev-{f.severity}">{f.severity}</span></td>
                            <td class="kind">{f.kind}</td>
                            <td class="target">{f.target}</td>
                            <td class="evidence">
                              {#if f.status_code}
                                <span class="t-code">{f.status_code}{#if f.baseline_status} ← {f.baseline_status}{/if}</span>
                              {/if}
                              {f.evidence}
                            </td>
                            <td class="hits">{f.count || 1}</td>
                            <td class="copy">
                              <button
                                class="mini ghost copy-finding"
                                onclick={() => copyText(findingText(f), 'finding copied')}
                                title="Copy this finding"
                                aria-label="Copy this finding"
                              >Copy</button>
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  {:else}
                    <p class="pass">No findings — every declared target survived the payload set</p>
                  {/if}

                  {#if result.fuzz.aborted}
                    <p class="note">aborted: {result.fuzz.aborted}</p>
                  {/if}

                  {#if advisory.length > 0}
                    <div class="group-label">Advisory</div>
                    <ul class="list">
                      {#each advisory as a}
                        <li>
                          <span class="sev sev-advisory">advisory</span>
                          <span class="target">{a.target}</span>
                          <span class="note">{a.evidence}</span>
                        </li>
                      {/each}
                    </ul>
                  {/if}
                {/if}
              </div>
            </div>

            {#if result.diff}
              <div class="sheet-row">
                <div class="sheet-lbl"><span class="num">{nums.diff}</span>Baseline</div>
                <div class="cell">
                  {#if changes.length === 0}
                    <p class="pass">No changes against the baseline</p>
                  {:else}
                    <div class="changes">
                      {#each changes as c}
                        <div class="change {c.kind}">
                          <span class="mark">{c.kind === 'added' ? '+' : c.kind === 'removed' ? '−' : '~'}</span>
                          <span class="mono">{c.path}</span>
                          <span class="val">
                            {#if c.kind === 'added'}
                              {c.after}
                            {:else if c.kind === 'removed'}
                              {c.before}
                            {:else}
                              {c.before} → {c.after}
                            {/if}
                          </span>
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>
            {/if}

            {#if warnings.length > 0}
              <div class="sheet-row">
                <div class="sheet-lbl"><span class="num">{nums.notices}</span>Notices</div>
                <div class="cell">
                  <ul class="warns">
                    {#each warnings as w}
                      <li>{w}</li>
                    {/each}
                  </ul>
                </div>
              </div>
            {/if}

            <div class="sheet-foot">
              <span>{result.diff?.baseline_file || result.spec?.source || result.request?.file || ''}</span>
              <span>{fmtWhen(result.generated)}</span>
            </div>
          </section>
        {/if}
      </div>
      </div>
    </main>
  </div>

  <footer class="statusbar">
    <span class="sb-path">
      <span class="status-dot {running ? 'is-run' : result ? (clean ? 'is-ok' : 'is-bad') : ''}"></span>
      <span class="sb-text">{selected?.path ?? 'no request selected'}</span>
    </span>
    {#if result}
      <span class="sb-verdict {clean ? 'tone-good' : 'tone-bad'}">{clean ? 'clean' : 'needs attention'}</span>
    {/if}
    <span>
      {#if result}
        <button class="has-ico" onclick={saveHTML} disabled={!html}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v11" /><path d="m7.5 10 4.5 4.5L16.5 10" /><path d="M4 20h16" /></svg>
          Save HTML report
        </button>
      {/if}
      <span>exit <span class="exit-code">{result?.exit_code ?? '—'}</span></span>
    </span>
  </footer>

  {#if paletteOpen}
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="palette-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closePalette()}>
      <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div class="palette-input">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></svg>
          <input
            bind:this={paletteInputEl}
            bind:value={paletteQuery}
            onkeydown={paletteKeys}
            placeholder="Jump to a request or run a command…"
            spellcheck="false"
            autocomplete="off"
            aria-label="Command palette query"
          />
          <span class="kbd">Esc</span>
        </div>
        <ul class="palette-list">
          {#each paletteItems as item, i (item.id)}
            {#if i === 0 || paletteItems[i - 1].group !== item.group}
              <li class="palette-group">{item.group}</li>
            {/if}
            <li>
              <button
                type="button"
                class="palette-item {i === paletteIndex ? 'is-active' : ''}"
                onclick={() => execPalette(item)}
                onmouseenter={() => (paletteIndex = i)}
                tabindex="-1"
              >
                {#if item.method}
                  <span class="method {methodClass(item.method)}">{item.method}</span>
                {/if}
                <span class="p-label">{item.label}</span>
                {#if item.hint}<span class="kbd">{item.hint}</span>{/if}
              </button>
            </li>
          {/each}
          {#if paletteItems.length === 0}
            <li class="palette-empty">No matches — try a request name, or “run”</li>
          {/if}
        </ul>
      </div>
    </div>
  {/if}

  {#if toast}
    <div class="toast-float" role="status">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="m8.5 12.2 2.4 2.4 4.6-5" /></svg>
      <span>{toast}</span>
    </div>
  {/if}
</div>
