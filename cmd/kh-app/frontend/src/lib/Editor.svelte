<script>
  let { doc, busy, onSave, onSaveAndRun, onDiscard, dirty = $bindable(false) } = $props();

  // Editing works on a clone: the report on the other tab keeps describing the
  // file as it was when the run happened. The clone captures `doc` on mount on
  // purpose — App.svelte remounts this component (keyed) for every new doc.
  // svelte-ignore state_referenced_locally
  let form = $state(clone(doc));
  let error = $state('');
  const docJSON = $derived(JSON.stringify(doc));
  const isDirty = $derived(JSON.stringify(form) !== docJSON);

  $effect(() => {
    dirty = isDirty;
  });

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function addRow(list, field = 'name') {
    list.push(field === 'name' ? { name: '', value: '' } : '');
  }

  function removeRow(list, index) {
    list.splice(index, 1);
  }

  async function save() {
    error = '';
    try {
      await onSave(clone(form));
    } catch (e) {
      error = String(e?.message ?? e);
    }
  }

  function keydown(event) {
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 's') return;
    // The Editor stays mounted behind the palette and the typed-confirmation
    // boxes. Ctrl+S there must not silently save the request underneath.
    const target = event.target;
    const tag = (target?.tagName ?? '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable) return;
    event.preventDefault();
    if (!busy) save();
  }

  async function saveAndRun() {
    error = '';
    try {
      await onSaveAndRun(clone(form));
    } catch (e) {
      error = String(e?.message ?? e);
    }
  }

  function discard() {
    form = clone(doc);
    error = '';
    onDiscard?.();
  }

  function toggleMethod(method) {
    const i = form.fuzz.methods.indexOf(method);
    if (i >= 0) form.fuzz.methods.splice(i, 1);
    else form.fuzz.methods.push(method);
  }
</script>

<svelte:window onkeydown={keydown} />

<div class="editor">
  <div class="editor-scroll">
    {#if error}
      <div class="banner err">{error}</div>
    {/if}
    {#if doc.unknownFields?.length}
      <div class="banner warn">
        This file has fields this build does not know: {doc.unknownFields.join('; ')}. Saving rewrites the
        frontmatter and drops them.
      </div>
    {/if}

    <section class="sheet">
      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">01</span>Request</div>
        <div class="cell">
          <div class="form-grid">
            <label class="field">
              <span>name</span>
              <input bind:value={form.name} spellcheck="false" />
            </label>
            <label class="field">
              <span>method</span>
              <select bind:value={form.method} aria-label="method">
                {#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
            </label>
          </div>
          <label class="field">
            <span>url</span>
            <input bind:value={form.url} spellcheck="false" class="mono" />
          </label>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">02</span>Headers</div>
        <div class="cell">
          {#if form.headers.length === 0}
            <p class="note">No headers.</p>
          {/if}
          {#each form.headers as row, i}
            <div class="kv-row">
              <input bind:value={row.name} placeholder="name" spellcheck="false" aria-label="header name" />
              <input bind:value={row.value} placeholder="value" spellcheck="false" aria-label="header value" />
              <button class="mini ghost" onclick={() => removeRow(form.headers, i)} title="remove" aria-label="remove header">×</button>
            </div>
          {/each}
          <div>
            <button class="mini" onclick={() => addRow(form.headers)}>+ Add header</button>
          </div>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">03</span>Query</div>
        <div class="cell">
          {#if form.query.length === 0}
            <p class="note">No query parameters.</p>
          {/if}
          {#each form.query as row, i}
            <div class="kv-row">
              <input bind:value={row.name} placeholder="name" spellcheck="false" aria-label="query name" />
              <input bind:value={row.value} placeholder="value" spellcheck="false" aria-label="query value" />
              <button class="mini ghost" onclick={() => removeRow(form.query, i)} title="remove" aria-label="remove query parameter">×</button>
            </div>
          {/each}
          <div>
            <button class="mini" onclick={() => addRow(form.query)}>+ Add parameter</button>
          </div>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">04</span>Auth</div>
        <div class="cell">
          <label class="field">
            <span>type</span>
            <select bind:value={form.auth.type} aria-label="auth type">
              <option value="none">none</option>
              <option value="basic">basic</option>
              <option value="bearer">bearer</option>
              <option value="api_key">api_key</option>
            </select>
          </label>

          {#if form.auth.type === 'basic'}
            <div class="form-grid">
              <label class="field"><span>username</span><input bind:value={form.auth.username} spellcheck="false" /></label>
              <label class="field"><span>password</span><input bind:value={form.auth.password} spellcheck="false" /></label>
            </div>
          {:else if form.auth.type === 'bearer'}
            <label class="field"><span>token</span><input bind:value={form.auth.token} spellcheck="false" class="mono" /></label>
          {:else if form.auth.type === 'api_key'}
            <div class="form-grid three">
              <label class="field">
                <span>in</span>
                <select bind:value={form.auth.in} aria-label="api key location">
                  <option value="header">header</option>
                  <option value="query">query</option>
                </select>
              </label>
              <label class="field"><span>name</span><input bind:value={form.auth.name} spellcheck="false" class="mono" /></label>
              <label class="field"><span>value</span><input bind:value={form.auth.value} spellcheck="false" class="mono" /></label>
            </div>
          {/if}
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">05</span>Spec</div>
        <div class="cell">
          <label class="field">
            <span>source</span>
            <input bind:value={form.spec.source} placeholder="../openapi.yaml" spellcheck="false" class="mono" />
          </label>
          <div class="form-grid">
            <label class="field">
              <span>operation</span>
              <input bind:value={form.spec.operation} placeholder={"/pets/{id} get"} spellcheck="false" class="mono" />
            </label>
            <label class="field">
              <span>baseline</span>
              <input bind:value={form.spec.baseline} placeholder=".kilhook/baselines/name.json" spellcheck="false" class="mono" />
            </label>
          </div>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">06</span>Body</div>
        <div class="cell">
          <textarea class="body-input" bind:value={form.body} spellcheck="false" rows="8" aria-label="request body"
          ></textarea>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">07</span>Fuzzing</div>
        <div class="cell">
          {#if form.fuzz.targets.length === 0}
            <p class="note">No targets — the fuzz pass will be skipped.</p>
          {/if}
          {#each form.fuzz.targets as target, i}
            <div class="kv-row single">
              <input bind:value={form.fuzz.targets[i]} placeholder="body.email" spellcheck="false" class="mono" aria-label="fuzz target" />
              <button class="mini ghost" onclick={() => removeRow(form.fuzz.targets, i)} title="remove" aria-label="remove target">×</button>
            </div>
          {/each}
          <div>
            <button class="mini" onclick={() => addRow(form.fuzz.targets, 'text')}>+ Add target</button>
          </div>

          <div class="form-grid">
            <label class="field">
              <span>wordlist</span>
              <input bind:value={form.fuzz.wordlist} placeholder="default" spellcheck="false" />
            </label>
            <div class="field">
              <span>methods</span>
              <div class="chips">
                {#each ['injection', 'boundary', 'type_confusion'] as m}
                  <button class="chip {form.fuzz.methods.includes(m) ? 'on' : ''}" onclick={() => toggleMethod(m)}>{m}</button>
                {/each}
              </div>
            </div>
          </div>

          <div class="form-grid three">
            <label class="field">
              <span>max_requests</span>
              <input type="number" min="0" bind:value={form.fuzz.maxRequests} placeholder="500" />
            </label>
            <label class="field">
              <span>rate_limit</span>
              <input type="number" min="0" step="0.5" bind:value={form.fuzz.rateLimit} placeholder="5" />
            </label>
            <label class="field">
              <span>per_host</span>
              <input type="number" min="0" bind:value={form.fuzz.perHostConcurrency} placeholder="2" />
            </label>
          </div>
        </div>
      </div>

      <div class="sheet-row">
        <div class="sheet-lbl"><span class="num">08</span>Advanced</div>
        <div class="cell">
          <div class="form-grid">
            <label class="field">
              <span>timeout_ms</span>
              <input
                type="number"
                min="0"
                value={form.timeoutMs || ''}
                placeholder="30000"
                oninput={(e) => (form.timeoutMs = Number(e.currentTarget.value) || 0)}
              />
            </label>
            <label class="switch align-end">
              <span>Follow redirects</span>
              <input type="checkbox" bind:checked={form.followRedirects} aria-label="follow redirects" />
            </label>
          </div>
        </div>
      </div>

      {#if doc.warnings?.length}
        <div class="sheet-row">
          <div class="sheet-lbl"><span class="num">09</span>Parser notes</div>
          <div class="cell">
            <ul class="warns">
              {#each doc.warnings as w}<li>{w}</li>{/each}
            </ul>
          </div>
        </div>
      {/if}
    </section>
  </div>

  <div class="editor-actions">
    <span class="path">{doc.path}</span>
    <div class="state">
      {#if isDirty}
        <span class="dirty">unsaved changes · </span>
      {/if}
      <span class="hint">format {doc.format} · run uses the saved file</span>
      <span class="kbd">Ctrl+S</span>
      <div class="actions">
        <button onclick={discard} disabled={busy || !isDirty}>Revert</button>
        <button onclick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
        <button class="primary" onclick={saveAndRun} disabled={busy || !dirty}>Save &amp; Run</button>
      </div>
    </div>
  </div>
</div>
