import { describe, expect, it } from 'vitest';
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
  pickSelection,
  refreshSelected,
  selectionUnchanged,
  severityCounts,
  severityPct,
  shortURL,
  statusTone,
  violationText,
} from './logic.js';

describe('workspace selection', () => {
  const files = [{ path: 'a.kh' }, { path: 'b.kh' }];

  it('keeps the selected file by identity when it still exists', () => {
    const selected = { path: 'b.kh' };
    expect(pickSelection(files, selected)).toBe(selected);
  });

  it('falls back to the first file when the selection vanished', () => {
    expect(pickSelection(files, { path: 'gone.kh' })).toBe(files[0]);
    expect(pickSelection(files, null)).toBe(files[0]);
    expect(pickSelection([], { path: 'a.kh' })).toBeNull();
  });

  it('refreshes stale Workfile metadata after a save', () => {
    const stale = { path: 'b.kh', method: 'GET' };
    const freshFiles = [{ path: 'a.kh', method: 'GET' }, { path: 'b.kh', method: 'DELETE' }];
    const { next, refreshOnly } = refreshSelected(freshFiles, stale);
    // The old object must not survive: a stale method bypasses the typed
    // unsafe-method confirmation on the next Run.
    expect(next).toBe(freshFiles[1]);
    expect(next.method).toBe('DELETE');
    expect(refreshOnly).toBe(true);
    // A vanished file still falls back to the first entry.
    const gone = refreshSelected(freshFiles, { path: 'gone.kh' });
    expect(gone.next).toBe(freshFiles[0]);
    expect(gone.refreshOnly).toBe(false);
  });

  it('only sends an env name that has a backing file', () => {
    expect(envForRun('dev', ['dev', 'prod'])).toBe('dev');
    expect(envForRun('typo', ['dev'])).toBe('');
    expect(envForRun('dev', undefined)).toBe('');
  });

  it('keeps an async save/run bound to the file it started on', () => {
    expect(selectionUnchanged('a.kh', 'a.kh')).toBe(true);
    expect(selectionUnchanged('a.kh', 'b.kh')).toBe(false);
    expect(selectionUnchanged('', 'b.kh')).toBe(true);
    expect(selectionUnchanged(undefined, 'b.kh')).toBe(true);
  });

  it('blocks Run for a missing, running or broken selection', () => {
    expect(canRun({ path: 'a.kh' }, false)).toBe(true);
    expect(canRun(null, false)).toBe(false);
    expect(canRun({ path: 'a.kh' }, true)).toBe(false);
    expect(canRun({ path: 'a.kh', error: 'cannot parse' }, false)).toBe(false);
  });
});

describe('write-method guard', () => {
  it('flags methods that can change server state', () => {
    for (const m of ['POST', 'put', 'Patch', 'delete']) expect(isUnsafeMethod(m)).toBe(true);
    for (const m of ['GET', 'HEAD', 'OPTIONS', '', null]) expect(isUnsafeMethod(m)).toBe(false);
  });
});

describe('palette filtering', () => {
  const items = [
    { id: '1', label: 'Run loop', text: 'run loop start send execute', group: 'Actions' },
    { id: '2', label: 'Reload workspace', text: 'reload workspace refresh', group: 'Actions' },
    { id: '3', label: 'Get Pet', text: 'get pet open request jump go', group: 'Requests', method: 'GET' },
  ];

  it('returns the original order for an empty query', () => {
    expect(filterPalette(items, '  ')).toBe(items);
  });

  it('ranks a label prefix above a substring and a keyword hit', () => {
    const got = filterPalette(items, 'run');
    expect(got[0].id).toBe('1');
  });

  it('matches keywords and request names', () => {
    expect(filterPalette(items, 'pet').map((i) => i.id)).toEqual(['3']);
    expect(filterPalette(items, 'refresh').map((i) => i.id)).toEqual(['2']);
    expect(filterPalette(items, 'nothing')).toEqual([]);
  });
});

describe('report formatting', () => {
  it('counts only real severities and computes percentages', () => {
    const counts = severityCounts([
      { severity: 'high' },
      { severity: 'HIGH' },
      { severity: 'low' },
      { severity: 'advisory' },
      { severity: null },
    ]);
    expect(counts).toEqual({ high: 2, medium: 0, low: 1 });
    expect(severityPct(counts, counts.high)).toBe(67);
    expect(severityPct({ high: 0, medium: 0, low: 0 }, 0)).toBe(0);
  });

  it('formats durations and sizes without lying about null', () => {
    expect(fmtMS(null)).toBe('—');
    expect(fmtMS(42)).toBe('42ms');
    expect(fmtMS(1500)).toBe('1.5s');
    expect(fmtBytes(null)).toBe('—');
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(2048)).toBe('2.0 kB');
    expect(fmtBytes(2 * 1024 * 1024)).toBe('2.0 MB');
  });

  it('labels methods and status codes', () => {
    expect(methodClass('GET')).toBe('m-get');
    expect(methodClass(null)).toBe('m-');
    expect(statusTone(200)).toBe('tone-good');
    expect(statusTone(302)).toBe('tone-info');
    expect(statusTone(404)).toBe('tone-warn');
    expect(statusTone(500)).toBe('tone-bad');
    expect(statusTone(0)).toBe('');
    expect(shortURL('https://example.test/x')).toBe('example.test/x');
    expect(shortURL(null)).toBe('');
  });

  it('renders no timestamp for missing or invalid dates', () => {
    expect(fmtWhen('')).toBe('');
    expect(fmtWhen('not-a-date')).toBe('');
  });
});

describe('clipboard text and JSON paths', () => {
  it('renders a finding as a portable text block', () => {
    const text = findingText({
      severity: 'high',
      kind: 'status_anomaly',
      target: 'path.1',
      payload: "' OR 1=1--",
      status_code: 500,
      baseline_status: 200,
      count: 8,
      evidence: 'baseline 200 -> 500',
    });
    expect(text).toContain('[high] status_anomaly | path.1');
    expect(text).toContain("payload: ' OR 1=1--");
    expect(text).toContain('status: 500 (baseline 200)');
    expect(text).toContain('hits: 8');
    expect(text).toContain('evidence: baseline 200 -> 500');
  });

  it('renders a violation with its operation and status', () => {
    const text = violationText({
      path: 'response.id',
      message: "must have required property 'id'",
      operation: 'GET /pets/{id}',
      status: 200,
    });
    expect(text).toBe(
      ['path: response.id', "message: must have required property 'id'", 'operation: GET /pets/{id}', 'status: 200'].join(
        '\n',
      ),
    );
  });

  it('extracts the field a JSON path points at', () => {
    expect(lastPathKey('response.users[3].email')).toBe('email');
    expect(lastPathKey('response.items[0]')).toBe('items');
    expect(lastPathKey('response[0].id')).toBe('id');
    expect(lastPathKey('response.id')).toBe('id');
    expect(lastPathKey('response')).toBe('');
    expect(lastPathKey('')).toBe('');
  });
});
