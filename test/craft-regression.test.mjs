import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const styles = readFileSync(new URL('../styles.css', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/app.mjs', import.meta.url), 'utf8');

function hexRgb(hex) {
  return [1, 3, 5].map((start) => parseInt(hex.slice(start, start + 2), 16) / 255);
}

function luminance(hex) {
  const [r, g, b] = hexRgb(hex).map((v) => v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const x = luminance(a);
  const y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

test('craft regression: section palette and controls meet contrast and touch contracts', () => {
  for (const match of styles.matchAll(/\.seg-[a-z-]+ \{ background: (#[0-9a-f]{6}); \}/g)) {
    assert.ok(contrast(match[1], '#f4f0e7') >= 4.5, match[0] + ' keeps light label text readable');
  }
  assert.match(styles, /button, select, input:not\(\[type="range"\]\), textarea \{ min-height: 44px; border: 1px solid var\(--muted\);/);
  assert.match(styles, /\.section-button \{ padding: 4px 0; min-height: 44px; min-width: 44px;/);
});

test('craft regression: print output is static, paginated and keeps section names', () => {
  assert.match(styles, /@page \{ margin: 14mm; \}/);
  const printBlock = styles.slice(styles.indexOf('@media print'));
  assert.match(printBlock, /\.skip-link, \.input-controls, \.input-bench details, \.report-controls,/);
  assert.match(printBlock, /button, input, select, textarea, summary \{ display: none !important; \}/);
  assert.match(printBlock, /\.audit-list li, \.self-test-view li, \.hex-view, pre, \.section-map, \.call-graph, tr \{ break-inside: avoid; \}/);
  assert.equal((app.match(/class="print-label"/g) || []).length, 2);
  assert.match(printBlock, /\.print-label \{ display: inline !important; \}/);
});
