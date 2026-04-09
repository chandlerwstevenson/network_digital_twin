const test = require('node:test');
const assert = require('node:assert/strict');
const ThemeUi = require('./theme_ui.js');

function makeDoc() {
  const attrs = {};
  const nodes = {
    themeMode: { value: '' },
    themeStatus: { textContent: '' },
  };
  return {
    documentElement: {
      setAttribute(name, value) {
        attrs[name] = value;
      },
    },
    getElementById(id) {
      return nodes[id] || null;
    },
    attrs,
    nodes,
  };
}

test('resolveTheme honors explicit preference', () => {
  assert.equal(ThemeUi.resolveTheme('dark', false), 'dark');
  assert.equal(ThemeUi.resolveTheme('light', true), 'light');
});

test('resolveTheme falls back to system preference for auto', () => {
  assert.equal(ThemeUi.resolveTheme('auto', true), 'dark');
  assert.equal(ThemeUi.resolveTheme('auto', false), 'light');
});

test('applyThemePreference updates dataset, select, and status copy', () => {
  const doc = makeDoc();
  const result = ThemeUi.applyThemePreference(doc, 'auto', { prefersDark: false });

  assert.equal(doc.attrs['data-theme'], 'light');
  assert.equal(doc.nodes.themeMode.value, 'auto');
  assert.match(doc.nodes.themeStatus.textContent, /follows this device automatically/i);
  assert.equal(result.resolvedTheme, 'light');
});

test('stored theme preference is sanitized', () => {
  const storage = {
    getItem() {
      return 'neon';
    },
  };
  assert.equal(ThemeUi.getStoredThemePreference(storage), 'auto');
});
