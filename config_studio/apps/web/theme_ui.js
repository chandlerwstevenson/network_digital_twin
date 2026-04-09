(function (global) {
  const STORAGE_KEY = 'configStudio.themePreference';

  function getStoredThemePreference(storage) {
    try {
      const value = storage?.getItem?.(STORAGE_KEY);
      return ['auto', 'dark', 'light'].includes(value) ? value : 'auto';
    } catch {
      return 'auto';
    }
  }

  function persistThemePreference(storage, preference) {
    try {
      if (!storage?.setItem) return;
      storage.setItem(STORAGE_KEY, ['auto', 'dark', 'light'].includes(preference) ? preference : 'auto');
    } catch {
      // ignore storage failures in restricted browser contexts
    }
  }

  function resolveTheme(preference = 'auto', prefersDark = true) {
    if (preference === 'dark' || preference === 'light') return preference;
    return prefersDark ? 'dark' : 'light';
  }

  function getThemeStatusText(preference = 'auto', resolvedTheme = 'dark') {
    if (preference === 'auto') {
      return `Theme follows this device automatically (${resolvedTheme} active).`;
    }
    return `${resolvedTheme === 'dark' ? 'Dark' : 'Light'} theme is locked for this browser.`;
  }

  function applyThemePreference(doc, preference = 'auto', options = {}) {
    const prefersDark = typeof options.prefersDark === 'boolean'
      ? options.prefersDark
      : Boolean(global.matchMedia?.('(prefers-color-scheme: dark)')?.matches);
    const resolvedTheme = resolveTheme(preference, prefersDark);

    doc?.documentElement?.setAttribute?.('data-theme', resolvedTheme);

    const select = doc?.getElementById?.('themeMode');
    if (select) select.value = preference;

    const status = doc?.getElementById?.('themeStatus');
    if (status) status.textContent = getThemeStatusText(preference, resolvedTheme);

    return {
      preference,
      resolvedTheme,
      statusText: getThemeStatusText(preference, resolvedTheme),
    };
  }

  const api = {
    STORAGE_KEY,
    getStoredThemePreference,
    persistThemePreference,
    resolveTheme,
    getThemeStatusText,
    applyThemePreference,
  };

  global.ConfigStudioThemeUi = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
