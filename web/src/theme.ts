export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'docksentinel.theme';

export function getInitialTheme(): Theme {
  try {
    return localStorage.getItem(STORAGE_KEY) === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute('content', theme === 'light' ? '#f4f0e6' : '#14171c');
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* Storage can be unavailable (private mode); the in-memory choice still applies. */
  }
}
