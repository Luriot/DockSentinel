(() => {
  try {
    const stored = localStorage.getItem('docksentinel.theme');
    const theme = stored === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute('content', theme === 'light' ? '#f6f1e8' : '#14110e');
  } catch {
    document.documentElement.dataset.theme = 'dark';
  }
})();
