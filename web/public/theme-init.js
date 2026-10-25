(() => {
  try {
    const stored = localStorage.getItem('docksentinel.theme');
    document.documentElement.dataset.theme = stored === 'light' ? 'light' : 'dark';
  } catch {
    document.documentElement.dataset.theme = 'dark';
  }
})();
