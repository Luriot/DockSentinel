import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/fraunces';
import '@fontsource-variable/ibm-plex-sans';
import App from './App.tsx';
import './styles.css';
import './theme.css';
import { applyTheme, getInitialTheme } from './theme.ts';

applyTheme(getInitialTheme());

const container = document.getElementById('root');
if (!container) throw new Error('Root element missing');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
