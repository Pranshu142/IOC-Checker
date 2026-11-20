import { useState } from 'react';

const initial = () => (document.documentElement.classList.contains('dark') ? 'dark' : 'light');

// The class on <html> is set before first paint by the script in index.html.
export function useTheme() {
  const [theme, setTheme] = useState(initial);
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.toggle('dark', next === 'dark');
    try { localStorage.setItem('theme', next); } catch { /* storage blocked */ }
    setTheme(next);
  };
  return [theme, toggle];
}
