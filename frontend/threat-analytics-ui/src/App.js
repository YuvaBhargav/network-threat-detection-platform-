// src/App.js
import React, { useEffect, useState } from 'react';
import ThreatAnalytics from './ThreatAnalytics';
import './App.css';


function App() {
  const [theme, setTheme] = useState('dark');
  useEffect(() => {
    const cls = theme === 'light' ? 'theme-light' : 'theme-dark';
    document.body.classList.remove('theme-light', 'theme-dark');
    document.body.classList.add(cls);
  }, [theme]);
  return (
    <div className="App">
      <h1>Threat Analytics Dashboard</h1>
      <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '0 20px' }}>
        <button
          className="refresh-button"
          onClick={() => setTheme(t => (t === 'light' ? 'dark' : 'light'))}
          title="Toggle Theme"
        >
          🎨 Theme
        </button>
      </div>
      <ThreatAnalytics />
    </div>
  );
}

export default App;
