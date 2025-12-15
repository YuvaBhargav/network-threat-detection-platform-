// src/App.js
import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import ThreatAnalytics from './ThreatAnalytics';
import IPAnalytics from './IPAnalytics';
import './App.css';

function Navigation({ theme, setTheme }) {
  const location = useLocation();
  
  return (
    <nav className="modern-nav">
      <div className="nav-container">
        <div className="nav-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-text">Threat Analytics</span>
        </div>
        <div className="nav-links">
          <Link 
            to="/" 
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
          >
            <span className="nav-icon">📊</span>
            Dashboard
          </Link>
          <Link 
            to="/analytics" 
            className={`nav-link ${location.pathname.startsWith('/analytics') ? 'active' : ''}`}
          >
            <span className="nav-icon">🔍</span>
            IP Analytics
          </Link>
        </div>
        <div className="nav-actions">
          <button
            className="theme-toggle"
            onClick={() => setTheme(t => (t === 'light' ? 'dark' : 'light'))}
            title="Toggle Theme"
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </div>
      </div>
    </nav>
  );
}

function AppContent() {
  const [theme, setTheme] = useState('dark');
  
  useEffect(() => {
    const cls = theme === 'light' ? 'theme-light' : 'theme-dark';
    document.body.classList.remove('theme-light', 'theme-dark');
    document.body.classList.add(cls);
  }, [theme]);

  return (
    <div className="App">
      <Navigation theme={theme} setTheme={setTheme} />
      <Routes>
        <Route path="/" element={<ThreatAnalytics />} />
        <Route path="/analytics/ip/:ip" element={<IPAnalytics />} />
      </Routes>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;
