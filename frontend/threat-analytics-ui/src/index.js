import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css'; // REMOVE this line or add index.css back
// import reportWebVitals from './reportWebVitals'; // REMOVE this line

import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// REMOVE or comment out this too:
// reportWebVitals();
