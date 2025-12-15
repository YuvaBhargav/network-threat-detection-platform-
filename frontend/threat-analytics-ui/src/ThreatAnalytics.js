import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, ComposedChart, Area, Brush, ReferenceLine } from 'recharts';
import './App.css';

function ThreatAnalytics() {
  const navigate = useNavigate();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    ddosCount: 0,
    portScanCount: 0,
    maliciousIpCount: 0,
    sqlInjectionCount: 0,
    recentThreats: 0
  });
  const [timelineData, setTimelineData] = useState([]);
  const [lifetimeData, setLifetimeData] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [activeSeries, setActiveSeries] = useState({
    DDoS: true,
    PortScan: true,
    Malicious: true,
    SQLInjection: true,
    Total: true
  });
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [showThreatModal, setShowThreatModal] = useState(false);
  const [alertHistory, setAlertHistory] = useState([]);
  const [showAlertHistory, setShowAlertHistory] = useState(false);
  const [alertStats, setAlertStats] = useState(null);
  const DDOS_THRESHOLD = 300;
  const PORTSCAN_THRESHOLD = 10;

  // Calculate statistics from threat data - memoized
  const calculateStats = useCallback((threatData) => {
    const now = new Date();
    const last24Hours = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    
    return {
      total: threatData.length,
      ddosCount: threatData.filter(t => t.threatType && t.threatType.includes('DDoS')).length,
      portScanCount: threatData.filter(t => t.threatType && t.threatType.includes('Port Scan')).length,
      maliciousIpCount: threatData.filter(t => t.threatType && t.threatType.includes('Malicious')).length,
      sqlInjectionCount: threatData.filter(t => t.threatType && t.threatType.includes('SQL Injection')).length,
      recentThreats: threatData.filter(t => new Date(t.timestamp) > last24Hours).length
    };
  }, []);

  // Process timeline data for the graph - memoized
  const processTimelineData = useCallback((threatData) => {
    // Group threats by hour
    const last24Hours = new Date(new Date().getTime() - (24 * 60 * 60 * 1000));
    const recentThreats = threatData.filter(t => new Date(t.timestamp) > last24Hours);
    
    // Create hourly buckets for the last 24 hours
    const hourlyData = [];
    for (let i = 0; i < 24; i++) {
      const hourDate = new Date(new Date().getTime() - (i * 60 * 60 * 1000));
      const hour = hourDate.getHours();
      
      // Count threats in this hour
      const hourStart = new Date(hourDate);
      hourStart.setMinutes(0, 0, 0);
      const hourEnd = new Date(hourDate);
      hourEnd.setMinutes(59, 59, 999);
      
      const ddosCount = recentThreats.filter(t => 
        t.threatType && t.threatType.includes('DDoS') && 
        new Date(t.timestamp) >= hourStart && 
        new Date(t.timestamp) <= hourEnd
      ).length;
      
      const portScanCount = recentThreats.filter(t => 
        t.threatType && t.threatType.includes('Port Scan') && 
        new Date(t.timestamp) >= hourStart && 
        new Date(t.timestamp) <= hourEnd
      ).length;
      
      const maliciousCount = recentThreats.filter(t => 
        t.threatType && t.threatType.includes('Malicious') && 
        new Date(t.timestamp) >= hourStart && 
        new Date(t.timestamp) <= hourEnd
      ).length;
      
      const sqlInjectionCount = recentThreats.filter(t => 
        t.threatType && t.threatType.includes('SQL Injection') && 
        new Date(t.timestamp) >= hourStart && 
        new Date(t.timestamp) <= hourEnd
      ).length;
      
      hourlyData.unshift({
        hour: `${hour}:00`,
        DDoS: ddosCount,
        PortScan: portScanCount,
        Malicious: maliciousCount,
        SQLInjection: sqlInjectionCount,
        Total: ddosCount + portScanCount + maliciousCount + sqlInjectionCount
      });
    }
    
    return hourlyData;
  }, []);

  // Process lifetime data for the bar graph - memoized
  const processLifetimeData = useCallback((threatData) => {
    // Group threats by day for the last 30 days
    const last30Days = new Date(new Date().getTime() - (30 * 24 * 60 * 60 * 1000));
    const recentThreats = threatData.filter(t => new Date(t.timestamp) > last30Days);
    
    // Create daily buckets
    const dailyData = [];
    for (let i = 0; i < 30; i++) {
      const date = new Date(new Date().getTime() - (i * 24 * 60 * 60 * 1000));
      const day = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      
      // Count threats on this day
      const dayStart = new Date(date);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(date);
      dayEnd.setHours(23, 59, 59, 999);
      
      const count = recentThreats.filter(t => 
        new Date(t.timestamp) >= dayStart && 
        new Date(t.timestamp) <= dayEnd
      ).length;
      
      dailyData.unshift({
        day,
        count
      });
    }
    
    return dailyData;
  }, []);

  // Get threat severity level
  const getThreatSeverity = (threatType) => {
    if (!threatType) return 'low';
    if (threatType.includes('DDoS')) return 'high';
    if (threatType.includes('Port Scan')) return 'medium';
    if (threatType.includes('Malicious')) return 'high';
    if (threatType.includes('SQL Injection')) return 'high';
    if (threatType.includes('XSS')) return 'medium';
    return 'low';
  };

  // Get threat class for styling
  const getThreatClass = (threatType) => {
    if (!threatType) return '';
    if (threatType.includes('DDoS')) return 'threat-ddos';
    if (threatType.includes('Port Scan')) return 'threat-portscan';
    if (threatType.includes('Malicious')) return 'threat-malicious';
    if (threatType.includes('SQL Injection')) return 'threat-sqli';
    return '';
  };

  // Filter threats based on search term and threat type filter - memoized
  const filteredThreats = useMemo(() => {
    return threats.filter(threat => {
      // Search term filter
      const searchMatch = 
        (threat.sourceIP && threat.sourceIP.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (threat.destinationIP && threat.destinationIP.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (threat.threatType && threat.threatType.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (threat.ports && threat.ports.toString().includes(searchTerm.toLowerCase()));
      
      // Threat type filter
      const typeMatch = 
        threatTypeFilter === 'all' || 
        (threat.threatType && threat.threatType.includes(threatTypeFilter));
      
      return searchMatch && typeMatch;
    });
  }, [threats, searchTerm, threatTypeFilter]);

  // Memoize reversed threats to avoid unnecessary reversals on each render
  const reversedFilteredThreats = useMemo(() => {
    return [...filteredThreats].reverse();
  }, [filteredThreats]);
  
  const sortedThreats = useMemo(() => {
    const data = [...reversedFilteredThreats];
    const { key, direction } = sortConfig || {};
    const dir = direction === 'asc' ? 1 : -1;
    return data.sort((a, b) => {
      const av = a[key];
      const bv = b[key];
      if (key === 'timestamp') {
        const at = new Date(av).getTime() || 0;
        const bt = new Date(bv).getTime() || 0;
        return (at - bt) * dir;
      }
      if (key === 'ports') {
        const as = String(av ?? '');
        const bs = String(bv ?? '');
        return as.localeCompare(bs) * dir;
      }
      const as = String(av ?? '').toLowerCase();
      const bs = String(bv ?? '').toLowerCase();
      if (as < bs) return -1 * dir;
      if (as > bs) return 1 * dir;
      return 0;
    });
  }, [reversedFilteredThreats, sortConfig]);
  
  const totalPages = useMemo(() => Math.max(1, Math.ceil(sortedThreats.length / pageSize)), [sortedThreats, pageSize]);
  const paginatedThreats = useMemo(() => {
    const start = (page - 1) * pageSize;
    return sortedThreats.slice(start, start + pageSize);
  }, [sortedThreats, page, pageSize]);
  
  const isLive = useMemo(() => {
    if (!lastUpdate) return false;
    return Date.now() - lastUpdate < 5000;
  }, [lastUpdate]);
  
  const handleSort = useCallback((key) => {
    setSortConfig(prev => {
      if (prev.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { key, direction: 'asc' };
    });
    setPage(1);
  }, []);

  // Export threats as CSV
  const exportToCSV = useCallback(() => {
    const headers = ['Timestamp', 'Threat Type', 'Source IP', 'Destination IP', 'Ports'];
    
    const csvContent = [
      headers.join(','),
      ...filteredThreats.map(threat => [
        threat.timestamp,
        threat.threatType,
        threat.sourceIP,
        threat.destinationIP,
        threat.ports
      ].join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `threat-report-${new Date().toISOString().slice(0,10)}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url); // Clean up to avoid memory leaks
  }, [filteredThreats]);

  // Export threats as JSON
  const exportToJSON = useCallback(() => {
    fetch('http://localhost:5000/api/threats/export?format=json')
      .then(response => response.json())
      .then(data => {
        const jsonContent = JSON.stringify(data, null, 2);
        const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `threat-report-${new Date().toISOString().slice(0,10)}.json`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      })
      .catch(error => {
        console.error('Error exporting JSON:', error);
        alert('Failed to export JSON. Please try again.');
      });
  }, []);

  // Fetch alert history
  const fetchAlertHistory = useCallback(() => {
    fetch('http://localhost:5000/api/alerts?limit=100')
      .then(response => response.json())
      .then(data => {
        setAlertHistory(data);
      })
      .catch(error => {
        console.error('Error fetching alert history:', error);
      });
  }, []);

  const fetchAlertStats = useCallback(() => {
    fetch('http://localhost:5000/api/alerts/stats')
      .then(response => response.json())
      .then(data => {
        setAlertStats(data);
      })
      .catch(() => {});
  }, []);

  // Open threat details modal
  const openThreatDetails = useCallback((threat) => {
    setSelectedThreat(threat);
    setShowThreatModal(true);
  }, []);

  // Close threat details modal
  const closeThreatModal = useCallback(() => {
    setShowThreatModal(false);
    setSelectedThreat(null);
  }, []);

  // Colors for pie chart
  const COLORS = ['#ff5252', '#ffb74d', '#9575cd', '#4db6ac', '#f06292'];
  
  // Define fetchThreats function
  const fetchThreats = useCallback(() => {
    setIsLoading(true);
    setError(null);
    
    fetch('http://localhost:5000/api/threats', {
      method: 'GET',
      mode: 'cors',
      cache: 'no-cache'
    })
      .then(response => {
        if (!response.ok) {
          return response.json().then(err => {
            throw new Error(err.error || `HTTP error! Status: ${response.status}`);
          }).catch(() => {
            throw new Error(`HTTP error! Status: ${response.status}. Make sure the backend server is running on http://localhost:5000`);
          });
        }
        return response.json();
      })
      .then(data => {
        // Handle both array and object responses
        const threatsArray = Array.isArray(data) ? data : (data.threats || []);
        setThreats(threatsArray);
        setStats(calculateStats(threatsArray));
        setTimelineData(processTimelineData(threatsArray));
        setLifetimeData(processLifetimeData(threatsArray));
        setIsLoading(false);
      })
      .catch(error => {
        console.error('Error fetching threats:', error);
        let errorMessage = 'Failed to load threat data. ';
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
          errorMessage += 'Cannot connect to backend server. Please make sure the Flask server is running on http://localhost:5000';
        } else {
          errorMessage += error.message || 'Please try again later.';
        }
        setError(errorMessage);
        setIsLoading(false);
      });
  }, [calculateStats, processTimelineData, processLifetimeData]);
  
  // Fetch initial threats and alert history
  useEffect(() => {
    fetchThreats();
    fetchAlertHistory();
    fetchAlertStats();
  }, [fetchThreats, fetchAlertHistory, fetchAlertStats]);

  // Set up event source for real-time updates
  const sseRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const setupSSE = useCallback(() => {
    if (sseRef.current) {
      try { sseRef.current.close(); } catch (e) {}
      sseRef.current = null;
    }
    const es = new EventSource('http://localhost:5000/api/threats/stream');
    es.onmessage = (event) => {
      try {
        const newThreat = JSON.parse(event.data);
        setLastUpdate(Date.now());
        setThreats(prev => {
          const updatedThreats = [...prev, newThreat];
          setStats(calculateStats(updatedThreats));
          setTimelineData(processTimelineData(updatedThreats));
          setLifetimeData(processLifetimeData(updatedThreats));
          return updatedThreats;
        });
      } catch (error) {}
    };
    es.onerror = () => {
      try { es.close(); } catch (e) {}
      if (!reconnectTimerRef.current) {
        reconnectTimerRef.current = setTimeout(() => {
          reconnectTimerRef.current = null;
          setupSSE();
          fetchThreats();
        }, 5000);
      }
    };
    sseRef.current = es;
  }, [calculateStats, processTimelineData, processLifetimeData, fetchThreats]);
  useEffect(() => {
    setupSSE();
    return () => {
      if (sseRef.current) {
        try { sseRef.current.close(); } catch (e) {}
        sseRef.current = null;
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };
  }, [setupSSE]);
  
  const pieData = useMemo(() => ([
    { name: 'DDoS', value: stats.ddosCount },
    { name: 'Port Scan', value: stats.portScanCount },
    { name: 'Malicious', value: stats.maliciousIpCount },
    { name: 'SQL Injection', value: stats.sqlInjectionCount }
  ]), [stats]);
  
  const toggleSeries = useCallback((key) => {
    setActiveSeries(prev => ({ ...prev, [key]: !prev[key] }));
  }, []);

  if (isLoading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading threat data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <div className="error-content">
          <h2>⚠️ Connection Error</h2>
          <p>{error}</p>
          <div className="error-help">
            <h3>To fix this issue:</h3>
            <ol>
              <li>Make sure the backend Flask server is running</li>
              <li>Open a terminal and navigate to: <code>backend/api</code></li>
              <li>Run: <code>python server.py</code></li>
              <li>The server should start on <code>http://localhost:5000</code></li>
            </ol>
          </div>
          <button onClick={fetchThreats} className="retry-button">🔄 Retry Connection</button>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Network Security Dashboard</h1>
        <div className="header-actions">
          <div className="last-updated">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
          <div className={`live-badge ${isLive ? 'live' : 'idle'}`}>
            ● {isLive ? 'Live' : 'Idle'}
          </div>
          <button onClick={fetchThreats} className="refresh-button">
            🔄 Refresh Data
          </button>
        </div>
      </div>

      <div className="stats-container">
        <div className="stat-card">
          <div className="stat-icon">🛡️</div>
          <div className="stat-content">
            <h3>Total Threats</h3>
            <p className="stat-value">{stats.total}</p>
          </div>
        </div>
        
        <div className="stat-card ddos">
          <div className="stat-icon">🔥</div>
          <div className="stat-content">
            <h3>DDoS Attacks</h3>
            <p className="stat-value">{stats.ddosCount}</p>
          </div>
        </div>
        
        <div className="stat-card portscan">
          <div className="stat-icon">🔍</div>
          <div className="stat-content">
            <h3>Port Scans</h3>
            <p className="stat-value">{stats.portScanCount}</p>
          </div>
        </div>
        
        <div className="stat-card malicious">
          <div className="stat-icon">⚠️</div>
          <div className="stat-content">
            <h3>Malicious IPs</h3>
            <p className="stat-value">{stats.maliciousIpCount}</p>
          </div>
        </div>
        
        <div className="stat-card sqli">
          <div className="stat-icon">🧪</div>
          <div className="stat-content">
            <h3>SQL Injection</h3>
            <p className="stat-value">{stats.sqlInjectionCount}</p>
          </div>
        </div>
        
        <div className="stat-card recent">
          <div className="stat-icon">⏱️</div>
          <div className="stat-content">
            <h3>Last 24h</h3>
            <p className="stat-value">{stats.recentThreats}</p>
          </div>
        </div>
      </div>

      {alertStats && (
        <div className="stats-container">
          <div className="stat-card">
            <div className="stat-icon">📣</div>
            <div className="stat-content">
              <h3>Total Alerts</h3>
              <p className="stat-value">{alertStats.total}</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">⏳</div>
            <div className="stat-content">
              <h3>Alerts in 24h</h3>
              <p className="stat-value">{alertStats.recent_24h}</p>
            </div>
          </div>
        </div>
      )}

      <div className="filters-container">
        <input
          className="search-input"
          type="text"
          placeholder="Search IPs, type, ports"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <select
          className="filter-select threat-filter"
          value={threatTypeFilter}
          onChange={(e) => setThreatTypeFilter(e.target.value)}
        >
          <option value="all">All</option>
          <option value="DDoS">DDoS</option>
          <option value="Port Scan">Port Scan</option>
          <option value="Malicious">Malicious</option>
          <option value="SQL Injection">SQL Injection</option>
          <option value="XSS">XSS</option>
        </select>
      </div>

      <div className="threats-table">
        <div className="table-header">
          <h2>Top Offender IPs</h2>
        </div>
        <div className="table-container">
          <table className="styled-table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Threat Count</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(threats.reduce((acc, t) => {
                const ip = t.sourceIP;
                if (!ip || ip === 'N/A') return acc;
                acc[ip] = (acc[ip] || 0) + 1;
                return acc;
              }, {}))
                .map(([addr, count]) => ({ addr, count }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 5)
                .map((row, idx) => (
                  <tr key={idx} onClick={() => navigate(`/analytics/ip/${encodeURIComponent(row.addr)}`)} style={{ cursor: 'pointer' }}>
                    <td>{row.addr}</td>
                    <td>{row.count}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="charts-container">
        <div className="lifetime-container">
          <h2>Threat Activity Timeline</h2>
          <div className="series-toggle">
            <button className={`series-btn ${activeSeries.DDoS ? 'active ddos' : ''}`} onClick={() => toggleSeries('DDoS')}>DDoS</button>
            <button className={`series-btn ${activeSeries.PortScan ? 'active portscan' : ''}`} onClick={() => toggleSeries('PortScan')}>Port Scan</button>
            <button className={`series-btn ${activeSeries.Malicious ? 'active malicious' : ''}`} onClick={() => toggleSeries('Malicious')}>Malicious</button>
            <button className={`series-btn ${activeSeries.SQLInjection ? 'active sqli' : ''}`} onClick={() => toggleSeries('SQLInjection')}>SQL Injection</button>
            <button className={`series-btn ${activeSeries.Total ? 'active total' : ''}`} onClick={() => toggleSeries('Total')}>Total</button>
          </div>
          <ResponsiveContainer width="100%" height={320}>
            <ComposedChart data={timelineData}>
              <defs>
                <linearGradient id="totalGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#4fc3f7" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#4fc3f7" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#34495e" />
              <XAxis dataKey="hour" tick={{ fill: '#bbb' }} />
              <YAxis tick={{ fill: '#bbb' }} />
              <Tooltip />
              <Legend />
              {activeSeries.DDoS && <Line type="monotone" dataKey="DDoS" stroke="#ff5252" dot={false} strokeWidth={2} />}
              {activeSeries.PortScan && <Line type="monotone" dataKey="PortScan" stroke="#ffb74d" dot={false} strokeWidth={2} />}
              {activeSeries.Malicious && <Line type="monotone" dataKey="Malicious" stroke="#9575cd" dot={false} strokeWidth={2} />}
              {activeSeries.SQLInjection && <Line type="monotone" dataKey="SQLInjection" name="SQL Injection" stroke="#f06292" dot={false} strokeWidth={2} />}
              {activeSeries.Total && <Area type="monotone" dataKey="Total" stroke="#4fc3f7" fill="url(#totalGradient)" />}
              <ReferenceLine y={DDOS_THRESHOLD} stroke="#ff5252" strokeDasharray="4 4" label={{ value: 'DDoS thresh', fill: '#ff5252' }} />
              <ReferenceLine y={PORTSCAN_THRESHOLD} stroke="#ffb74d" strokeDasharray="4 4" label={{ value: 'PortScan thresh', fill: '#ffb74d' }} />
              <Brush dataKey="hour" height={20} travellerWidth={10} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="pie-container">
          <h2>Threat Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${Math.round(percent * 100)}%`}
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip formatter={(value, name) => [`${value}`, `${name}`]} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="lifetime-container">
        <h2>Last 30 Days</h2>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={lifetimeData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="day" />
            <YAxis />
            <Tooltip />
            <Legend />
            <defs>
              <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#4fc3f7" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#4fc3f7" stopOpacity={0.2}/>
              </linearGradient>
            </defs>
            <Bar dataKey="count" fill="url(#barGradient)" />
            <Brush dataKey="day" height={20} travellerWidth={10} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="threats-table">
        <div className="table-header">
          <h2>Recent Threats</h2>
          <div className="header-actions">
            <button onClick={() => setShowAlertHistory(!showAlertHistory)} className="export-button">
              📋 {showAlertHistory ? 'Hide' : 'Show'} Alert History
            </button>
            <button onClick={exportToCSV} className="export-button">
              📊 Export CSV
            </button>
            <button onClick={exportToJSON} className="export-button">
              📄 Export JSON
            </button>
          </div>
        </div>
        
        {showAlertHistory && (
          <div className="alert-history-panel">
            <h3>Alert History</h3>
            <div className="alert-list">
              {alertHistory.length === 0 ? (
                <p>No alerts yet</p>
              ) : (
                alertHistory.slice(0, 10).map((alert, idx) => (
                  <div key={idx} className="alert-item">
                    <span className="alert-time">{new Date(alert.timestamp).toLocaleString()}</span>
                    <span className="alert-type">{alert.alert_type}</span>
                    <span className="alert-ip">{alert.source_ip}</span>
                    {alert.geolocation && (
                      <span className="alert-location">
                        {alert.geolocation.city}, {alert.geolocation.country}
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
            <button onClick={fetchAlertHistory} className="refresh-button">Refresh</button>
          </div>
        )}
        <div className="table-container">
        {reversedFilteredThreats.length === 0 ? (
          <div className="no-threats">No matching threats</div>
        ) : (
        <table className="styled-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('timestamp')}>Time</th>
              <th onClick={() => handleSort('threatType')}>Type</th>
              <th onClick={() => handleSort('sourceIP')}>Source IP</th>
              <th onClick={() => handleSort('destinationIP')}>Destination IP</th>
              <th onClick={() => handleSort('ports')}>Ports</th>
            </tr>
          </thead>
          <tbody>
            {paginatedThreats.map((threat, index) => (
              <tr 
                key={index} 
                className={getThreatClass(threat.threatType)}
                onClick={() => openThreatDetails(threat)}
                style={{ cursor: 'pointer' }}
              >
                <td>{new Date(threat.timestamp).toLocaleString()}</td>
                <td>
                  <span className={
                    getThreatSeverity(threat.threatType) === 'high' ? 'severity-high' :
                    getThreatSeverity(threat.threatType) === 'medium' ? 'severity-medium' :
                    'severity-low'
                  } />
                  {threat.threatType}
                </td>
                <td>
                  {threat.sourceIP && threat.sourceIP !== 'N/A' ? (
                    <>
                      <span 
                        className="ip-link" 
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/analytics/ip/${encodeURIComponent(threat.sourceIP)}`);
                        }}
                        title="Click to view IP analytics"
                      >
                        {threat.sourceIP}
                      </span>
                      {threat.geolocation && (
                        <span className="geo-badge" title={`${threat.geolocation.city || 'Unknown'}, ${threat.geolocation.country || 'Unknown'}`}>
                          🌍 {threat.geolocation.country_code || threat.geolocation.country || 'Unknown'}
                        </span>
                      )}
                    </>
                  ) : (
                    <span>{threat.sourceIP || 'N/A'}</span>
                  )}
                </td>
                <td>{threat.destinationIP}</td>
                <td>{threat.ports}</td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
        <div className="table-controls">
          <div className="page-size">
            Rows per page:
            <select
              className="page-size-select"
              value={pageSize}
              onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
          <div className="pagination">
            <button
              className="page-btn"
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
            >Prev</button>
            <span className="page-info">{page} / {totalPages}</span>
            <button
              className="page-btn"
              disabled={page >= totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            >Next</button>
          </div>
        </div>
        </div>
      </div>

      {/* Threat Details Modal */}
      {showThreatModal && selectedThreat && (
        <div className="modal-overlay" onClick={closeThreatModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Threat Details</h2>
              <button className="modal-close" onClick={closeThreatModal}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">Timestamp:</span>
                <span className="detail-value">{new Date(selectedThreat.timestamp).toLocaleString()}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Threat Type:</span>
                <span className={`detail-value ${getThreatClass(selectedThreat.threatType)}`}>
                  {selectedThreat.threatType}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Source IP:</span>
                <span className="detail-value">{selectedThreat.sourceIP}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Destination IP:</span>
                <span className="detail-value">{selectedThreat.destinationIP}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Ports:</span>
                <span className="detail-value">{selectedThreat.ports}</span>
              </div>
              {selectedThreat.geolocation && (
                <div className="detail-section">
                  <h3>Geolocation Information</h3>
                  <div className="detail-row">
                    <span className="detail-label">Country:</span>
                    <span className="detail-value">{selectedThreat.geolocation.country}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">City:</span>
                    <span className="detail-value">{selectedThreat.geolocation.city}</span>
                  </div>
                  {selectedThreat.geolocation.lat && selectedThreat.geolocation.lon && (
                    <div className="detail-row">
                      <span className="detail-label">Coordinates:</span>
                      <span className="detail-value">
                        {selectedThreat.geolocation.lat.toFixed(4)}, {selectedThreat.geolocation.lon.toFixed(4)}
                      </span>
                    </div>
                  )}
                  {selectedThreat.geolocation.isp && (
                    <div className="detail-row">
                      <span className="detail-label">ISP:</span>
                      <span className="detail-value">{selectedThreat.geolocation.isp}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button onClick={closeThreatModal} className="modal-button">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatAnalytics;
