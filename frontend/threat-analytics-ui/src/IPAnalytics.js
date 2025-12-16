import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  BarChart, Bar, PieChart, Pie, Cell, ComposedChart, Area 
} from 'recharts';
import './App.css';

function IPAnalytics() {
  const { ip } = useParams();
  const navigate = useNavigate();
  const [threats, setThreats] = useState([]);
  const [ipData, setIpData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('24h'); // 24h, 7d, 30d

  // Filter threats for this IP
  const ipThreats = useMemo(() => {
    if (!ip) return [];
    return threats.filter(t => t.sourceIP === ip);
  }, [threats, ip]);

  // Calculate IP statistics
  const ipStats = useMemo(() => {
    if (!ipThreats.length) return null;

    const now = new Date();
    const timeRanges = {
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    };
    const rangeMs = timeRanges[timeRange] || timeRanges['24h'];
    const rangeStart = new Date(now.getTime() - rangeMs);

    const filtered = ipThreats.filter(t => new Date(t.timestamp) >= rangeStart);

    const threatTypes = {};
    const ports = {};
    const hourlyData = {};
    const geolocation = ipThreats[0]?.geolocation || null;

    filtered.forEach(threat => {
      // Count by threat type
      const type = threat.threatType || 'Unknown';
      threatTypes[type] = (threatTypes[type] || 0) + 1;

      // Count by port
      const port = threat.ports || 'Unknown';
      ports[port] = (ports[port] || 0) + 1;

      // Group by hour
      const date = new Date(threat.timestamp);
      const hour = `${date.getHours()}:00`;
      if (!hourlyData[hour]) {
        hourlyData[hour] = { hour, count: 0 };
      }
      hourlyData[hour].count++;
    });

    return {
      totalThreats: filtered.length,
      threatTypes: Object.entries(threatTypes).map(([name, value]) => ({ name, value })),
      ports: Object.entries(ports).map(([name, value]) => ({ name, value: Number(value) })).slice(0, 10),
      hourlyData: Object.values(hourlyData).sort((a, b) => a.hour.localeCompare(b.hour)),
      geolocation,
      firstSeen: filtered.length > 0 ? filtered[filtered.length - 1].timestamp : null,
      lastSeen: filtered.length > 0 ? filtered[0].timestamp : null,
      uniqueDestinations: new Set(filtered.map(t => t.destinationIP)).size
    };
  }, [ipThreats, timeRange]);

  // Fetch threats
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
            throw new Error(`HTTP error! Status: ${response.status}. Make sure the backend server is running.`);
          });
        }
        return response.json();
      })
      .then(data => {
        const threatsArray = Array.isArray(data) ? data : (data.threats || []);
        setThreats(threatsArray);
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
  }, []);

  // Fetch IP geolocation if not in threat data
  useEffect(() => {
    if (ip && !ipStats?.geolocation) {
      fetch(`http://localhost:5000/api/geolocation/${ip}`)
        .then(response => response.json())
        .then(data => {
          if (data && !data.error) {
            setIpData(data);
          }
        })
        .catch(err => console.error('Geolocation fetch error:', err));
    }
  }, [ip, ipStats]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  const COLORS = ['#ff5252', '#ffb74d', '#9575cd', '#4db6ac', '#f06292', '#64b5f6', '#81c784'];

  if (isLoading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading IP analytics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <div className="error-content">
          <h2>⚠️ Connection Error</h2>
          <p>{error}</p>
          <button onClick={fetchThreats} className="retry-button">🔄 Retry Connection</button>
        </div>
      </div>
    );
  }

  if (!ip) {
    const ipCounts = threats.reduce((acc, t) => {
      const sip = t.sourceIP;
      if (!sip || sip === 'N/A') return acc;
      acc[sip] = (acc[sip] || 0) + 1;
      return acc;
    }, {});
    const topIps = Object.entries(ipCounts)
      .map(([addr, count]) => ({ addr, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
    return (
      <div className="dashboard-container ip-analytics-page">
        <div className="ip-analytics-header">
          <button onClick={() => navigate('/')} className="back-button">← Back to Dashboard</button>
          <h1>IP Analytics</h1>
        </div>
        <div className="chart-card">
          <h2>Select an IP to view analytics</h2>
          <div className="table-container">
            <table className="styled-table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Threat Count</th>
                </tr>
              </thead>
              <tbody>
                {topIps.length === 0 ? (
                  <tr>
                    <td colSpan="2">No IPs available. Click an IP in the dashboard table to open its analytics.</td>
                  </tr>
                ) : (
                  topIps.map((row, idx) => (
                    <tr key={idx} onClick={() => navigate(`/analytics/ip/${encodeURIComponent(row.addr)}`)} style={{ cursor: 'pointer' }}>
                      <td>{row.addr}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  if (!ipThreats.length) {
    return (
      <div className="dashboard-container">
        <div className="ip-analytics-header">
          <button onClick={() => navigate('/')} className="back-button">← Back to Dashboard</button>
          <h1>IP Analytics: {ip}</h1>
        </div>
        <div className="no-data-container">
          <h2>No threats found for this IP address</h2>
          <p>This IP address ({ip}) has not generated any threats in the system.</p>
        </div>
      </div>
    );
  }

  const geoData = ipStats.geolocation || ipData;

  return (
    <div className="dashboard-container ip-analytics-page">
      <div className="ip-analytics-header">
        <button onClick={() => navigate('/')} className="back-button">← Back to Dashboard</button>
        <div className="ip-header-content">
          <h1 className="ip-title">
            <span className="ip-badge">{ip}</span>
            {geoData && (
              <span className="geo-info">
                🌍 {geoData.city}, {geoData.country}
              </span>
            )}
          </h1>
          <div className="time-range-selector">
            <button 
              className={timeRange === '24h' ? 'active' : ''} 
              onClick={() => setTimeRange('24h')}
            >
              24 Hours
            </button>
            <button 
              className={timeRange === '7d' ? 'active' : ''} 
              onClick={() => setTimeRange('7d')}
            >
              7 Days
            </button>
            <button 
              className={timeRange === '30d' ? 'active' : ''} 
              onClick={() => setTimeRange('30d')}
            >
              30 Days
            </button>
          </div>
        </div>
      </div>

      {/* IP Stats Cards */}
      <div className="ip-stats-grid">
        <div className="ip-stat-card gradient-1">
          <div className="stat-icon">📊</div>
          <div className="stat-info">
            <h3>Total Threats</h3>
            <p className="stat-value-large">{ipStats.totalThreats}</p>
          </div>
        </div>
        <div className="ip-stat-card gradient-2">
          <div className="stat-icon">🎯</div>
          <div className="stat-info">
            <h3>Threat Types</h3>
            <p className="stat-value-large">{ipStats.threatTypes.length}</p>
          </div>
        </div>
        <div className="ip-stat-card gradient-3">
          <div className="stat-icon">🔌</div>
          <div className="stat-info">
            <h3>Ports Targeted</h3>
            <p className="stat-value-large">{ipStats.ports.length}</p>
          </div>
        </div>
        <div className="ip-stat-card gradient-4">
          <div className="stat-icon">🌐</div>
          <div className="stat-info">
            <h3>Destinations</h3>
            <p className="stat-value-large">{ipStats.uniqueDestinations}</p>
          </div>
        </div>
      </div>

      {/* Geolocation Info */}
      {geoData && (
        <div className="geo-card">
          <h2>📍 Geolocation Information</h2>
          <div className="geo-details">
            <div className="geo-item">
              <span className="geo-label">Country:</span>
              <span className="geo-value">{geoData.country}</span>
            </div>
            <div className="geo-item">
              <span className="geo-label">City:</span>
              <span className="geo-value">{geoData.city}</span>
            </div>
            {geoData.lat != null && geoData.lon != null && (
              <div className="geo-item">
                <span className="geo-label">Coordinates:</span>
                <span className="geo-value">
                  {typeof geoData.lat === 'number' ? geoData.lat.toFixed(4) : geoData.lat}, 
                  {typeof geoData.lon === 'number' ? geoData.lon.toFixed(4) : geoData.lon}
                </span>
              </div>
            )}
            {geoData.isp && (
              <div className="geo-item">
                <span className="geo-label">ISP:</span>
                <span className="geo-value">{geoData.isp}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Timeline */}
      {ipStats.hourlyData.length > 0 && (
        <div className="chart-card">
          <h2>Threat Timeline</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={ipStats.hourlyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#34495e" />
              <XAxis dataKey="hour" stroke="#bbb" />
              <YAxis stroke="#bbb" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#2c3e50', 
                  border: '1px solid #34495e',
                  borderRadius: '8px'
                }} 
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="count" 
                stroke="#4fc3f7" 
                strokeWidth={3}
                dot={{ fill: '#4fc3f7', r: 4 }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Charts Grid */}
      <div className="charts-grid-ip">
        {/* Threat Types Pie Chart */}
        {ipStats.threatTypes.length > 0 && (
          <div className="chart-card">
            <h2>Threat Types Distribution</h2>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={ipStats.threatTypes}
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {ipStats.threatTypes.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Ports Bar Chart */}
        {ipStats.ports.length > 0 && (
          <div className="chart-card">
            <h2>Targeted Ports</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={ipStats.ports}>
                <CartesianGrid strokeDasharray="3 3" stroke="#34495e" />
                <XAxis dataKey="name" stroke="#bbb" />
                <YAxis stroke="#bbb" />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#2c3e50', 
                    border: '1px solid #34495e',
                    borderRadius: '8px'
                  }} 
                />
                <Bar dataKey="value" fill="#4fc3f7" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Recent Threats Table */}
      <div className="chart-card">
        <h2>Recent Threats from this IP</h2>
        <div className="table-container">
          <table className="styled-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Threat Type</th>
                <th>Destination IP</th>
                <th>Ports</th>
              </tr>
            </thead>
            <tbody>
              {ipThreats.slice(0, 20).map((threat, index) => (
                <tr key={index}>
                  <td>{new Date(threat.timestamp).toLocaleString()}</td>
                  <td>
                    <span className={`threat-badge ${threat.threatType?.toLowerCase().replace(/\s+/g, '-')}`}>
                      {threat.threatType}
                    </span>
                  </td>
                  <td>{threat.destinationIP}</td>
                  <td>{threat.ports}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default IPAnalytics;

