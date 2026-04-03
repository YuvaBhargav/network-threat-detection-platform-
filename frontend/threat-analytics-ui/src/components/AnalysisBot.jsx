import React, { useEffect, useMemo, useRef, useState } from 'react';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000';

const STARTER_PROMPTS = [
  'Give me a 24h security summary',
  'What anomalies stand out?',
  'What should I fix first?',
  'Explain the latest alert',
  'Show the highest-priority incidents',
];

function AnalysisBot() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Security Analysis Bot is ready. Ask for summaries, anomalies, incidents, trends, or alert explanations.',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const messageEndRef = useRef(null);

  const refreshSummary = () => {
    fetch(`${API_BASE_URL}/api/analysis/summary`)
      .then((response) => response.json())
      .then((data) => setSummary(data))
      .catch(() => setSummary(null));
  };

  useEffect(() => {
    refreshSummary();
  }, []);

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, loading]);

  const summaryStats = useMemo(() => {
    if (!summary || !summary.counts) return [];
    return [
      { label: '24h threats', value: summary.counts.total_24h ?? 0 },
      { label: 'Risk score', value: summary.riskScore ?? 0 },
      { label: 'Inbound', value: summary.counts.inbound ?? 0 },
      { label: 'Outbound', value: summary.counts.outbound ?? 0 },
      { label: 'Web attacks', value: (summary.counts.sqli ?? 0) + (summary.counts.xss ?? 0) },
    ];
  }, [summary]);

  const sendMessage = async (presetMessage) => {
    const text = (presetMessage ?? input).trim();
    if (!text || loading) return;

    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text }),
      });
      const data = await response.json();
      const reply = data.reply || 'No analysis available.';
      if (data.snapshot) {
        setSummary(data.snapshot);
      }
      setMessages((prev) => [...prev, { role: 'assistant', content: reply }]);
    } catch (error) {
      setMessages((prev) => [...prev, { role: 'assistant', content: 'Analysis service is unavailable right now.' }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chart-card analysis-bot-panel">
      <div className="analysis-bot-header">
        <div>
          <h2>Security Analysis Bot</h2>
          <p>Local, data-driven incident analysis built from your live threat store. No external LLM is required.</p>
        </div>
        <button className="refresh-button" onClick={refreshSummary}>
          Sync Snapshot
        </button>
      </div>

      <div className="analysis-summary-strip">
        {summaryStats.map((item) => (
          <div key={item.label} className="analysis-summary-chip">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>

      <div className="analysis-grid">
        <div className="analysis-card">
          <h3>Incident Clusters</h3>
          {summary?.incidents?.length ? summary.incidents.slice(0, 4).map((incident) => (
            <div key={`${incident.threatType}-${incident.sourceIP}-${incident.destinationIP}`} className="analysis-list-item">
              <strong>{incident.threatType}</strong>
              <span>{incident.sourceIP} -> {incident.destinationIP}</span>
              <span>count {incident.count} | score {incident.severityScore}</span>
            </div>
          )) : <p>No clustered incidents yet.</p>}
        </div>

        <div className="analysis-card">
          <h3>Anomalies</h3>
          {summary?.anomalies?.length ? summary.anomalies.map((item) => (
            <div key={item.title} className="analysis-list-item">
              <strong>{item.title}</strong>
              <span>{item.detail}</span>
            </div>
          )) : <p>No anomalies highlighted.</p>}
        </div>

        <div className="analysis-card">
          <h3>Trend Watch</h3>
          {summary?.trends ? (
            <div className="analysis-list-item">
              <strong>{summary.trends.direction === 'up' ? 'Activity increasing' : summary.trends.direction === 'down' ? 'Activity easing' : 'Activity stable'}</strong>
              <span>Last 6h: {summary.trends.currentWindow} | Previous 6h: {summary.trends.previousWindow}</span>
              <span>Dominant threat: {summary.trends.dominantThreat}</span>
            </div>
          ) : <p>No trend data yet.</p>}
        </div>
      </div>

      <div className="analysis-prompt-row">
        {STARTER_PROMPTS.map((prompt) => (
          <button key={prompt} className="series-btn active" onClick={() => sendMessage(prompt)}>
            {prompt}
          </button>
        ))}
      </div>

      <div className="chat-messages analysis-messages">
        {messages.map((message, index) => (
          <div key={`${message.role}-${index}`} className={`chat-message ${message.role}`}>
            <div className="chat-bubble">{message.content}</div>
          </div>
        ))}
        {loading ? (
          <div className="chat-message assistant">
            <div className="chat-bubble">Analyzing current threat activity...</div>
          </div>
        ) : null}
        <div ref={messageEndRef} />
      </div>

      <div className="chat-input-row">
        <input
          className="chat-input"
          type="text"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              sendMessage();
            }
          }}
          placeholder="Ask about incidents, anomalies, trends, or alert explanations"
        />
        <button className="refresh-button" onClick={() => sendMessage()} disabled={loading}>
          Ask
        </button>
      </div>
    </div>
  );
}

export default AnalysisBot;
