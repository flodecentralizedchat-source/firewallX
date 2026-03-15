import React, { useEffect, useState } from 'react';
import './App.css';

// Reusable Stats Card Component
interface StatsCardProps { title: string; value: number; statusColor?: string; delta?: string; }
const StatsCard = ({ title, value, statusColor = 'var(--text-primary)', delta = '' }: StatsCardProps) => (
  <div className="glass-panel" style={{ flex: '1 1 200px' }}>
    <div className="stats-label">{title}</div>
    <div className="stats-value" style={{ color: statusColor }}>
      {value.toLocaleString()}
    </div>
    {delta && <div style={{ fontSize: '0.85rem', color: 'var(--status-warn)' }}>{delta}</div>}
  </div>
);

interface DashboardStats {
  total_packets: number;
  allowed_packets: number;
  dropped_packets: number;
  active_connections: number;
  ids_alerts: number;
}

interface AlertResponse {
  kind: string;
  src_ip: string;
  description: string;
  block: boolean;
}

interface TunnelResponse {
  id: number;
  peer_ip: string;
  state: string;
  cipher: string;
  bytes_in: number;
  bytes_out: number;
}

interface Rule {
  id: number;
  name: string;
  action: string;
  protocol: string;
  direction: string;
}

function App() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<AlertResponse[]>([]);
  const [tunnels, setTunnels] = useState<TunnelResponse[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [newRule, setNewRule] = useState<Partial<Rule>>({
    name: '', action: 'Drop', protocol: 'Tcp', direction: 'Inbound'
  });
  
  // Copilot State
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatHistory, setChatHistory] = useState<{role: 'user' | 'bot', text: string}[]>([]);
  
  const [error, setError] = useState<string | null>(null);

  const handleChatSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userPrompt = chatInput;
    setChatHistory(prev => [...prev, { role: 'user', text: userPrompt }]);
    setChatInput('');

    try {
      const res = await fetch('http://localhost:3000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: userPrompt })
      });
      const data = await res.json();
      setChatHistory(prev => [...prev, { role: 'bot', text: data.response }]);
    } catch (err) {
      setChatHistory(prev => [...prev, { role: 'bot', text: 'Connection to FirewallX Core lost.' }]);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const payload = {
        id: Math.floor(Math.random() * 10000) + 100, // naive ID generation for demo
        name: newRule.name,
        action: newRule.action,
        protocol: newRule.protocol,
        direction: newRule.direction,
      };

      const res = await fetch('http://localhost:3000/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        setShowRuleModal(false);
        setNewRule({ name: '', action: 'Drop', protocol: 'Tcp', direction: 'Inbound' });
        fetchData(); // Refresh the table
      }
    } catch (err) {
      console.error("Failed to post rule", err);
    }
  };

  const fetchData = async () => {
    try {
      const urls = [
        'http://localhost:3000/api/stats',
        'http://localhost:3000/api/alerts',
        'http://localhost:3000/api/tunnels',
        'http://localhost:3000/api/rules'
      ];
      const [resStats, resAlerts, resTunnels, resRules] = await Promise.all(
        urls.map((u) => fetch(u).then((r) => r.json()))
      );
      
      setStats(resStats);
      setAlerts(resAlerts);
      setTunnels(resTunnels);
      setRules(resRules);
      setError(null);
    } catch (err) {
      setError('Connection to Engine lost...');
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 1000); // 1s live refresh
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: '40px', maxWidth: '1400px', margin: '0 auto' }}>
      <header style={{ marginBottom: '40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="text-gradient" style={{ fontSize: '2.5rem' }}>FirewallX Core</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>
            <span className="live-indicator"></span> 
            {error ? <span style={{ color: 'var(--status-error)' }}>{error}</span> : 'System Online • Line-Rate Telemetry Active'}
          </p>
        </div>
        <button className="btn-primary" onClick={fetchData}>Force Refresh Datalink</button>
      </header>

      {/* Metrics Row */}
      <div style={{ display: 'flex', gap: '24px', marginBottom: '32px', flexWrap: 'wrap' }}>
        <StatsCard 
          title="Total Packets Processed" 
          value={stats?.total_packets || 0} 
        />
        <StatsCard 
          title="Line-Rate Allow" 
          value={stats?.allowed_packets || 0} 
          statusColor="var(--status-ok)" 
        />
        <StatsCard 
          title="Dropped Threats" 
          value={stats?.dropped_packets || 0} 
          statusColor="var(--status-error)" 
        />
        <StatsCard 
          title="Active State Connections" 
          value={stats?.active_connections || 0} 
          statusColor="var(--accent-cyan)" 
        />
        <StatsCard 
          title="IDS Alerts Issued" 
          value={stats?.ids_alerts || 0} 
          statusColor="var(--status-warn)" 
          delta={stats && stats.ids_alerts > 0 ? '⚠ Investigation Required' : ''}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
        
        {/* IDS Alerts Panel */}
        <section className="glass-panel">
          <h3 style={{ marginBottom: '20px', color: 'var(--status-error)' }}>Active IDS Intrusions</h3>
          <div style={{ maxHeight: '300px', overflowY: 'auto', paddingRight: '8px' }}>
            {alerts.length === 0 ? (
              <p style={{ color: 'var(--text-secondary)' }}>No intrusions detected. Sensors clear.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {alerts.map((a, i) => (
                  <div key={i} style={{ 
                    padding: '16px', background: 'rgba(244, 67, 54, 0.05)', 
                    borderLeft: '4px solid var(--status-error)', borderRadius: '4px' 
                  }}>
                    <strong style={{ display: 'block', marginBottom: '4px' }}>[{a.kind}] {a.src_ip}</strong>
                    <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{a.description}</span>
                    {a.block && <span style={{ float: 'right', color: 'var(--status-error)', fontSize: '0.8rem', fontWeight: 'bold' }}>BLOCKED</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* VPN Gateway Tunnels */}
        <section className="glass-panel">
          <h3 style={{ marginBottom: '20px', color: 'var(--accent-teal)' }}>VPN Gateway Tunnels</h3>
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {tunnels.length === 0 ? (
              <p style={{ color: 'var(--text-secondary)' }}>No active site-to-site peers established.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {tunnels.map((t) => (
                  <div key={t.id} style={{ 
                    padding: '16px', background: 'var(--glass-bg)', 
                    border: '1px solid var(--glass-border)', borderRadius: '8px' 
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <strong>Peer: {t.peer_ip}</strong>
                      <span style={{ 
                        color: t.state === 'Established' ? 'var(--status-ok)' : 'var(--status-warn)',
                        fontWeight: 'bold', fontSize: '0.85rem'
                      }}>{t.state}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      <span>Cipher: {t.cipher}</span>
                      <span>Rx: {(t.bytes_in / 1024).toFixed(1)} KB │ Tx: {(t.bytes_out / 1024).toFixed(1)} KB</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Rules Engine Dashboard */}
        <section className="glass-panel" style={{ gridColumn: '1 / -1' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
            <h3 style={{ color: 'var(--text-primary)' }}>Enforcement Policies (RuleSet)</h3>
            <button className="btn-primary" style={{ padding: '6px 12px', fontSize: '0.9rem' }} onClick={() => setShowRuleModal(true)}>+ New Rule</button>
          </div>
          
          <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.95rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--glass-border)' }}>
                <th style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>ID</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>Name</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>Action</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>Protocol</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>Direction</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id} style={{ borderBottom: '1px solid var(--glass-bg-hover)' }}>
                  <td style={{ padding: '16px' }}>#{r.id}</td>
                  <td style={{ padding: '16px', fontWeight: 500 }}>{r.name}</td>
                  <td style={{ padding: '16px', color: r.action === 'Allow' ? 'var(--status-ok)' : 'var(--status-error)' }}>
                    {r.action}
                  </td>
                  <td style={{ padding: '16px' }}>{r.protocol}</td>
                  <td style={{ padding: '16px' }}>{r.direction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

      </div>

      {/* Create Rule Modal */}
      {showRuleModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '450px' }}>
            <h3 style={{ marginBottom: '20px' }}>Create Enforcement Rule</h3>
            <form onSubmit={handleCreateRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              
              <div>
                <label className="stats-label" style={{ display: 'block', marginBottom: '8px' }}>Rule Name</label>
                <input required type="text" placeholder="e.g. block_ssh_external" 
                       value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} />
              </div>
              
              <div style={{ display: 'flex', gap: '16px' }}>
                <div style={{ flex: 1 }}>
                  <label className="stats-label" style={{ display: 'block', marginBottom: '8px' }}>Action</label>
                  <select value={newRule.action} onChange={e => setNewRule({...newRule, action: e.target.value})}>
                    <option value="Allow">Allow</option>
                    <option value="Drop">Drop (Block)</option>
                    <option value="Reject">Reject</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label className="stats-label" style={{ display: 'block', marginBottom: '8px' }}>Protocol</label>
                  <select value={newRule.protocol} onChange={e => setNewRule({...newRule, protocol: e.target.value})}>
                    <option value="Tcp">TCP</option>
                    <option value="Udp">UDP</option>
                    <option value="Icmp">ICMP</option>
                    <option value="Any">ANY</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="stats-label" style={{ display: 'block', marginBottom: '8px' }}>Direction</label>
                <select value={newRule.direction} onChange={e => setNewRule({...newRule, direction: e.target.value})}>
                  <option value="Inbound">Inbound</option>
                  <option value="Outbound">Outbound</option>
                </select>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '16px' }}>
                <button type="button" className="btn-primary" style={{ background: 'transparent', borderColor: 'var(--text-secondary)' }} onClick={() => setShowRuleModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary">Deploy Policy</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Copilot Floating Chat Widget */}
      <div style={{
        position: 'fixed', bottom: '24px', right: '24px', zIndex: 900,
        width: chatOpen ? '350px' : 'auto',
        transition: 'all 0.3s ease'
      }}>
        {!chatOpen ? (
          <button 
            className="btn-primary" 
            style={{ borderRadius: '50%', width: '60px', height: '60px', boxShadow: '0 4px 20px var(--accent-cyan-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onClick={() => setChatOpen(true)}
          >
            <span style={{ fontSize: '1.5rem' }}>🧠</span>
          </button>
        ) : (
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '450px', padding: 0, overflow: 'hidden' }}>
            {/* Header */}
            <div style={{ padding: '16px', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,0,0,0.2)' }}>
              <strong style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="live-indicator"></span> Firewall Copilot
              </strong>
              <button style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }} onClick={() => setChatOpen(false)}>✕</button>
            </div>
            
            {/* Messages */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {chatHistory.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-secondary)', marginTop: '40px', fontSize: '0.9rem' }}>
                  Ask me to block an IP, summarize traffic, or evaluate IDS alerts!
                </div>
              ) : (
                chatHistory.map((msg, i) => (
                  <div key={i} style={{ 
                    alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                    background: msg.role === 'user' ? 'var(--accent-teal)' : 'var(--glass-bg-hover)',
                    color: msg.role === 'user' ? '#fff' : 'var(--text-primary)',
                    padding: '10px 14px', borderRadius: '12px', maxWidth: '85%',
                    borderBottomRightRadius: msg.role === 'user' ? '4px' : '12px',
                    borderBottomLeftRadius: msg.role === 'bot' ? '4px' : '12px',
                    fontSize: '0.9rem', lineHeight: '1.4'
                  }}>
                    {msg.text}
                  </div>
                ))
              )}
            </div>

            {/* Input Form */}
            <form onSubmit={handleChatSubmit} style={{ padding: '16px', borderTop: '1px solid var(--glass-border)', display: 'flex', gap: '8px', background: 'rgba(0,0,0,0.2)' }}>
              <input 
                type="text" 
                placeholder="Message Copilot..." 
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                style={{ flex: 1, padding: '10px', borderRadius: '20px', background: 'rgba(255,255,255,0.05)' }}
              />
              <button type="submit" className="btn-primary" style={{ padding: '10px 16px', borderRadius: '20px' }}>&rarr;</button>
            </form>
          </div>
        )}
      </div>

    </div>
  );
}

export default App;
