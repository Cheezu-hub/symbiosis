import React, { useState, useEffect } from 'react';
import { Zap, Check, X, Truck, Leaf, TrendingUp, MapPin, RefreshCw, Cpu } from 'lucide-react';
import { matchAPI } from '../services/api';
import api from '../services/api';

const MatchesPage = ({ user }) => {
  const [matches, setMatches]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [generating, setGenerating] = useState(false);
  const [actionId, setActionId] = useState(null);
  const [error, setError]       = useState('');
  const [message, setMessage]   = useState('');

  useEffect(() => { fetchMatches(); }, []);

  const fetchMatches = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await matchAPI.getAll();
      setMatches(res.data.data?.matches || []);
    } catch (err) {
      setError('Failed to load matches.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setMessage('');
    setError('');
    try {
      const res = await api.post('/matches/generate');
      setMessage(res.data.message);
      await fetchMatches();
    } catch (err) {
      setError('Failed to generate matches.');
    } finally {
      setGenerating(false);
    }
  };

  const handleAccept = async (matchId) => {
    setActionId(matchId);
    try {
      await matchAPI.accept(matchId);
      setMatches(prev => prev.map(m => m.id === matchId ? { ...m, status: 'accepted' } : m));
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to accept match.');
    } finally { setActionId(null); }
  };

  const handleReject = async (matchId) => {
    if (!window.confirm('Reject this match?')) return;
    setActionId(matchId);
    try {
      await matchAPI.reject(matchId);
      setMatches(prev => prev.map(m => m.id === matchId ? { ...m, status: 'rejected' } : m));
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to reject match.');
    } finally { setActionId(null); }
  };

  const pendingMatches = matches.filter(m => m.status === 'pending');
  const totalCO2       = matches.reduce((acc, m) => acc + (m.co2Reduction || 0), 0);
  const totalSavings   = matches.reduce((acc, m) => acc + (m.costSavings   || 0), 0);

  if (loading) return <div className="page-container"><div className="loading"><div className="spinner"></div></div></div>;

  return (
    <div className="page-container fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">AI Match Recommendations</h1>
          <p className="page-subtitle">Intelligent waste-resource matching powered by semantic AI</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-outline" onClick={fetchMatches}>
            <RefreshCw size={18} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={handleGenerate} disabled={generating}>
            <Cpu size={18} /> {generating ? 'Running AI...' : 'Run AI Matching'}
          </button>
        </div>
      </div>

      {/* Status messages */}
      {message && (
        <div style={{ background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#16A34A', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Zap size={16} /> {message}
        </div>
      )}
      {error && (
        <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#DC2626' }}>
          {error}
        </div>
      )}

      {/* Stats */}
      <div className="dashboard-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon primary"><Zap size={24} /></div></div>
          <div className="stat-value">{pendingMatches.length}</div>
          <div className="stat-label">Pending Matches</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon success"><Leaf size={24} /></div></div>
          <div className="stat-value">{totalCO2.toFixed(1)} tons</div>
          <div className="stat-label">Potential CO₂ Reduction</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon accent"><TrendingUp size={24} /></div></div>
          <div className="stat-value">₹{(totalSavings / 100000).toFixed(1)}L</div>
          <div className="stat-label">Potential Cost Savings</div>
        </div>
      </div>

      {matches.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '4rem' }}>
          <Cpu size={64} style={{ color: 'var(--text-muted)', marginBottom: '1rem' }} />
          <h3 style={{ marginBottom: '0.5rem' }}>No Matches Yet</h3>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
            Add waste listings and resource requests, then click <strong>Run AI Matching</strong> to generate matches automatically.
          </p>
          <button className="btn btn-primary" onClick={handleGenerate} disabled={generating}>
            <Cpu size={18} /> {generating ? 'Running...' : 'Run AI Matching Now'}
          </button>
        </div>
      ) : (
        matches.map((match) => (
          <div key={match.id} className="card" style={{ marginBottom: '1.5rem', opacity: match.status === 'rejected' ? 0.5 : 1 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '2rem' }}>

              {/* Match Info */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{ color: 'var(--primary)' }}>{match.wasteType}</h3>
                  <div className="score-circle" style={{ width: '72px', height: '72px', background: `conic-gradient(var(--primary) ${match.matchScore || 0}%, var(--border) ${match.matchScore || 0}%)` }}>
                    <div className="score-inner" style={{ width: '58px', height: '58px' }}>
                      <div className="score-value" style={{ fontSize: '1.3rem' }}>{match.matchScore || '—'}</div>
                      <div className="score-label" style={{ fontSize: '0.6rem' }}>Match</div>
                    </div>
                  </div>
                </div>
                {match.wasteLocation && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
                    <MapPin size={16} /><span>{match.wasteLocation}</span>
                  </div>
                )}
                {match.logisticsCost > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
                    <Truck size={16} /><span>Logistics: ₹{match.logisticsCost.toLocaleString()}</span>
                  </div>
                )}
              </div>

              {/* Parties */}
              <div>
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Waste Provider</div>
                  <div style={{ fontWeight: 600 }}>{match.wasteProvider}</div>
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Resource Seeker</div>
                  <div style={{ fontWeight: 600 }}>{match.resourceSeeker}</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Quantity</div>
                  <div style={{ fontWeight: 600 }}>{match.quantity}</div>
                </div>
              </div>

              {/* Impact + Actions */}
              <div>
                {match.co2Reduction > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <Leaf size={18} style={{ color: 'var(--success)' }} />
                    <span style={{ fontWeight: 600 }}>CO₂: {match.co2Reduction} tons saved</span>
                  </div>
                )}
                {match.costSavings > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                    <TrendingUp size={18} style={{ color: 'var(--accent)' }} />
                    <span style={{ fontWeight: 600 }}>Savings: ₹{match.costSavings.toLocaleString()}</span>
                  </div>
                )}
                {match.status === 'pending' && (
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button className="btn btn-primary" style={{ flex: 1 }} onClick={() => handleAccept(match.id)} disabled={actionId === match.id}>
                      <Check size={18} /> {actionId === match.id ? '...' : 'Accept'}
                    </button>
                    <button className="btn btn-outline" style={{ flex: 1, color: 'var(--error)', borderColor: 'var(--error)' }} onClick={() => handleReject(match.id)} disabled={actionId === match.id}>
                      <X size={18} /> Reject
                    </button>
                  </div>
                )}
                {match.status === 'accepted' && <span className="badge badge-success">✓ Accepted</span>}
                {match.status === 'rejected' && <span className="badge" style={{ background: '#FEE2E2', color: '#DC2626' }}>Rejected</span>}
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default MatchesPage;
