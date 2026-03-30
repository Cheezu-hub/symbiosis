import React, { useState, useEffect } from 'react';
import { Leaf, TrendingUp, Package, Droplets, Wind, RefreshCw } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { impactAPI } from '../services/api';

const COLORS = ['#1F7A8C', '#10B981', '#F59E0B', '#00C9B1'];

const ImpactPage = ({ user }) => {
  const [metrics, setMetrics] = useState({});
  const [report, setReport] = useState([]);
  const [score, setScore] = useState({});
  const [period, setPeriod] = useState('monthly');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => { fetchAll(); }, [period]);

  const fetchAll = async () => {
    setLoading(true);
    setError('');
    try {
      const [metricsRes, reportRes, scoreRes] = await Promise.all([
        impactAPI.getMetrics(),
        impactAPI.getReport(period),
        impactAPI.getSustainabilityScore(),
      ]);
      setMetrics(metricsRes.data.data || {});
      setReport(reportRes.data.data || []);
      setScore(scoreRes.data.data || {});
    } catch (err) {
      setError('Failed to load impact data.');
    } finally {
      setLoading(false);
    }
  };

  const impactCards = [
    { icon: Wind,      title: 'CO₂ Reduced',        value: (metrics.co2Reduced || 0).toLocaleString(),      unit: 'tons',   color: 'success' },
    { icon: Package,   title: 'Waste Diverted',      value: (metrics.wasteDiverted || 0).toLocaleString(),   unit: 'tons',   color: 'primary' },
    { icon: Droplets,  title: 'Water Saved',         value: (metrics.waterSaved || 0).toLocaleString(),      unit: 'liters', color: 'accent'  },
    { icon: TrendingUp,title: 'Energy Saved',        value: (metrics.energySaved || 0).toLocaleString(),     unit: 'MWh',    color: 'warning' },
  ];

  // Build pie data from score breakdown if available
  const pieData = Object.entries(score.breakdown || {}).map(([key, val], i) => ({
    name: key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()),
    value: val,
    color: COLORS[i % COLORS.length]
  }));

  if (loading) return (
    <div className="page-container">
      <div className="loading"><div className="spinner"></div></div>
    </div>
  );

  return (
    <div className="page-container fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Environmental Impact</h1>
          <p className="page-subtitle">Track your contribution to sustainability and circular economy</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select className="form-select" style={{ width: 'auto' }} value={period} onChange={(e) => setPeriod(e.target.value)}>
            <option value="monthly">Monthly</option>
            <option value="weekly">Weekly</option>
            <option value="yearly">Yearly</option>
          </select>
          <button className="btn btn-outline" onClick={fetchAll}><RefreshCw size={18} /></button>
        </div>
      </div>

      {error && (
        <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '1rem', marginBottom: '1.5rem', color: '#DC2626' }}>
          {error}
        </div>
      )}

      {/* Impact Summary Banners */}
      <div className="impact-grid">
        <div className="impact-card">
          <div className="impact-value">{(metrics.co2Reduced || 0).toLocaleString()}</div>
          <div className="impact-label">Tons CO₂ Reduced</div>
        </div>
        <div className="impact-card" style={{ background: 'linear-gradient(135deg, #10B981, #059669)' }}>
          <div className="impact-value">{(metrics.wasteDiverted || 0).toLocaleString()}</div>
          <div className="impact-label">Tons Waste Diverted</div>
        </div>
        <div className="impact-card" style={{ background: 'linear-gradient(135deg, #00C9B1, #009688)' }}>
          <div className="impact-value">{((metrics.waterSaved || 0) / 1000).toFixed(1)}K</div>
          <div className="impact-label">Liters Water Saved</div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="dashboard-grid" style={{ marginTop: '2rem' }}>
        {impactCards.map((card, index) => {
          const Icon = card.icon;
          return (
            <div key={index} className="stat-card">
              <div className="stat-header"><div className={`stat-icon ${card.color}`}><Icon size={24} /></div></div>
              <div className="stat-value">{card.value}</div>
              <div className="stat-label">{card.unit}</div>
            </div>
          );
        })}
      </div>

      {/* Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '2rem', marginTop: '2rem' }}>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Impact Over Time</h3></div>
          {report.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', padding: '2rem 0', textAlign: 'center' }}>No report data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={report}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="period" stroke="#64748B" tickFormatter={v => new Date(v).toLocaleDateString('en-IN', { month: 'short' })} />
                <YAxis stroke="#64748B" />
                <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }} />
                <Bar dataKey="co2Reduced" fill="#1F7A8C" name="CO₂ (tons)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="wasteDiverted" fill="#10B981" name="Waste (tons)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="card-header"><h3 className="card-title">Sustainability Score Breakdown</h3></div>
          {pieData.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', padding: '2rem 0', textAlign: 'center' }}>No score data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Raw Material Savings */}
      {metrics.rawMaterialSaved > 0 && (
        <div className="card" style={{ marginTop: '2rem' }}>
          <div className="card-header"><h3 className="card-title">Raw Material Savings</h3></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem' }}>
            <div>
              <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--primary)' }}>{metrics.rawMaterialSaved} tons</div>
              <div style={{ color: 'var(--text-secondary)' }}>Total Raw Materials Saved</div>
            </div>
            <div>
              <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--success)' }}>
                ₹{(metrics.rawMaterialSaved * 2500 / 100000).toFixed(1)}L
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>Equivalent Cost Savings</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ImpactPage;
