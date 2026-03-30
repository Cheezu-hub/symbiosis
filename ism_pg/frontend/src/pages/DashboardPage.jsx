import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Recycle, Factory, Zap, Leaf, TrendingUp, Plus, ArrowRight
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { wasteAPI, resourceAPI, matchAPI, impactAPI } from '../services/api';

const DashboardPage = ({ user }) => {
  const [stats, setStats] = useState({
    wasteListed: 0, resourceRequests: 0, activeMatches: 0,
    co2Reduced: 0, wasteDiverted: 0, costSavings: 0
  });
  const [recentMatches, setRecentMatches] = useState([]);
  const [sustainabilityScore, setSustainabilityScore] = useState(0);
  const [scoreBreakdown, setScoreBreakdown] = useState({});
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    setError('');
    try {
      const [wasteRes, resourceRes, matchRes, impactRes, scoreRes] = await Promise.all([
        wasteAPI.getAll(),
        resourceAPI.getAll(),
        matchAPI.getAll(),
        impactAPI.getMetrics(),
        impactAPI.getSustainabilityScore(),
      ]);

      const wastes = wasteRes.data.data || [];
      const resources = resourceRes.data.data || [];
      const matchData = matchRes.data.data?.matches || [];
      const impact = impactRes.data.data || {};
      const scoreData = scoreRes.data.data || {};

      const activeMatches = matchData.filter(m => m.status === 'pending' || m.status === 'accepted');
      const totalCostSavings = matchData.reduce((acc, m) => acc + (m.costSavings || 0), 0);

      setStats({
        wasteListed: wastes.length,
        resourceRequests: resources.length,
        activeMatches: activeMatches.length,
        co2Reduced: impact.co2Reduced || 0,
        wasteDiverted: impact.wasteDiverted || 0,
        costSavings: totalCostSavings
      });

      setRecentMatches(matchData.slice(0, 5));
      setSustainabilityScore(scoreData.overallScore || 0);
      setScoreBreakdown(scoreData.breakdown || {});

      // Build simple 6-point chart from cumulative match data
      const months = ['Month 1','Month 2','Month 3','Month 4','Month 5','Month 6'];
      setChartData(months.map((month, i) => ({
        month,
        waste: Math.round((wastes.length / 6) * (i + 1)),
        matches: Math.round((matchData.length / 6) * (i + 1))
      })));
    } catch (err) {
      setError('Failed to load dashboard data. Make sure the backend is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const statCards = [
    { icon: Recycle, title: 'Waste Listed', value: stats.wasteListed, unit: 'streams', color: 'primary' },
    { icon: Factory, title: 'Resource Requests', value: stats.resourceRequests, unit: 'active', color: 'accent' },
    { icon: Zap, title: 'AI Matches', value: stats.activeMatches, unit: 'active', color: 'success' },
    { icon: Leaf, title: 'CO₂ Reduced', value: `${stats.co2Reduced.toFixed(1)}`, unit: 'tons', color: 'success' },
  ];

  if (loading) return (
    <div className="page-container">
      <div className="loading"><div className="spinner"></div></div>
    </div>
  );

  return (
    <div className="page-container fade-in">
      <div className="page-header">
        <h1 className="page-title">Welcome back, {user?.companyName || 'Industry Partner'}!</h1>
        <p className="page-subtitle">Track your industrial symbiosis performance and opportunities</p>
      </div>

      {error && (
        <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '1rem', marginBottom: '1.5rem', color: '#DC2626' }}>
          {error}
        </div>
      )}

      {/* Impact Metrics */}
      <div className="impact-grid">
        <div className="impact-card">
          <div className="impact-value">{stats.wasteDiverted.toLocaleString()}</div>
          <div className="impact-label">Tons Waste Diverted</div>
        </div>
        <div className="impact-card" style={{ background: 'linear-gradient(135deg, #10B981, #059669)' }}>
          <div className="impact-value">{stats.co2Reduced.toLocaleString()}</div>
          <div className="impact-label">Tons CO₂ Reduced</div>
        </div>
        <div className="impact-card" style={{ background: 'linear-gradient(135deg, #F59E0B, #D97706)' }}>
          <div className="impact-value">₹{(stats.costSavings / 100000).toFixed(1)}L</div>
          <div className="impact-label">Cost Savings</div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="dashboard-grid">
        {statCards.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div key={index} className="stat-card">
              <div className="stat-header">
                <div className={`stat-icon ${stat.color}`}><Icon size={24} /></div>
              </div>
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.unit}</div>
            </div>
          );
        })}
      </div>

      {/* Sustainability Score */}
      <div className="card" style={{ marginBottom: '2rem', marginTop: '2rem' }}>
        <div className="card-header">
          <h3 className="card-title">Sustainability Score</h3>
          <Link to="/impact" className="btn btn-outline" style={{ fontSize: '0.9rem' }}>
            View Details <ArrowRight size={16} />
          </Link>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '2rem', flexWrap: 'wrap' }}>
          <div className="score-circle" style={{
            background: `conic-gradient(var(--primary) ${sustainabilityScore}%, var(--border) ${sustainabilityScore}%)`
          }}>
            <div className="score-inner">
              <div className="score-value">{sustainabilityScore}</div>
              <div className="score-label">out of 100</div>
            </div>
          </div>
          <div style={{ flex: 1 }}>
            <h4 style={{ marginBottom: '1rem' }}>Score Breakdown</h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
              {Object.entries(scoreBreakdown).map(([key, val]) => (
                <div key={key}>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textTransform: 'capitalize' }}>
                    {key.replace(/([A-Z])/g, ' $1')}
                  </div>
                  <div style={{ fontWeight: 600, color: 'var(--primary)' }}>{val}/100</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '2rem', marginBottom: '2rem' }}>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Waste Listings Over Time</h3></div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis dataKey="month" stroke="#64748B" />
              <YAxis stroke="#64748B" />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }} />
              <Bar dataKey="waste" fill="#1F7A8C" radius={[4, 4, 0, 0]} name="Waste Listings" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Match Activity</h3></div>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis dataKey="month" stroke="#64748B" />
              <YAxis stroke="#64748B" />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }} />
              <Line type="monotone" dataKey="matches" stroke="#1F7A8C" strokeWidth={3} dot={{ fill: '#1F7A8C' }} name="Matches" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Matches */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Recent AI Matches</h3>
          <Link to="/matches" className="btn btn-primary" style={{ fontSize: '0.9rem' }}>View All</Link>
        </div>
        {recentMatches.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', padding: '1rem 0' }}>No matches yet. Add waste listings or resource requests to get started.</p>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Waste Type</th>
                  <th>Provider</th>
                  <th>Seeker</th>
                  <th>Quantity</th>
                  <th>Score</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentMatches.map((match) => (
                  <tr key={match.id}>
                    <td style={{ fontWeight: 500 }}>{match.wasteType}</td>
                    <td>{match.wasteProvider}</td>
                    <td>{match.resourceSeeker}</td>
                    <td>{match.quantity}</td>
                    <td>{match.matchScore}%</td>
                    <td>
                      <span className={`badge ${match.status === 'accepted' ? 'badge-success' : 'badge-warning'}`}>
                        {match.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '2rem' }}>
        <Link to="/waste-listings" className="card" style={{ textAlign: 'center', textDecoration: 'none', color: 'inherit' }}>
          <div className="stat-icon primary" style={{ margin: '0 auto 1rem' }}><Plus size={24} /></div>
          <h4>List Waste Stream</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Add new waste material</p>
        </Link>
        <Link to="/resource-requests" className="card" style={{ textAlign: 'center', textDecoration: 'none', color: 'inherit' }}>
          <div className="stat-icon accent" style={{ margin: '0 auto 1rem' }}><Factory size={24} /></div>
          <h4>Request Resources</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Find needed materials</p>
        </Link>
        <Link to="/network" className="card" style={{ textAlign: 'center', textDecoration: 'none', color: 'inherit' }}>
          <div className="stat-icon success" style={{ margin: '0 auto 1rem' }}><Zap size={24} /></div>
          <h4>View Network</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Explore symbiosis links</p>
        </Link>
        <Link to="/impact" className="card" style={{ textAlign: 'center', textDecoration: 'none', color: 'inherit' }}>
          <div className="stat-icon warning" style={{ margin: '0 auto 1rem' }}><Leaf size={24} /></div>
          <h4>Impact Report</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>View environmental data</p>
        </Link>
      </div>
    </div>
  );
};

export default DashboardPage;
