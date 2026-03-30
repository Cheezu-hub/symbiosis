import React, { useState, useEffect } from 'react';
import { Globe, Users, Link as LinkIcon, RefreshCw } from 'lucide-react';
import { industryAPI } from '../services/api';

const NODE_COLORS = {
  steel: '#1F7A8C', cement: '#10B981', construction: '#F59E0B',
  energy: '#00C9B1', chemical: '#EF4444', textile: '#8B5CF6',
  manufacturing: '#F97316', default: '#64748B'
};

// Simple force-layout approximation using fixed positions spread in a circle
const layoutNodes = (nodes) => {
  const cx = 400, cy = 250, r = 180;
  return nodes.map((node, i) => ({
    ...node,
    x: cx + r * Math.cos((2 * Math.PI * i) / nodes.length),
    y: cy + r * Math.sin((2 * Math.PI * i) / nodes.length),
  }));
};

const NetworkPage = ({ user }) => {
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tooltip, setTooltip] = useState(null);

  useEffect(() => { fetchNetwork(); }, []);

  const fetchNetwork = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await industryAPI.getNetwork();
      const data = res.data.data || {};
      setNodes(layoutNodes(data.nodes || []));
      setLinks(data.links || []);
    } catch (err) {
      setError('Failed to load network data.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return (
    <div className="page-container">
      <div className="loading"><div className="spinner"></div></div>
    </div>
  );

  return (
    <div className="page-container fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Industrial Symbiosis Network</h1>
          <p className="page-subtitle">Visualize resource flow relationships between industries</p>
        </div>
        <button className="btn btn-outline" onClick={fetchNetwork}><RefreshCw size={18} /> Refresh</button>
      </div>

      {error && (
        <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '1rem', marginBottom: '1.5rem', color: '#DC2626' }}>
          {error}
        </div>
      )}

      <div className="dashboard-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon primary"><Users size={24} /></div></div>
          <div className="stat-value">{nodes.length}</div>
          <div className="stat-label">Connected Industries</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon accent"><LinkIcon size={24} /></div></div>
          <div className="stat-value">{links.length}</div>
          <div className="stat-label">Active Symbiosis Links</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon success"><Globe size={24} /></div></div>
          <div className="stat-value">{new Set(nodes.map(n => n.type)).size}</div>
          <div className="stat-label">Industry Types</div>
        </div>
      </div>

      {nodes.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '4rem' }}>
          <Globe size={64} style={{ color: 'var(--text-muted)', marginBottom: '1rem' }} />
          <h3 style={{ marginBottom: '0.5rem' }}>No Network Data</h3>
          <p style={{ color: 'var(--text-secondary)' }}>Accept matches to build the symbiosis network</p>
        </div>
      ) : (
        <div className="network-container" style={{ position: 'relative' }}>
          <svg width="100%" height="100%" viewBox="0 0 800 500">
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#1F7A8C" opacity="0.6" />
              </marker>
            </defs>

            {/* Links */}
            {links.map((link, index) => {
              const source = nodes.find(n => n.id === link.source);
              const target = nodes.find(n => n.id === link.target);
              if (!source || !target) return null;
              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;
              return (
                <g key={index}>
                  <line
                    x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                    stroke="#1F7A8C" strokeWidth={Math.max(1, (link.value || 100) / 100)}
                    opacity={0.5} markerEnd="url(#arrowhead)"
                  />
                  <text x={midX} y={midY - 6} textAnchor="middle" fontSize="10" fill="#64748B">{link.material}</text>
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const color = NODE_COLORS[node.type] || NODE_COLORS.default;
              return (
                <g key={node.id}
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={() => setTooltip(node)}
                  onMouseLeave={() => setTooltip(null)}
                >
                  <circle cx={node.x} cy={node.y} r={32} fill={color} opacity={0.9} />
                  <circle cx={node.x} cy={node.y} r={26} fill="white" opacity={0.15} />
                  <text x={node.x} y={node.y + 48} textAnchor="middle" fontSize="11" fill="#1E293B" fontWeight="600">
                    {node.label.length > 18 ? node.label.slice(0, 16) + '…' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {tooltip && (
            <div style={{
              position: 'absolute', top: 16, right: 16,
              background: 'white', border: '1px solid var(--border)',
              borderRadius: 'var(--radius)', padding: '1rem', minWidth: '160px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
            }}>
              <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>{tooltip.label}</div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', textTransform: 'capitalize' }}>{tooltip.type}</div>
              {tooltip.location && <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{tooltip.location}</div>}
            </div>
          )}
        </div>
      )}

      {/* Legend */}
      <div className="card" style={{ marginTop: '2rem' }}>
        <h3 style={{ marginBottom: '1rem' }}>Industry Types</h3>
        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
          {Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: color }}></div>
              <span style={{ textTransform: 'capitalize', fontSize: '0.9rem' }}>{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default NetworkPage;
