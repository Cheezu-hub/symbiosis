import React, { useState, useEffect } from 'react';
import { Plus, Search, Filter, Edit, Trash2, MapPin, Package, Building, AlertCircle } from 'lucide-react';
import { resourceAPI } from '../services/api';

const emptyForm = {
  materialNeeded: '', description: '', quantity: '', unit: 'tons',
  industrySector: '', location: '', requiredBy: ''
};

const ResourceRequestsPage = ({ user }) => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [formData, setFormData] = useState(emptyForm);

  useEffect(() => { fetchRequests(); }, []);

  const fetchRequests = async () => {
    setLoading(true);
    try {
      const res = await resourceAPI.getAll();
      setRequests(res.data.data || []);
    } catch (err) {
      setError('Failed to load resource requests.');
    } finally {
      setLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingId(null);
    setFormData(emptyForm);
    setError('');
    setShowModal(true);
  };

  const openEditModal = (req) => {
    setEditingId(req.id);
    setFormData({
      materialNeeded: req.materialNeeded,
      description: req.description || '',
      quantity: req.quantity.toString(),
      unit: req.unit,
      industrySector: req.industrySector || '',
      location: req.location || '',
      requiredBy: req.requiredBy ? req.requiredBy.split('T')[0] : ''
    });
    setError('');
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    try {
      if (editingId) {
        await resourceAPI.update(editingId, { ...formData, quantity: parseFloat(formData.quantity) });
      } else {
        await resourceAPI.create({ ...formData, quantity: parseFloat(formData.quantity) });
      }
      setShowModal(false);
      await fetchRequests();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to save request.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this resource request?')) return;
    try {
      await resourceAPI.delete(id);
      setRequests(prev => prev.filter(r => r.id !== id));
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to delete request.');
    }
  };

  const filtered = requests.filter(r =>
    r.materialNeeded.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (r.description || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const activeCount = requests.filter(r => r.status === 'active').length;
  const fulfilledCount = requests.filter(r => r.status === 'fulfilled').length;

  return (
    <div className="page-container fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Resource Requests</h1>
          <p className="page-subtitle">Find and request materials you need from other industries</p>
        </div>
        <button className="btn btn-primary" onClick={openCreateModal}>
          <Plus size={20} /> Create Request
        </button>
      </div>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '300px' }}>
            <div style={{ position: 'relative' }}>
              <Search size={20} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input type="text" className="form-input" placeholder="Search materials needed..."
                value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '3rem', marginBottom: 0 }} />
            </div>
          </div>
          <button className="btn btn-outline"><Filter size={20} /> Filter</button>
        </div>
      </div>

      <div className="dashboard-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon primary"><Package size={24} /></div></div>
          <div className="stat-value">{activeCount}</div>
          <div className="stat-label">Active Requests</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon success"><Building size={24} /></div></div>
          <div className="stat-value">{fulfilledCount}</div>
          <div className="stat-label">Fulfilled Requests</div>
        </div>
        <div className="stat-card">
          <div className="stat-header"><div className="stat-icon accent"><MapPin size={24} /></div></div>
          <div className="stat-value">{requests.length}</div>
          <div className="stat-label">Total Requests</div>
        </div>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner"></div></div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '4rem' }}>
          <Package size={64} style={{ color: 'var(--text-muted)', marginBottom: '1rem' }} />
          <h3 style={{ marginBottom: '0.5rem' }}>No Resource Requests</h3>
          <p style={{ color: 'var(--text-secondary)' }}>Create your first request to find materials</p>
        </div>
      ) : (
        <div className="dashboard-grid">
          {filtered.map((req) => (
            <div key={req.id} className="card">
              <div className="card-header">
                <h3 className="card-title" style={{ fontSize: '1.1rem' }}>{req.materialNeeded}</h3>
                <span className={`badge ${req.status === 'active' ? 'badge-success' : 'badge-primary'}`}>{req.status}</span>
              </div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.9rem' }}>{req.description || '—'}</p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
                <Package size={16} /><span>{req.quantity} {req.unit}</span>
              </div>
              {req.industrySector && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
                  <Building size={16} /><span>{req.industrySector} Industry</span>
                </div>
              )}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}>
                <MapPin size={16} /><span>{req.location || '—'}</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-outline" style={{ flex: 1, fontSize: '0.85rem' }} onClick={() => openEditModal(req)}>
                  <Edit size={16} /> Edit
                </button>
                <button className="btn btn-outline" style={{ color: 'var(--error)', borderColor: 'var(--error)', flex: 1, fontSize: '0.85rem' }} onClick={() => handleDelete(req.id)}>
                  <Trash2 size={16} /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">{editingId ? 'Edit Request' : 'Create Resource Request'}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#DC2626' }}>
                <AlertCircle size={16} /><span style={{ fontSize: '0.9rem' }}>{error}</span>
              </div>
            )}
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label className="form-label">Material Needed</label>
                <input type="text" className="form-input" value={formData.materialNeeded}
                  onChange={(e) => setFormData({ ...formData, materialNeeded: e.target.value })}
                  placeholder="e.g., Fly Ash, Steel Slag" required />
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea className="form-textarea" value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Describe your requirements..." />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Quantity</label>
                  <input type="number" className="form-input" value={formData.quantity}
                    onChange={(e) => setFormData({ ...formData, quantity: e.target.value })}
                    placeholder="100" min="0" required />
                </div>
                <div className="form-group">
                  <label className="form-label">Unit</label>
                  <select className="form-select" value={formData.unit} onChange={(e) => setFormData({ ...formData, unit: e.target.value })}>
                    <option value="tons">Tons</option>
                    <option value="kg">Kilograms</option>
                    <option value="MWh">MWh</option>
                    <option value="liters">Liters</option>
                  </select>
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Industry Sector</label>
                <select className="form-select" value={formData.industrySector} onChange={(e) => setFormData({ ...formData, industrySector: e.target.value })}>
                  <option value="">Select Sector</option>
                  <option value="Cement">Cement</option>
                  <option value="Construction">Construction</option>
                  <option value="Energy">Energy</option>
                  <option value="Chemical">Chemical</option>
                  <option value="Manufacturing">Manufacturing</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Location</label>
                <input type="text" className="form-input" value={formData.location}
                  onChange={(e) => setFormData({ ...formData, location: e.target.value })} placeholder="City, State" />
              </div>
              <div className="form-group">
                <label className="form-label">Required By</label>
                <input type="date" className="form-input" value={formData.requiredBy}
                  onChange={(e) => setFormData({ ...formData, requiredBy: e.target.value })} />
              </div>
              <div style={{ display: 'flex', gap: '1rem', marginTop: '2rem' }}>
                <button type="button" className="btn btn-outline" style={{ flex: 1 }} onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={saving}>
                  {saving ? 'Saving...' : editingId ? 'Save Changes' : 'Create Request'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ResourceRequestsPage;
