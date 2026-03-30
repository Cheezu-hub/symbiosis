import React, { useState, useEffect } from 'react';
import { Plus, Search, Filter, Edit, Trash2, MapPin, Package, AlertCircle } from 'lucide-react';
import { wasteAPI } from '../services/api';

const emptyForm = {
  materialType: '', description: '', quantity: '', unit: 'tons', location: '', availableFrom: ''
};

const WasteListingsPage = ({ user }) => {
  const [listings, setListings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [formData, setFormData] = useState(emptyForm);

  useEffect(() => { fetchListings(); }, []);

  const fetchListings = async () => {
    setLoading(true);
    try {
      const res = await wasteAPI.getAll();
      setListings(res.data.data || []);
    } catch (err) {
      setError('Failed to load waste listings.');
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

  const openEditModal = (listing) => {
    setEditingId(listing.id);
    setFormData({
      materialType: listing.materialType,
      description: listing.description || '',
      quantity: listing.quantity.toString(),
      unit: listing.unit,
      location: listing.location || '',
      availableFrom: listing.availableFrom ? listing.availableFrom.split('T')[0] : ''
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
        await wasteAPI.update(editingId, { ...formData, quantity: parseFloat(formData.quantity) });
      } else {
        await wasteAPI.create({ ...formData, quantity: parseFloat(formData.quantity) });
      }
      setShowModal(false);
      await fetchListings();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to save listing.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this waste listing?')) return;
    try {
      await wasteAPI.delete(id);
      setListings(prev => prev.filter(l => l.id !== id));
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to delete listing.');
    }
  };

  const filtered = listings.filter(l =>
    l.materialType.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (l.description || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="page-container fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Waste Listings</h1>
          <p className="page-subtitle">Manage your available waste streams for industrial symbiosis</p>
        </div>
        <button className="btn btn-primary" onClick={openCreateModal}>
          <Plus size={20} /> Add Waste Stream
        </button>
      </div>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '300px' }}>
            <div style={{ position: 'relative' }}>
              <Search size={20} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search waste materials..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '3rem', marginBottom: 0 }}
              />
            </div>
          </div>
          <button className="btn btn-outline"><Filter size={20} /> Filter</button>
        </div>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner"></div></div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '4rem' }}>
          <Package size={64} style={{ color: 'var(--text-muted)', marginBottom: '1rem' }} />
          <h3 style={{ marginBottom: '0.5rem' }}>No Waste Listings</h3>
          <p style={{ color: 'var(--text-secondary)' }}>Add your first waste stream to get started</p>
        </div>
      ) : (
        <div className="dashboard-grid">
          {filtered.map((listing) => (
            <div key={listing.id} className="card">
              <div className="card-header">
                <h3 className="card-title" style={{ fontSize: '1.1rem' }}>{listing.materialType}</h3>
                <span className={`badge ${listing.status === 'available' ? 'badge-success' : 'badge-warning'}`}>
                  {listing.status}
                </span>
              </div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.9rem' }}>
                {listing.description || '—'}
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
                <Package size={16} /><span>{listing.quantity} {listing.unit}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}>
                <MapPin size={16} /><span>{listing.location || '—'}</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-outline" style={{ flex: 1, fontSize: '0.85rem' }} onClick={() => openEditModal(listing)}>
                  <Edit size={16} /> Edit
                </button>
                <button className="btn btn-outline" style={{ color: 'var(--error)', borderColor: 'var(--error)', flex: 1, fontSize: '0.85rem' }} onClick={() => handleDelete(listing.id)}>
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
              <h3 className="modal-title">{editingId ? 'Edit Waste Listing' : 'Add Waste Stream'}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>

            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#DC2626' }}>
                <AlertCircle size={16} /><span style={{ fontSize: '0.9rem' }}>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label className="form-label">Material Type</label>
                <input type="text" className="form-input" value={formData.materialType}
                  onChange={(e) => setFormData({ ...formData, materialType: e.target.value })}
                  placeholder="e.g., Fly Ash, Steel Slag" required />
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea className="form-textarea" value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Describe the material..." />
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
                  <select className="form-select" value={formData.unit}
                    onChange={(e) => setFormData({ ...formData, unit: e.target.value })}>
                    <option value="tons">Tons</option>
                    <option value="kg">Kilograms</option>
                    <option value="MWh">MWh</option>
                    <option value="liters">Liters</option>
                  </select>
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Location</label>
                <input type="text" className="form-input" value={formData.location}
                  onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  placeholder="City, State" />
              </div>
              <div className="form-group">
                <label className="form-label">Available From</label>
                <input type="date" className="form-input" value={formData.availableFrom}
                  onChange={(e) => setFormData({ ...formData, availableFrom: e.target.value })} />
              </div>
              <div style={{ display: 'flex', gap: '1rem', marginTop: '2rem' }}>
                <button type="button" className="btn btn-outline" style={{ flex: 1 }} onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={saving}>
                  {saving ? 'Saving...' : editingId ? 'Save Changes' : 'Add Listing'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default WasteListingsPage;
