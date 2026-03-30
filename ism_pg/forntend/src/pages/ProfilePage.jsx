import React, { useState, useEffect } from 'react';
import { User, Building, Mail, Phone, MapPin, Shield, Bell, LogOut, Save, AlertCircle, CheckCircle } from 'lucide-react';
import { authAPI } from '../services/api';

const ProfilePage = ({ user, onLogout }) => {
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [profileData, setProfileData] = useState({
    companyName: '', industryType: '', email: '',
    phone: '', location: '', transportRadius: '', website: ''
  });
  const [notifications, setNotifications] = useState({
    emailMatches: true, newOpportunities: true, impactReports: false, systemUpdates: true
  });

  useEffect(() => { fetchProfile(); }, []);

  const fetchProfile = async () => {
    setLoading(true);
    try {
      const res = await authAPI.getProfile();
      const u = res.data.user;
      setProfileData({
        companyName: u.companyName || '',
        industryType: u.industryType || '',
        email: u.email || '',
        phone: u.phone || '',
        location: u.location || '',
        transportRadius: u.transportRadius?.toString() || '',
        website: u.website || ''
      });
    } catch (err) {
      setError('Failed to load profile.');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      await authAPI.updateProfile({
        companyName: profileData.companyName,
        industryType: profileData.industryType,
        phone: profileData.phone,
        location: profileData.location,
        transportRadius: profileData.transportRadius ? parseInt(profileData.transportRadius) : null,
        website: profileData.website
      });
      setIsEditing(false);
      setSuccess('Profile updated successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update profile.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return (
    <div className="page-container">
      <div className="loading"><div className="spinner"></div></div>
    </div>
  );

  return (
    <div className="page-container fade-in">
      <div className="page-header">
        <h1 className="page-title">Profile & Settings</h1>
        <p className="page-subtitle">Manage your account and company information</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '2rem', flexWrap: 'wrap' }}>
        {/* Sidebar */}
        <div>
          <div className="card" style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
            <div style={{
              width: '90px', height: '90px', borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--primary), var(--accent))',
              margin: '0 auto 1rem', display: 'flex', alignItems: 'center',
              justifyContent: 'center', color: 'white', fontSize: '2rem', fontWeight: 700
            }}>
              {(profileData.companyName || 'U').charAt(0).toUpperCase()}
            </div>
            <h3 style={{ marginBottom: '0.25rem' }}>{profileData.companyName || '—'}</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textTransform: 'capitalize' }}>
              {profileData.industryType} Industry
            </p>
            <div style={{ marginTop: '1rem' }}>
              <span className="badge badge-success">Verified</span>
            </div>
          </div>

          <button
            className="btn btn-outline"
            style={{ width: '100%', color: 'var(--error)', borderColor: 'var(--error)' }}
            onClick={onLogout}
          >
            <LogOut size={18} /> Logout
          </button>
        </div>

        {/* Main Content */}
        <div>
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#DC2626' }}>
              <AlertCircle size={16} /><span style={{ fontSize: '0.9rem' }}>{error}</span>
            </div>
          )}
          {success && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: 'var(--radius)', padding: '0.75rem 1rem', marginBottom: '1rem', color: '#16A34A' }}>
              <CheckCircle size={16} /><span style={{ fontSize: '0.9rem' }}>{success}</span>
            </div>
          )}

          {/* Company Info */}
          <div className="card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-header">
              <h3 className="card-title">Company Information</h3>
              <button
                className="btn btn-primary"
                onClick={() => isEditing ? handleSave() : setIsEditing(true)}
                disabled={saving}
              >
                {isEditing ? <Save size={18} /> : <User size={18} />}
                {saving ? 'Saving...' : isEditing ? 'Save Changes' : 'Edit Profile'}
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem' }}>
              {[
                { label: 'Company Name', field: 'companyName', icon: Building, type: 'text' },
                { label: 'Email Address', field: 'email', icon: Mail, type: 'email', readOnly: true },
                { label: 'Phone Number', field: 'phone', icon: Phone, type: 'tel' },
                { label: 'Location', field: 'location', icon: MapPin, type: 'text' },
                { label: 'Transport Radius (km)', field: 'transportRadius', type: 'number' },
                { label: 'Website', field: 'website', type: 'url' },
              ].map(({ label, field, icon: Icon, type, readOnly }) => (
                <div className="form-group" key={field}>
                  <label className="form-label">
                    {Icon && <Icon size={15} style={{ display: 'inline', marginRight: '0.4rem' }} />}
                    {label}
                  </label>
                  <input
                    type={type}
                    className="form-input"
                    value={profileData[field]}
                    onChange={(e) => setProfileData({ ...profileData, [field]: e.target.value })}
                    disabled={!isEditing || readOnly}
                  />
                </div>
              ))}

              <div className="form-group">
                <label className="form-label">Industry Type</label>
                <select
                  className="form-select"
                  value={profileData.industryType}
                  onChange={(e) => setProfileData({ ...profileData, industryType: e.target.value })}
                  disabled={!isEditing}
                >
                  <option value="">Select Industry</option>
                  <option value="steel">Steel Plant</option>
                  <option value="cement">Cement Factory</option>
                  <option value="chemical">Chemical Industry</option>
                  <option value="manufacturing">Manufacturing</option>
                  <option value="energy">Energy Plant</option>
                  <option value="textile">Textile Industry</option>
                </select>
              </div>
            </div>
          </div>

          {/* Notification Settings */}
          <div className="card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-header"><h3 className="card-title">Notifications</h3></div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {[
                { key: 'emailMatches', label: 'AI Match Recommendations', desc: 'Get notified when new matches are found' },
                { key: 'newOpportunities', label: 'New Symbiosis Opportunities', desc: 'Alerts for potential collaborations' },
                { key: 'impactReports', label: 'Monthly Impact Reports', desc: 'Receive environmental impact summaries' },
                { key: 'systemUpdates', label: 'System Updates', desc: 'Platform updates and maintenance notices' },
              ].map(({ key, label, desc }) => (
                <label key={key} style={{ display: 'flex', alignItems: 'center', gap: '1rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={notifications[key]}
                    onChange={() => setNotifications({ ...notifications, [key]: !notifications[key] })}
                    style={{ width: '18px', height: '18px' }}
                  />
                  <div>
                    <div style={{ fontWeight: 500 }}>{label}</div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Account Actions */}
          <div className="card">
            <h3 className="card-title" style={{ marginBottom: '1rem' }}>Account Actions</h3>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <button className="btn btn-outline"><Bell size={18} /> View All Notifications</button>
              <button
                className="btn btn-outline"
                style={{ color: 'var(--error)', borderColor: 'var(--error)' }}
                onClick={onLogout}
              >
                Delete Account
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
