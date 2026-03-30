import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  Factory, 
  Recycle, 
  MapPin, 
  TrendingUp, 
  Users, 
  Settings,
  Plus,
  Search,
  Bell,
  Menu,
  X,
  Leaf,
  Truck,
  Zap,
  Globe
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// Import Pages
import HomePage from './pages/HomePage';
import DashboardPage from './pages/DashboardPage';
import WasteListingsPage from './pages/WasteListingsPage';
import ResourceRequestsPage from './pages/ResourceRequestsPage';
import MatchesPage from './pages/MatchesPage';
import NetworkPage from './pages/NetworkPage';
import ImpactPage from './pages/ImpactPage';
import ProfilePage from './pages/ProfilePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';

// Navigation Component
const Navbar = ({ isLoggedIn, onLogout }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

  const navLinks = [
    { path: '/dashboard', label: 'Dashboard', icon: Home },
    { path: '/waste-listings', label: 'Waste Listings', icon: Recycle },
    { path: '/resource-requests', label: 'Resource Requests', icon: Factory },
    { path: '/matches', label: 'AI Matches', icon: Zap },
    { path: '/network', label: 'Network', icon: Globe },
    { path: '/impact', label: 'Impact', icon: Leaf },
  ];

  return (
    <nav className="navbar">
      <div className="nav-content">
        <Link to="/" className="logo">
          <div className="logo-icon">
            <Recycle size={24} />
          </div>
          SymbioTech
        </Link>

        {isLoggedIn && (
          <>
            <div className="nav-links">
              {navLinks.map((link) => {
                const Icon = link.icon;
                return (
                  <Link
                    key={link.path}
                    to={link.path}
                    className={`nav-link ${location.pathname === link.path ? 'active' : ''}`}
                  >
                    <Icon size={18} style={{ marginRight: '0.5rem' }} />
                    {link.label}
                  </Link>
                );
              })}
            </div>

            <div className="nav-links">
              <button className="btn btn-outline" style={{ marginRight: '0.5rem' }}>
                <Bell size={18} />
              </button>
              <Link to="/profile" className="btn btn-primary">
                <Users size={18} />
                Profile
              </Link>
            </div>
          </>
        )}

        {!isLoggedIn && (
          <div className="nav-links">
            <Link to="/login" className="btn btn-outline">Login</Link>
            <Link to="/register" className="btn btn-primary">Get Started</Link>
          </div>
        )}

        <button 
          className="btn btn-outline" 
          style={{ display: 'none' }}
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>
    </nav>
  );
};

// Main App Component
function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('symbiotech_user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
      setIsLoggedIn(true);
    }
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
    setIsLoggedIn(true);
    localStorage.setItem('symbiotech_user', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setUser(null);
    setIsLoggedIn(false);
    localStorage.removeItem('symbiotech_user');
  };

  return (
    <Router>
      <div className="app-container">
        <Navbar isLoggedIn={isLoggedIn} onLogout={handleLogout} />
        <main>
          <Routes>
            <Route path="/" element={<HomePage onLogin={handleLogin} />} />
            <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
            <Route path="/register" element={<RegisterPage onLogin={handleLogin} />} />
            <Route path="/dashboard" element={isLoggedIn ? <DashboardPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/waste-listings" element={isLoggedIn ? <WasteListingsPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/resource-requests" element={isLoggedIn ? <ResourceRequestsPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/matches" element={isLoggedIn ? <MatchesPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/network" element={isLoggedIn ? <NetworkPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/impact" element={isLoggedIn ? <ImpactPage user={user} /> : <LoginPage onLogin={handleLogin} />} />
            <Route path="/profile" element={isLoggedIn ? <ProfilePage user={user} onLogout={handleLogout} /> : <LoginPage onLogin={handleLogin} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;