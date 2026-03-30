import React from 'react';
import { Link } from 'react-router-dom';
import { Recycle, Zap, Leaf, Globe, TrendingUp, Shield, ArrowRight, Check, Factory } from 'lucide-react';
import { motion } from 'framer-motion';

const HomePage = ({ onLogin }) => {
  const features = [
    {
      icon: Zap,
      title: 'AI Semantic Matching',
      description: 'Advanced NLP models match waste materials with industrial requirements automatically.',
      color: '#1F7A8C'
    },
    {
      icon: Leaf,
      title: 'Environmental Impact',
      description: 'Calculate CO₂ reduction, landfill diversion, and raw material savings in real-time.',
      color: '#10B981'
    },
    {
      icon: Globe,
      title: 'Network Visualization',
      description: 'Visualize industrial symbiosis relationships with interactive network graphs.',
      color: '#00C9B1'
    },
    {
      icon: TrendingUp,
      title: 'Sustainability Score',
      description: 'Track your circular economy performance with our comprehensive scoring system.',
      color: '#F59E0B'
    },
    {
      icon: Shield,
      title: 'Smart Logistics',
      description: 'Optimize transportation routes and get accurate cost estimates for material exchange.',
      color: '#1F7A8C'
    },
    {
      icon: Recycle,
      title: 'Opportunity Detection',
      description: 'Automatically detect potential industrial symbiosis opportunities in your sector.',
      color: '#00C9B1'
    }
  ];

  const stats = [
    { value: '500+', label: 'Industries Connected' },
    { value: '50K+', label: 'Tons Waste Diverted' },
    { value: '100K+', label: 'Tons CO₂ Reduced' },
    { value: '₹10Cr+', label: 'Cost Savings Generated' }
  ];

  const industries = [
    'Steel Plants',
    'Cement Factories',
    'Chemical Industries',
    'Manufacturing Companies',
    'Energy Plants',
    'Textile Industries'
  ];

  return (
    <div className="home-page">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="page-container">
          <motion.div 
            className="hero-content"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="hero-title">
              Transform Industrial Waste into
              <span style={{ color: 'var(--primary)' }}> Valuable Resources</span>
            </h1>
            <p className="hero-subtitle">
              AI-powered industrial symbiosis platform connecting industries to exchange waste 
              materials and resources, enabling circular economy practices.
            </p>
            <div className="hero-actions">
              <Link to="/register" className="btn btn-primary" style={{ fontSize: '1.1rem', padding: '1rem 2rem' }}>
                Get Started Free
                <ArrowRight size={20} />
              </Link>
              <Link to="/dashboard" className="btn btn-secondary" style={{ fontSize: '1.1rem', padding: '1rem 2rem' }}>
                View Demo
              </Link>
            </div>
          </motion.div>

          <motion.div 
            className="hero-stats"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.3 }}
          >
            {stats.map((stat, index) => (
              <div key={index} className="stat-card hero-stat">
                <div className="stat-value">{stat.value}</div>
                <div className="stat-label">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section" style={{ padding: '4rem 2rem', background: 'var(--background)' }}>
        <div className="page-container">
          <motion.div 
            className="section-header"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
          >
            <h2 style={{ fontSize: '2.5rem', marginBottom: '1rem', textAlign: 'center' }}>
              Powerful Features for Industrial Symbiosis
            </h2>
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', maxWidth: '600px', margin: '0 auto' }}>
              Our platform provides comprehensive tools to help industries reduce waste, 
              save costs, and contribute to a sustainable future.
            </p>
          </motion.div>

          <div className="features-grid" style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', 
            gap: '2rem',
            marginTop: '3rem'
          }}>
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={index}
                  className="card feature-card"
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: index * 0.1 }}
                  style={{ borderTop: `4px solid ${feature.color}` }}
                >
                  <div className="stat-icon" style={{ 
                    background: `${feature.color}15`, 
                    color: feature.color,
                    marginBottom: '1rem'
                  }}>
                    <Icon size={24} />
                  </div>
                  <h3 style={{ marginBottom: '0.75rem' }}>{feature.title}</h3>
                  <p style={{ color: 'var(--text-secondary)' }}>{feature.description}</p>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Industries Section */}
      <section className="industries-section" style={{ padding: '4rem 2rem', background: 'var(--surface)' }}>
        <div className="page-container">
          <div className="section-header" style={{ textAlign: 'center', marginBottom: '3rem' }}>
            <h2 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>
              Industries We Serve
            </h2>
            <p style={{ color: 'var(--text-secondary)', maxWidth: '600px', margin: '0 auto' }}>
              Connecting diverse industries to create a sustainable industrial ecosystem
            </p>
          </div>

          <div className="industries-grid" style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
            gap: '1.5rem'
          }}>
            {industries.map((industry, index) => (
              <motion.div
                key={index}
                className="card"
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
                style={{ textAlign: 'center', padding: '2rem' }}
              >
                <div className="stat-icon primary" style={{ margin: '0 auto 1rem' }}>
                  <Factory size={24} />
                </div>
                <h4 style={{ color: 'var(--primary)' }}>{industry}</h4>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section" style={{ 
        padding: '4rem 2rem', 
        background: 'linear-gradient(135deg, var(--primary), var(--primary-light))',
        color: 'white',
        textAlign: 'center'
      }}>
        <div className="page-container">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <h2 style={{ fontSize: '2.5rem', marginBottom: '1rem', color: 'white' }}>
              Ready to Transform Your Industrial Waste?
            </h2>
            <p style={{ marginBottom: '2rem', opacity: 0.9, maxWidth: '600px', margin: '0 auto 2rem' }}>
              Join hundreds of industries already saving costs and reducing environmental impact 
              through intelligent resource sharing.
            </p>
            <Link to="/register" className="btn" style={{ 
              background: 'white', 
              color: 'var(--primary)',
              fontSize: '1.1rem',
              padding: '1rem 2rem'
            }}>
              Start Your Journey
              <ArrowRight size={20} />
            </Link>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ 
        background: 'var(--text-primary)', 
        color: 'white', 
        padding: '3rem 2rem',
        marginTop: 'auto'
      }}>
        <div className="page-container">
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
            gap: '2rem' 
          }}>
            <div>
              <div className="logo" style={{ color: 'white', marginBottom: '1rem' }}>
                <Recycle size={24} />
                SymbioTech
              </div>
              <p style={{ opacity: 0.8, fontSize: '0.9rem' }}>
                AI-powered industrial symbiosis platform enabling circular economy practices.
              </p>
            </div>
            <div>
              <h4 style={{ color: 'white', marginBottom: '1rem' }}>Platform</h4>
              <ul style={{ listStyle: 'none', opacity: 0.8 }}>
                <li style={{ marginBottom: '0.5rem' }}><Link to="/dashboard" style={{ color: 'white', textDecoration: 'none' }}>Dashboard</Link></li>
                <li style={{ marginBottom: '0.5rem' }}><Link to="/matches" style={{ color: 'white', textDecoration: 'none' }}>AI Matches</Link></li>
                <li style={{ marginBottom: '0.5rem' }}><Link to="/network" style={{ color: 'white', textDecoration: 'none' }}>Network</Link></li>
              </ul>
            </div>
            <div>
              <h4 style={{ color: 'white', marginBottom: '1rem' }}>Company</h4>
              <ul style={{ listStyle: 'none', opacity: 0.8 }}>
                <li style={{ marginBottom: '0.5rem' }}>About Us</li>
                <li style={{ marginBottom: '0.5rem' }}>Careers</li>
                <li style={{ marginBottom: '0.5rem' }}>Contact</li>
              </ul>
            </div>
            <div>
              <h4 style={{ color: 'white', marginBottom: '1rem' }}>Legal</h4>
              <ul style={{ listStyle: 'none', opacity: 0.8 }}>
                <li style={{ marginBottom: '0.5rem' }}>Privacy Policy</li>
                <li style={{ marginBottom: '0.5rem' }}>Terms of Service</li>
                <li style={{ marginBottom: '0.5rem' }}>Cookie Policy</li>
              </ul>
            </div>
          </div>
          <div style={{ 
            borderTop: '1px solid rgba(255,255,255,0.1)', 
            marginTop: '2rem', 
            paddingTop: '2rem', 
            textAlign: 'center',
            opacity: 0.8
          }}>
            <p>© 2024 SymbioTech. All rights reserved.</p>
          </div>
        </div>
      </footer>

      <style>{`
        .hero-section {
          padding: 6rem 2rem 4rem;
          background: linear-gradient(135deg, #F8FAFC 0%, #E0F2F1 100%);
        }
        
        .hero-title {
          font-size: 3.5rem;
          line-height: 1.2;
          margin-bottom: 1.5rem;
          max-width: 800px;
        }
        
        .hero-subtitle {
          font-size: 1.25rem;
          color: var(--text-secondary);
          margin-bottom: 2rem;
          max-width: 600px;
        }
        
        .hero-actions {
          display: flex;
          gap: 1rem;
          margin-bottom: 4rem;
        }
        
        .hero-stats {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 1.5rem;
        }
        
        .hero-stat {
          text-align: center;
        }
        
        .hero-stat .stat-value {
          color: var(--primary);
        }
        
        @media (max-width: 768px) {
          .hero-title {
            font-size: 2.5rem;
          }
          
          .hero-stats {
            grid-template-columns: repeat(2, 1fr);
          }
          
          .hero-actions {
            flex-direction: column;
          }
        }
      `}</style>
    </div>
  );
};

export default HomePage;