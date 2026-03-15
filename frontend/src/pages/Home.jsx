import { Link } from 'react-router-dom';
import './Home.css';

const features = [
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4f7fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
        <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
      </svg>
    ),
    title: '14 question types',
    description: 'Short text, grids, ratings, dropdowns, date pickers, and more — all in one editor.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4f7fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
      </svg>
    ),
    title: 'Real-time responses',
    description: 'Watch submissions come in as they happen. Export to CSV whenever you need.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4f7fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/>
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
      </svg>
    ),
    title: 'Share anywhere',
    description: 'Send a link, scan a QR code, or embed your form directly on any webpage.',
  },
];

export default function Home() {
  return (
    <div className="home-page">

      {/* ── Nav ── */}
      <nav className="home-nav">
        <span className="home-logo">
          <span className="home-logo-data">data</span><span className="home-logo-booq">booq</span>
        </span>
        <div className="home-nav-actions">
          <Link to="/login" className="home-nav-login">Log in</Link>
          <Link to="/register" className="home-btn home-btn--sm">Get Started</Link>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="home-hero">
        <h1 className="home-hero-heading">Build forms that work.</h1>
        <p className="home-hero-sub">
          Create, share, and collect responses with a simple and powerful form builder.
        </p>
        <Link to="/register" className="home-btn home-btn--lg">Get Started — it's free</Link>
        <p className="home-hero-login">
          Already have an account?{' '}
          <Link to="/login" className="home-hero-login-link">Log in</Link>
        </p>
      </section>

      {/* ── Features ── */}
      <section className="home-features">
        {features.map((f, i) => (
          <div key={i} className="home-feature-card">
            <div className="home-feature-icon">{f.icon}</div>
            <h3 className="home-feature-title">{f.title}</h3>
            <p className="home-feature-desc">{f.description}</p>
          </div>
        ))}
      </section>

      {/* ── Footer ── */}
      <footer className="home-footer">
        <p>© 2026 databooq</p>
      </footer>

    </div>
  );
}
