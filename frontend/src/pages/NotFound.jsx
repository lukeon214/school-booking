import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div style={{
      minHeight: '100vh',
      background: '#f5f7fa',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Poppins', sans-serif",
    }}>
      <div style={{
        background: '#fff',
        borderRadius: '18px',
        border: '1px solid #e8edf9',
        boxShadow: '0 4px 24px rgba(80,120,200,0.08)',
        padding: '56px 64px',
        textAlign: 'center',
        maxWidth: '400px',
        width: '100%',
      }}>
        <div style={{ fontSize: '5rem', fontWeight: 800, color: '#2c3a75', lineHeight: 1 }}>404</div>
        <p style={{ margin: '16px 0 32px', color: '#778bab', fontSize: '1rem' }}>Page not found</p>
        <Link
          to="/dashboard"
          style={{
            display: 'inline-block',
            background: '#4f7fff',
            color: '#fff',
            fontWeight: 700,
            fontSize: '0.95rem',
            padding: '12px 28px',
            borderRadius: '10px',
            textDecoration: 'none',
          }}
        >
          Go to Dashboard
        </Link>
      </div>
    </div>
  );
}
