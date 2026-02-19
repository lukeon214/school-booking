// frontend/src/pages/ForgotPassword.jsx (styled with modern-form)
import { useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/forgot-password`, { email });
      setMessage(res.data.message);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Error');
      setMessage('');
    }
  };

  return (
    <div className="auth-page">
      <form className="modern-form-bu" onSubmit={handleSubmit}>
        <div className="form-title">Forgot Password</div>

        <div className="form-body">
          <div className="input-group-auth">
            <div className="input-wrapper">
              <svg fill="none" viewBox="0 0 24 24" className="input-icon">
                <path
                  stroke-width="1.5"
                  stroke="currentColor"
                  d="M3 8L10.8906 13.2604C11.5624 13.7083 12.4376 13.7083 13.1094 13.2604L21 8M5 19H19C20.1046 19 21 18.1046 21 17V7C21 5.89543 20.1046 5 19 5H5C3.89543 5 3 5.89543 3 7V17C3 18.1046 3.89543 19 5 19Z"
                ></path>
              </svg>
              <input
                required
                placeholder="Email"
                className="form-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>
        </div>

        <button className="submit-button" type="submit">
          <span className="button-text">Send Reset Link</span>
          <div className="button-glow"></div>
        </button>

        <div className="form-footer">
          <Link className="login-link" to="/login">
            Back to <span>Login</span>
          </Link>
        </div>
        {message && <p>{message}</p>}
        {error && <p className="error">{error}</p>}
      </form>
    </div>
  );
}

export default ForgotPassword;