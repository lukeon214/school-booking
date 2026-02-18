import { useState } from 'react';
import axios from 'axios';
import { useParams, Link } from 'react-router-dom';

function ResetPassword() {
  const { token } = useParams();
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/reset-password/${token}`, { password });
      setMessage(res.data.message);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Error');
      setMessage('');
    }
  };

  return (
    <div className="auth-page">
      <form className="modern-form" onSubmit={handleSubmit}>
        <div className="form-title">Reset Password</div>

        <div className="form-body">
          <div className="input-group-auth">
            <div className="input-wrapper">
              <svg fill="none" viewBox="0 0 24 24" className="input-icon">
                <path
                  stroke-width="1.5"
                  stroke="currentColor"
                  d="M12 10V14M8 6H16C17.1046 6 18 6.89543 18 8V16C18 17.1046 17.1046 18 16 18H8C6.89543 18 6 17.1046 6 16V8C6 6.89543 6.89543 6 8 6Z"
                ></path>
              </svg>
              <input
                required
                placeholder="New Password"
                className="form-input"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button className="password-toggle" type="button" onClick={() => setShowPassword(!showPassword)}>
                <svg fill="none" viewBox="0 0 24 24" className="eye-icon">
                  <path
                    stroke-width="1.5"
                    stroke="currentColor"
                    d="M2 12C2 12 5 5 12 5C19 5 22 12 22 12C22 12 19 19 12 19C5 19 2 12 2 12Z"
                  ></path>
                  <circle
                    stroke-width="1.5"
                    stroke="currentColor"
                    r="3"
                    cy="12"
                    cx="12"
                  ></circle>
                </svg>
              </button>
            </div>
          </div>
        </div>

        <button className="submit-button" type="submit">
          <span className="button-text">Reset Password</span>
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

export default ResetPassword;