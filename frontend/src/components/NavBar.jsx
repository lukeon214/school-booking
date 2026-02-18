import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

function NavBar() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/me`, { withCredentials: true })
      .then(res => setUser(res.data.user))
      .catch(() => setUser(null));
  }, []);

  const handleLogout = async () => {
    await axios.post(`${import.meta.env.VITE_API_URL}/logout`, {}, { withCredentials: true });
    setUser(null);
    window.location.href = '/';
  };

  return (
    <div className="nav-bar">
      <div>
        <Link to="/dashboard">Dashboard</Link>
      </div>
      {user && <button className="logout" onClick={handleLogout}>Logout</button>}
    </div>
  );
}

export default NavBar;