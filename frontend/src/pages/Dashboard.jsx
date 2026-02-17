import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const [message, setMessage] = useState('Loading...');
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/hello`, { withCredentials: true })
      .then(res => setMessage(res.data.message))
      .catch(err => {
        if (err.response?.status === 401) navigate('/login');
        else setMessage(`Error: ${err.message}`);
      });
  }, [navigate]);

  return (
    <div>
      <h1>Dashboard</h1>
      <p>{message}</p>
    </div>
  );
}

export default Dashboard;