import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const [forms, setForms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchForms();
  }, []);

  const fetchForms = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/forms`, { withCredentials: true });
      setForms(res.data);
      setLoading(false);
    } catch (err) {
      if (err.response?.status === 401) navigate('/login');
      else setError('Error loading forms');
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    const title = prompt('Form title:');
    if (!title) return;
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/forms`, { title }, { withCredentials: true });
      navigate(`/edit/${res.data.id}`);
    } catch (err) {
      alert('Error creating');
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete?')) return;
    try {
      await axios.delete(`${import.meta.env.VITE_API_URL}/forms/${id}`, { withCredentials: true });
      fetchForms();
    } catch (err) {
      alert('Error deleting');
    }
  };

  const handleTogglePublish = async (id, current) => {
    try {
      await axios.put(`${import.meta.env.VITE_API_URL}/forms/${id}`, { isPublished: !current }, { withCredentials: true });
      fetchForms();
    } catch (err) {
      alert('Error');
    }
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div className="dashboard">
      <div className="top-bar">
        <button onClick={handleCreate}>Create Form</button>
      </div>
      <div className="dashboard-content">
        {forms.length === 0 ? <p>No forms yet</p> : (
          <ul>
            {forms.map(form => (
              <li key={form.id}>
                {form.title} - {form.isPublished ? 'Published' : 'Draft'}
                <button onClick={() => navigate(`/edit/${form.id}`)}>Edit</button>
                <button onClick={() => handleTogglePublish(form.id, form.isPublished)}>
                  {form.isPublished ? 'Unpublish' : 'Publish'}
                </button>
                <button onClick={() => handleDelete(form.id)}>Delete</button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default Dashboard;