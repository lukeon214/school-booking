// frontend/src/pages/Dashboard.jsx (updated with modal for create form)
import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const [forms, setForms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
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

  const handleOpenModal = () => {
    setShowModal(true);
    setNewTitle('');
  };

  const handleCreate = async () => {
    if (!newTitle) {
      alert('Title required');
      return;
    }
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/forms`, { title: newTitle }, { withCredentials: true });
      setShowModal(false);
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
        <button onClick={handleOpenModal}>Create Form</button>
      </div>
      <div className="dashboard-content">
        {forms.length === 0 ? <p>No forms yet</p> : (
          <div className="row">
            {forms.map(form => (
              <div key={form.id} className="col-md-4 mb-4">
                <div className="card" style={{ border: '1px solid #5c8df6', borderRadius: '8px' }}>
                  <div className="card-body">
                    <h5 className="card-title">{form.title}</h5>
                    <p className="card-text">{form.isPublished ? 'Published' : 'Draft'}</p>
                    <button onClick={() => navigate(`/edit/${form.id}`)}>Edit</button>
                    <button onClick={() => handleTogglePublish(form.id, form.isPublished)}>
                      {form.isPublished ? 'Unpublish' : 'Publish'}
                    </button>
                    <button onClick={() => handleDelete(form.id)}>Delete</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>Create New Form</h3>
            <input
              type="text"
              placeholder="Enter form title"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="modal-input"
            />
            <div className="modal-buttons">
              <button onClick={handleCreate} className="modal-create">Create</button>
              <button onClick={() => setShowModal(false)} className="modal-cancel">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;