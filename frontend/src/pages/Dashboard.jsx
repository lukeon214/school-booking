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
    if (!newTitle.trim()) {
      alert('Title required');
      return;
    }
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/forms`, { title: newTitle.trim() }, { withCredentials: true });
      setShowModal(false);
      navigate(`/edit/${res.data.publicId}`);
    } catch (err) {
      alert('Error creating form');
    }
  };

  const handleEdit = (publicId) => navigate(`/edit/${publicId}`);
  const handleStats = (publicId) => navigate(`/stats/${publicId}`);
  const handlePreview = (publicId) => navigate(`/preview/${publicId}`);

  const handleDelete = async (publicId) => {
    if (!confirm('Delete this form?')) return;
    try {
      await axios.delete(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, { withCredentials: true });
      fetchForms();
    } catch (err) {
      alert('Error deleting');
    }
  };

  const handleTogglePublish = async (publicId, current) => {
    try {
      await axios.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, { isPublished: !current }, { withCredentials: true });
      fetchForms();
    } catch (err) {
      alert('Error updating publish status');
    }
  };

  const copyShareLink = (publicId) => {
    const link = `https://form.databooq.com/f/${publicId}`;
    navigator.clipboard.writeText(link);
    alert('Share link copied!\n\n' + link);
  };

  if (loading) return <p>Loading forms...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div className="dashboard">
      <div className="top-bar">
        <button onClick={handleOpenModal} className="create-btn">+ Create New Form</button>
      </div>

      <div className="dashboard-content">
        {forms.length === 0 ? (
          <p className="empty-state">No forms yet. Create your first one!</p>
        ) : (
          <div className="form-grid">
            {forms.map(form => {
              const createdDate = new Date(form.createdAt).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              });

              return (
                <div key={form.id} className="form-card">
                  <div className="card-header">
                    <h5 className="card-title">{form.title}</h5>
                    <span className={`status-badge ${form.isPublished ? 'published' : 'draft'}`}>
                      {form.isPublished ? 'Published' : 'Draft'}
                    </span>
                  </div>

                  <p className="card-date">Created {createdDate}</p>

                  <div className="card-actions">
                    <button onClick={() => handleEdit(form.publicId)} className="btn-primary">Edit</button>
                    <button onClick={() => handleStats(form.publicId)} className="btn-primary">Stats</button>
                    <button onClick={() => handlePreview(form.publicId)} className="btn-secondary">Preview</button>
                    <button onClick={() => handleTogglePublish(form.publicId, form.isPublished)} className="btn-secondary">
                      {form.isPublished ? 'Unpublish' : 'Publish'}
                    </button>
                    <button onClick={() => copyShareLink(form.publicId)} className="btn-secondary">Share</button>
                    <button onClick={() => handleDelete(form.publicId)} className="btn-danger">Delete</button>
                  </div>
                </div>
              );
            })}
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
              autoFocus
            />
            <div className="modal-buttons">
              <button onClick={handleCreate} className="modal-create">Create & Edit</button>
              <button onClick={() => setShowModal(false)} className="modal-cancel">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;