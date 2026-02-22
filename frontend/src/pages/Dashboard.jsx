import { useEffect, useState, useMemo } from 'react';
import api from '../lib/axios';
import { useNavigate } from 'react-router-dom';
import '../Dashboard.css';

function Dashboard() {
  const [forms, setForms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [copiedId, setCopiedId] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const navigate = useNavigate();

  useEffect(() => { fetchForms(); }, []);

  const fetchForms = async () => {
    try {
      const res = await api.get(`${import.meta.env.VITE_API_URL}/forms`, { withCredentials: true });
      setForms(res.data);
    } catch (err) {
      if (err.response?.status === 401) navigate('/login');
      else setError('Failed to load forms. Please refresh.');
    } finally {
      setLoading(false);
    }
  };

  const stats = useMemo(() => ({
    total: forms.length,
    published: forms.filter(f => f.isPublished).length,
    drafts: forms.filter(f => !f.isPublished).length,
    totalSubmissions: forms.reduce((sum, f) => sum + (f.submissionCount || 0), 0),
  }), [forms]);

  const filtered = useMemo(() => {
    let list = [...forms];
    if (statusFilter === 'published') list = list.filter(f => f.isPublished);
    if (statusFilter === 'draft') list = list.filter(f => !f.isPublished);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(f =>
        f.title.toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
      );
    }
    if (sortBy === 'newest') list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    if (sortBy === 'oldest') list.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    if (sortBy === 'submissions') list.sort((a, b) => (b.submissionCount || 0) - (a.submissionCount || 0));
    return list;
  }, [forms, search, statusFilter, sortBy]);

  const handleCreate = async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    try {
      const res = await api.post(`${import.meta.env.VITE_API_URL}/forms`,
        { title: newTitle.trim(), description: newDesc.trim() },
        { withCredentials: true }
      );
      setShowModal(false);
      navigate(`/edit/${res.data.publicId}`);
    } catch {
      alert('Error creating form. Please try again.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = (publicId, title) => {
    setDeleteConfirm({ publicId, title });
  };

  const confirmDelete = async () => {
    if (!deleteConfirm) return;
    try {
      await api.delete(`${import.meta.env.VITE_API_URL}/forms/${deleteConfirm.publicId}`, { withCredentials: true });
      setDeleteConfirm(null);
      fetchForms();
    } catch {
      setDeleteConfirm(null);
      setError('Error deleting form. Please try again.');
    }
  };

  const handleTogglePublish = async (publicId, current) => {
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`,
        { isPublished: !current },
        { withCredentials: true }
      );
      fetchForms();
    } catch {
      alert('Error updating publish status.');
    }
  };

  const copyShareLink = (publicId) => {
    const link = `https://form.databooq.com/f/${publicId}`;
    navigator.clipboard.writeText(link);
    setCopiedId(publicId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  function formatDate(dt) {
    if (!dt) return null;
    const diff = Math.floor((Date.now() - new Date(dt)) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return new Date(dt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function openModal() {
    setNewTitle('');
    setNewDesc('');
    setShowModal(true);
  }

  if (loading) {
    return (
      <div className="dash-loading">
        <div className="dash-spinner"></div>
        <p>Loading your forms…</p>
      </div>
    );
  }

  return (
    <div className="dash-page">

      {/* ── Page header ── */}
      <div className="dash-page-header">
        <div>
          <h1 className="dash-page-title">My Forms</h1>
          <p className="dash-page-sub">Build, share, and track your forms in one place.</p>
        </div>
        <button className="dash-create-btn" onClick={openModal}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          New Form
        </button>
      </div>

      {/* ── Summary stats ── */}
      <div className="dash-stats">
        <div className="dash-stat-card">
          <div className="dash-stat-icon dash-stat-icon--blue">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14,2 14,8 20,8"/>
            </svg>
          </div>
          <div>
            <div className="dash-stat-num">{stats.total}</div>
            <div className="dash-stat-label">Total Forms</div>
          </div>
        </div>
        <div className="dash-stat-card">
          <div className="dash-stat-icon dash-stat-icon--green">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
              <polyline points="22,4 12,14.01 9,11.01"/>
            </svg>
          </div>
          <div>
            <div className="dash-stat-num">{stats.published}</div>
            <div className="dash-stat-label">Published</div>
          </div>
        </div>
        <div className="dash-stat-card">
          <div className="dash-stat-icon dash-stat-icon--orange">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
          </div>
          <div>
            <div className="dash-stat-num">{stats.drafts}</div>
            <div className="dash-stat-label">Drafts</div>
          </div>
        </div>
        <div className="dash-stat-card">
          <div className="dash-stat-icon dash-stat-icon--purple">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
            </svg>
          </div>
          <div>
            <div className="dash-stat-num">{stats.totalSubmissions}</div>
            <div className="dash-stat-label">Total Responses</div>
          </div>
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div className="dash-toolbar">
        <div className="dash-search">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#9aabcc" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            placeholder="Search forms…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && <button className="dash-search-clear" onClick={() => setSearch('')}>×</button>}
        </div>

        <div className="dash-toolbar-right">
          {/* Status filter */}
          <div className="dash-filter-tabs">
            {[['all', 'All'], ['published', 'Published'], ['draft', 'Drafts']].map(([val, label]) => (
              <button
                key={val}
                className={`dash-filter-tab ${statusFilter === val ? 'dash-filter-tab--active' : ''}`}
                onClick={() => setStatusFilter(val)}
              >
                {label}
                <span className="dash-filter-count">
                  {val === 'all' ? stats.total : val === 'published' ? stats.published : stats.drafts}
                </span>
              </button>
            ))}
          </div>

          {/* Sort */}
          <select
            className="dash-sort-select"
            value={sortBy}
            onChange={e => setSortBy(e.target.value)}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="submissions">Most responses</option>
          </select>
        </div>
      </div>

      {/* ── Error ── */}
      {error && <div className="dash-error">{error}</div>}

      {/* ── Form grid ── */}
      {forms.length === 0 ? (
        <div className="dash-empty">
          <div className="dash-empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14,2 14,8 20,8"/>
              <line x1="12" y1="18" x2="12" y2="12"/>
              <line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
          </div>
          <h3>No forms yet</h3>
          <p>Create your first form and start collecting responses.</p>
          <button className="dash-create-btn" onClick={openModal}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            Create your first form
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="dash-empty">
          <div className="dash-empty-icon">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.2">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
          </div>
          <h3>No results</h3>
          <p>No forms match your search or filter.</p>
          <button className="dash-filter-reset" onClick={() => { setSearch(''); setStatusFilter('all'); }}>
            Clear filters
          </button>
        </div>
      ) : (
        <div className="dash-grid">
          {filtered.map(form => (
            <FormCard
              key={form.id}
              form={form}
              copiedId={copiedId}
              formatDate={formatDate}
              onEdit={() => navigate(`/edit/${form.publicId}`)}
              onStats={() => navigate(`/stats/${form.publicId}`)}
              onPreview={() => navigate(`/preview/${form.publicId}`)}
              onDelete={() => handleDelete(form.publicId, form.title)}
              onTogglePublish={() => handleTogglePublish(form.publicId, form.isPublished)}
              onCopy={() => copyShareLink(form.publicId)}
            />
          ))}
        </div>
      )}

      {/* ── Create modal ── */}
      {showModal && (
        <div className="dash-modal-overlay" onClick={() => setShowModal(false)}>
          <div className="dash-modal" onClick={e => e.stopPropagation()}>
            <div className="dash-modal-header">
              <h3>Create New Form</h3>
              <button className="dash-modal-close" onClick={() => setShowModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
            <div className="dash-modal-body">
              <div className="dash-modal-field">
                <label>Form title <span className="dash-modal-required">*</span></label>
                <input
                  type="text"
                  placeholder="e.g. Customer Feedback Survey"
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleCreate()}
                  autoFocus
                />
              </div>
              <div className="dash-modal-field">
                <label>Description <span className="dash-modal-optional">(optional)</span></label>
                <textarea
                  placeholder="What is this form for?"
                  value={newDesc}
                  onChange={e => setNewDesc(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
            <div className="dash-modal-footer">
              <button className="dash-modal-cancel" onClick={() => setShowModal(false)}>Cancel</button>
              <button
                className="dash-modal-confirm"
                onClick={handleCreate}
                disabled={!newTitle.trim() || creating}
              >
                {creating ? 'Creating…' : 'Create & Edit'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete confirm modal ── */}
      {deleteConfirm && (
        <div className="dash-modal-overlay" onClick={() => setDeleteConfirm(null)}>
          <div className="dash-modal dash-modal--narrow" onClick={e => e.stopPropagation()}>
            <div className="dash-modal-icon-danger">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#e53e3e" stroke-width="2"><polyline points="3,6 5,6 21,6"></polyline><path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,1,0,1,1-1h6a1,1,1,0,1,1,1v2"></path></svg>
            </div>
            <h3 className="dash-modal-danger-title">Delete Form</h3>
            <p className="dash-modal-danger-body">
              Are you sure you want to delete <strong>"{deleteConfirm.title}"</strong>?
              All submissions will be permanently lost. This cannot be undone.
            </p>
            <div className="dash-modal-footer-del">
              <button className="dash-modal-cancel" onClick={() => setDeleteConfirm(null)}>Cancel</button>
              <button className="dash-modal-delete" onClick={confirmDelete}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FormCard({ form, copiedId, formatDate, onEdit, onStats, onPreview, onDelete, onTogglePublish, onCopy }) {
  const createdDate = new Date(form.createdAt).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric'
  });

  const questionCount = form.schemaJson?.questions?.length ?? '—';
  const submissionCount = form.submissionCount ?? 0;
  const lastSub = form.lastSubmittedAt ? formatDate(form.lastSubmittedAt) : null;
  const isCopied = copiedId === form.publicId;

  return (
    <div className="dash-card">
      {/* Card top */}
      <div className="dash-card-top">
        <div className="dash-card-title-row">
          <h3 className="dash-card-title">{form.title}</h3>
          <span className={`dash-badge dash-badge--${form.status || (form.isPublished ? 'published' : 'draft')}`}>
            <span className="dash-badge-dot"></span>
            {(form.status || (form.isPublished ? 'published' : 'draft')) === 'closed' ? 'Closed' : form.isPublished ? 'Published' : 'Draft'}
          </span>
        </div>
        {form.description && (
          <p className="dash-card-desc">{form.description}</p>
        )}
      </div>

      {/* Meta row */}
      <div className="dash-card-meta">
        <div className="dash-card-meta-item" title="Questions">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span>{questionCount} {questionCount === 1 ? 'question' : 'questions'}</span>
        </div>
        <div className="dash-card-meta-item" title="Responses">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
          </svg>
          <span>{submissionCount} {submissionCount === 1 ? 'response' : 'responses'}</span>
        </div>
        {lastSub && (
          <div className="dash-card-meta-item" title="Last response">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12,6 12,12 16,14"/>
            </svg>
            <span>Last {lastSub}</span>
          </div>
        )}
        <div className="dash-card-meta-item dash-card-meta-item--date">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
            <line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>
            <line x1="3" y1="10" x2="21" y2="10"/>
          </svg>
          <span>{createdDate}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="dash-card-actions">
        <div className="dash-card-actions-primary">
          <button className="dash-btn dash-btn--primary" onClick={onEdit}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
            Edit
          </button>
          <button className="dash-btn dash-btn--primary" onClick={onStats}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <line x1="18" y1="20" x2="18" y2="10"/>
              <line x1="12" y1="20" x2="12" y2="4"/>
              <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
            Responses
          </button>
        </div>

        <div className="dash-card-actions-secondary">
          <button className="dash-btn dash-btn--ghost" title="Preview" onClick={onPreview}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </button>
          <button
            className={`dash-btn dash-btn--ghost ${form.isPublished ? 'dash-btn--warn' : ''}`}
            title={form.isPublished ? 'Unpublish' : 'Publish'}
            onClick={onTogglePublish}
          >
            {form.isPublished ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
                <line x1="1" y1="1" x2="23" y2="23"/>
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            )}
          </button>
          <button
            className={`dash-btn dash-btn--ghost ${isCopied ? 'dash-btn--copied' : ''}`}
            title={isCopied ? 'Copied!' : 'Copy share link'}
            onClick={onCopy}
          >
            {isCopied ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
              </svg>
            )}
          </button>
          <button className="dash-btn dash-btn--danger-ghost" title="Delete form" onClick={onDelete}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3,6 5,6 21,6"/>
              <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,0,0,1,1-1h6a1,1,0,0,1,1,1v2"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;