import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../lib/axios';
import '../Stats.css';

const API = 'https://api.databooq.com';

export default function Stats() {
  const { publicId } = useParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [form, setForm] = useState(null);
  const [submissions, setSubmissions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  useEffect(() => {
    fetchData();
  }, [publicId]);

  async function fetchData() {
    try {
      const res = await api.get(`${API}/forms/${publicId}/submissions`, {
        withCredentials: true,
      });
      setForm(res.data.form);
      setSubmissions(res.data.submissions);
      if (res.data.submissions.length > 0) setSelected(res.data.submissions[0]);
    } catch (e) {
      setError('Failed to load responses. You may not have access to this form.');
    } finally {
      setLoading(false);
    }
  }

  const totalSubmissions = submissions.length;

  const lastSubmission = submissions.length > 0 ? submissions[0].submittedAt : null;

  const todayCount = useMemo(() =>
    submissions.filter(s => {
      const d = new Date(s.submittedAt);
      const now = new Date();
      return d.toDateString() === now.toDateString();
    }).length,
    [submissions]
  );

  const filtered = useMemo(() => {
    if (!search.trim()) return submissions;
    const q = search.toLowerCase();
    return submissions.filter((s) => {
      const idx = submissions.indexOf(s);
      const num = `#${submissions.length - idx}`;
      const date = new Date(s.submittedAt).toLocaleString().toLowerCase();
      const dataStr = JSON.stringify(s.dataJson).toLowerCase();
      return num.includes(q) || date.includes(q) || dataStr.includes(q);
    });
  }, [submissions, search]);

  function exportCSV() {
    if (!form) return;
    const questions = form.schemaJson.questions;

    const columnDefs = [];

    for (const q of questions) {
      if (q.type === 'grid') {
        for (const col of q.columns) {
          columnDefs.push({
            header: col.label,
            getValue(dataJson) {
              const selected = dataJson[q.id];
              if (!Array.isArray(selected) || selected.length === 0) return '';
              return q.rows
                .map(row => {
                  const key = `${row.id}-${col.id}`;
                  if (!selected.includes(key)) return null;
                  const cellText = q.cells?.[key]?.text;
                  return cellText || null;
                })
                .filter(Boolean)
                .join(', ');
            }
          });
        }

        for (const row of q.rows) {
          columnDefs.push({
            header: row.label,
            getValue(dataJson) {
              const selected = dataJson[q.id];
              if (!Array.isArray(selected) || selected.length === 0) return '';
              return q.columns
                .map(col => {
                  const key = `${row.id}-${col.id}`;
                  if (!selected.includes(key)) return null;
                  const cellText = q.cells?.[key]?.text;
                  return cellText || null;
                })
                .filter(Boolean)
                .join(', ');
            }
          });
        }

      } else {
        columnDefs.push({
          header: q.label,
          getValue(dataJson) {
            const val = dataJson[q.id];
            if (val === undefined || val === null || val === '') return '';
            if (Array.isArray(val)) return val.join(', ');
            return String(val);
          }
        });
      }
    }

    const headers = ['Response #', 'Submitted At', ...columnDefs.map(c => c.header)];
    const rows = submissions.map((s, i) => {
      const num = submissions.length - i;
      const date = new Date(s.submittedAt).toLocaleString();
      const values = columnDefs.map(c => c.getValue(s.dataJson));
      return [num, date, ...values];
    });
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${form.title.replace(/\s+/g, '-')}-responses.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function deleteSubmission(id) {
    try {
      await api.delete(`${API}/forms/${publicId}/submissions/${id}`, {
        withCredentials: true,
      });
      const updated = submissions.filter(s => s.id !== id);
      setSubmissions(updated);
      if (selected?.id === id) setSelected(updated[0] || null);
      setDeleteConfirm(null);
    } catch (e) {
      alert('Failed to delete response. Please try again.');
    }
  }

  function formatRelativeTime(dt) {
    const diff = Math.floor((Date.now() - new Date(dt)) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return new Date(dt).toLocaleDateString();
  }

  function getPreview(sub) {
    if (!form) return '';
    for (const q of form.schemaJson.questions) {
      const val = sub.dataJson[q.id];
      if (!val) continue;
      if (typeof val === 'string' && val.trim()) return val;
      if (Array.isArray(val) && val.length > 0) return val[0];
    }
    return 'No preview available';
  }

  function renderAnswer(question, value) {
    if (value === undefined || value === null || value === '') {
      return <span className="stats-no-answer">Not answered</span>;
    }

    if (question.type === 'grid') {
      const selected = Array.isArray(value) ? value : [];
      if (selected.length === 0) return <span className="stats-no-answer">Not answered</span>;
      return (
        <div className="stats-grid-answer">
          <table className="stats-grid-table">
            <thead>
              <tr>
                <th className="stats-grid-corner"></th>
                {question.columns.map(col => (
                  <th key={col.id}>{col.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {question.rows.map(row => (
                <tr key={row.id}>
                  <td className="stats-grid-rowlabel">{row.label}</td>
                  {question.columns.map(col => {
                    const cellKey = `${row.id}-${col.id}`;
                    const isChosen = selected.includes(cellKey);
                    const cellData = question.cells?.[cellKey];
                    return (
                      <td
                        key={col.id}
                        className={`stats-grid-cell ${isChosen ? 'stats-grid-cell--selected' : ''} ${!cellData?.enabled ? 'stats-grid-cell--disabled' : ''}`}
                      >
                        {cellData?.text || ''}
                        {isChosen && <span className="stats-grid-check"></span>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }

    if (question.type === 'rating') {
      const num = parseInt(value) || 0;
      return (
        <div className="stats-rating-answer">
          <div className="stats-stars">
            {[1, 2, 3, 4, 5].map(i => (
              <span key={i} className={`stats-star ${i <= num ? 'stats-star--filled' : ''}`}>★</span>
            ))}
          </div>
          <span className="stats-rating-num">{value} / 5</span>
        </div>
      );
    }

    if (question.type === 'yes_no') {
      return (
        <span className={`stats-badge ${value === 'Yes' ? 'stats-badge--yes' : 'stats-badge--no'}`}>
          {value === 'Yes' ? '✓ Yes' : '✗ No'}
        </span>
      );
    }

    if (Array.isArray(value)) {
      return (
        <div className="stats-tags">
          {value.map((v, i) => (
            <span key={i} className="stats-tag">{v}</span>
          ))}
        </div>
      );
    }

    if (question.type === 'url') {
      return (
        <a href={value} target="_blank" rel="noreferrer" className="stats-link">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15,3 21,3 21,9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          {value}
        </a>
      );
    }

    if (question.type === 'email') {
      return (
        <a href={`mailto:${value}`} className="stats-link">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          {value}
        </a>
      );
    }

    if (question.type === 'date') {
      return <span className="stats-text-answer">{new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}</span>;
    }

    return <span className="stats-text-answer">{value}</span>;
  }

  const typeIcons = {
    short_text: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>,
    long_text:<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M7 8h10"/><path d="M7 11h10"/><path d="M7 14h10"/><path d="M7 17h6"/></svg>,
    number: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 9h16M4 15h16M10 3L8 21M16 3L14 21"/></svg>,
    radio: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4" fill="currentColor" stroke="none"/></svg>,
    checkbox: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><polyline points="7 12 10 15 17 8"/></svg>,
    select: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="5" width="18" height="16" rx="2"/><polyline points="8 11 12 15 16 11"/></svg>,
    date: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>,
    time: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
    email: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22 6 12 13 2 6"/></svg>,
    phone: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 10.09a16 16 0 0 0 6.5 6.5l1.79-1.79a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>,
    url: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"></path></svg>,
    rating: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>,
    yes_no: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
    grid: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
  };

  if (loading) {
    return (
      <div className="stats-fullscreen-center">
        <div className="stats-spinner"></div>
        <p className="stats-loading-text">Loading responses…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="stats-fullscreen-center">
        <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <p className="stats-error-msg">{error}</p>
        <button className="stats-back-btn-plain" onClick={() => navigate('/dashboard')}>← Back to Dashboard</button>
      </div>
    );
  }

  const questions = form.schemaJson.questions;
  const selectedIndex = selected ? submissions.findIndex(s => s.id === selected.id) : -1;
  const selectedNum = selectedIndex >= 0 ? submissions.length - selectedIndex : null;


  return (
    <div className="stats-page">

      {/* ── Header ── */}
      <header className="stats-header">
        <div className="stats-header-left">
          <button className="stats-back-btn" onClick={() => navigate('/dashboard')}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M19 12H5M12 5l-7 7 7 7"/>
            </svg>
            Dashboard
          </button>
          <div className="stats-title-group">
            <h1 className="stats-form-title">{form.title}</h1>
            {form.description && <p className="stats-form-desc">{form.description}</p>}
          </div>
        </div>
        <button className="stats-export-btn" onClick={exportCSV} disabled={submissions.length === 0}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
            <polyline points="7,10 12,15 17,10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Export CSV
        </button>
      </header>

      {/* ── Summary Cards ── */}
      <div className="stats-cards">
        <div className="stats-card">
          <div className="stats-card-icon stats-card-icon--blue">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
            </svg>
          </div>
          <div className="stats-card-body">
            <span className="stats-card-num">{totalSubmissions}</span>
            <span className="stats-card-label">Total Responses</span>
          </div>
        </div>

        <div className="stats-card">
          <div className="stats-card-icon stats-card-icon--green">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
              <line x1="16" y1="2" x2="16" y2="6"/>
              <line x1="8" y1="2" x2="8" y2="6"/>
              <line x1="3" y1="10" x2="21" y2="10"/>
            </svg>
          </div>
          <div className="stats-card-body">
            <span className="stats-card-num">{todayCount}</span>
            <span className="stats-card-label">Today's Responses</span>
          </div>
        </div>

        <div className="stats-card">
          <div className="stats-card-icon stats-card-icon--purple">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12,6 12,12 16,14"/>
            </svg>
          </div>
          <div className="stats-card-body">
            <span className="stats-card-num stats-card-num--sm">
              {lastSubmission ? formatRelativeTime(lastSubmission) : '—'}
            </span>
            <span className="stats-card-label">Last Response</span>
          </div>
        </div>
      </div>

      {/* ── Main area ── */}
      {submissions.length === 0 ? (
        <div className="stats-empty">
          <svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <polyline points="14,2 14,8 20,8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10,9 9,9 8,9"/>
          </svg>
          <h3>No responses yet</h3>
          <p>Share your form to start collecting responses.</p>
        </div>
      ) : (
        <div className="stats-main">

          {/* ── Left: submission list ── */}
          <div className="stats-list-panel">
            <div className="stats-list-header">
              <span className="stats-list-title">Responses</span>
              <span className="stats-list-badge">{filtered.length}</span>
            </div>

            <div className="stats-search">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#9aabcc" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input
                type="text"
                placeholder="Search responses…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
              {search && (
                <button className="stats-search-clear" onClick={() => setSearch('')}>×</button>
              )}
            </div>

            <div className="stats-list-scroll">
              {filtered.length === 0 ? (
                <div className="stats-no-results">No matching responses</div>
              ) : (
                filtered.map(sub => {
                  const idx = submissions.indexOf(sub);
                  const num = submissions.length - idx;
                  const isActive = selected?.id === sub.id;
                  const preview = getPreview(sub);

                  return (
                    <div
                      key={sub.id}
                      className={`stats-list-item ${isActive ? 'stats-list-item--active' : ''}`}
                      onClick={() => setSelected(sub)}
                    >
                      <div className="stats-list-item-row">
                        <span className="stats-list-num">#{num}</span>
                        <span className="stats-list-time">{formatRelativeTime(sub.submittedAt)}</span>
                        <button
                          className="stats-list-delete"
                          title="Delete response"
                          onClick={e => { e.stopPropagation(); setDeleteConfirm(sub.id); }}
                        >
                          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                            <polyline points="3,6 5,6 21,6"/>
                            <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,0,0,1,1-1h4a1,1,0,0,1,1,1v2"/>
                          </svg>
                        </button>
                      </div>
                      <div className="stats-list-preview">{preview}</div>
                      <div className="stats-list-date">{new Date(sub.submittedAt).toLocaleString()}</div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* ── Right: detail panel ── */}
          <div className="stats-detail-panel">
            {selected ? (
              <>
                <div className="stats-detail-header">
                  <div className="stats-detail-header-info">
                    <h2 className="stats-detail-title">Response #{selectedNum}</h2>
                    <p className="stats-detail-date">
                      Submitted on {new Date(selected.submittedAt).toLocaleString()}
                      {selected.ip && <span className="stats-detail-ip"> · {selected.ip}</span>}
                    </p>
                  </div>
                  <button
                    className="stats-detail-delete-btn"
                    onClick={() => setDeleteConfirm(selected.id)}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polyline points="3,6 5,6 21,6"/>
                      <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,0,0,1,1-1h6a1,1,0,0,1,1,1v2"/>
                    </svg>
                    Delete Response
                  </button>
                </div>

                <div className="stats-detail-body">
                  {questions.map((q, idx) => {
                    const val = selected.dataJson[q.id];
                    const hasAnswer = val !== undefined && val !== null && val !== '' && !(Array.isArray(val) && val.length === 0);
                    return (
                      <div key={q.id} className={`stats-answer-block ${!hasAnswer ? 'stats-answer-block--empty' : ''}`}>
                        <div className="stats-answer-meta">
                          <span className="stats-answer-qnum">Q{idx + 1}</span>
                          <span className="stats-answer-type">
                            {typeIcons[q.type] || '?'} {q.type.replace(/_/g, ' ')}
                          </span>
                          {q.required && <span className="stats-answer-required">required</span>}
                        </div>
                        <div className="stats-answer-label">{q.label}</div>
                        {q.description && <div className="stats-answer-desc">{q.description}</div>}
                        <div className="stats-answer-value">
                          {renderAnswer(q, val)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="stats-no-selection">
                <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.4">
                  <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                  <polyline points="14,2 14,8 20,8"/>
                  <line x1="16" y1="13" x2="8" y2="13"/>
                  <line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
                <p>Select a response to view details</p>
              </div>
            )}
          </div>

        </div>
      )}

      {/* ── Delete Confirm Modal ── */}
      {deleteConfirm && (
        <div className="stats-modal-overlay" onClick={() => setDeleteConfirm(null)}>
          <div className="stats-modal" onClick={e => e.stopPropagation()}>
            <div className="stats-modal-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#e53e3e" stroke-width="2"><polyline points="3,6 5,6 21,6"></polyline><path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,1,0,1,1-1h6a1,1,1,0,1,1,1v2"></path></svg>
            </div>
            <h3 className="stats-modal-title">Delete Response</h3>
            <p className="stats-modal-body">Are you sure you want to permanently delete this response? This cannot be undone.</p>
            <div className="stats-modal-actions">
              <button className="stats-modal-cancel" onClick={() => setDeleteConfirm(null)}>Cancel</button>
              <button className="stats-modal-confirm" onClick={() => deleteSubmission(deleteConfirm)}>Delete</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}