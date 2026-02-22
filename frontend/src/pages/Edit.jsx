import { useEffect, useState, useCallback } from 'react';
import api from '../lib/axios';
import { useParams, useNavigate } from 'react-router-dom';
import { DndProvider, useDrag, useDrop } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';
import '../Edit.css';

const ITEM_TYPE = 'question';

const TYPE_META = {
  short_text:  { label: 'Short Text',       icon: '✏️' },
  long_text:   { label: 'Long Text',         icon: '📝' },
  number:      { label: 'Number',            icon: '#'  },
  radio:       { label: 'Single Choice',     icon: '⊙'  },
  checkbox:    { label: 'Multiple Choice',   icon: '☑'  },
  select:      { label: 'Dropdown',          icon: '▾'  },
  date:        { label: 'Date',              icon: '📅' },
  time:        { label: 'Time',              icon: '🕐' },
  email:       { label: 'Email',             icon: '@'  },
  phone:       { label: 'Phone',             icon: '📞' },
  url:         { label: 'URL',               icon: '🔗' },
  rating:      { label: 'Rating',            icon: '⭐' },
  yes_no:      { label: 'Yes / No',          icon: '✓✗' },
  grid:        { label: 'Grid Table',        icon: '⊞'  },
};

// ─── Toggle Switch ───────────────────────────────────────────────────────────
function Toggle({ checked, onChange, label }) {
  return (
    <label className="edit-toggle">
      <span className="edit-toggle-label">{label}</span>
      <span
        className={`edit-toggle-track ${checked ? 'edit-toggle-track--on' : ''}`}
        onClick={() => onChange(!checked)}
      >
        <span className="edit-toggle-thumb" />
      </span>
    </label>
  );
}

// ─── Main Edit Component ─────────────────────────────────────────────────────
function Edit() {
  const { publicId } = useParams();
  const navigate = useNavigate();

  const [form, setForm] = useState(null);
  const [questions, setQuestions] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [closeDate, setCloseDate] = useState('');
  const [maxTotalResponses, setMaxTotalResponses] = useState(0);
  const [selectedQuestionIndex, setSelectedQuestionIndex] = useState(null);
  const [selectedCellKey, setSelectedCellKey] = useState(null);
  const [currentTab, setCurrentTab] = useState('edit');
  const [showAddModal, setShowAddModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [lastSavedTime, setLastSavedTime] = useState(null);
  const [saveError, setSaveError] = useState(false);

  // Deliver tab state
  const [isPublished, setIsPublished] = useState(false);
  const [submissionCount, setSubmissionCount] = useState(0);
  const [qrImage, setQrImage] = useState(null);
  const [qrLoading, setQrLoading] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [embedCopied, setEmbedCopied] = useState(false);

  const shareLink = `https://form.databooq.com/f/${publicId}`;
  const embedCode = `<iframe src="${shareLink}" width="100%" height="600" frameborder="0"></iframe>`;

  useEffect(() => {
    api.get(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, { withCredentials: true })
      .then(res => {
        const d = res.data;
        setForm(d);
        setTitle(d.title);
        setDescription(d.description || '');
        if (d.closeDate) {
          const utc = new Date(d.closeDate);
          const localISO = new Date(utc.getTime() - utc.getTimezoneOffset() * 60000)
            .toISOString()
            .slice(0, 16);
          setCloseDate(localISO);
        } else {
          setCloseDate('');
        }
        setMaxTotalResponses(d.maxTotalResponses || 0);
        setIsPublished(d.isPublished);
        setQuestions(d.schemaJson.questions || []);
        // fetch submission count for closed status computation
        return api.get(`${import.meta.env.VITE_API_URL}/forms/${publicId}/submissions`, { withCredentials: true });
      })
      .then(res => {
        setSubmissionCount(res.data.totalSubmissions || 0);
        setLoading(false);
      })
      .catch(() => { setError('Error loading form'); setLoading(false); });
  }, [publicId]);

  // Auto-save every 60 seconds
  useEffect(() => {
    if (loading || !publicId) return;
    const interval = setInterval(() => silentSave(), 60000);
    return () => clearInterval(interval);
  }, [title, description, questions, publicId, loading, closeDate, maxTotalResponses]);

  // Convert datetime-local string (local time, no tz) to proper ISO string with offset
  const toISOWithTZ = (dtLocal) => {
    if (!dtLocal) return null;
    // new Date(dtLocal) parses as LOCAL time in browsers, giving us the correct timestamp
    return new Date(dtLocal).toISOString();
  };

  const silentSave = useCallback(async () => {
    if (!publicId) return;
    setIsSaving(true);
    setSaveError(false);
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title,
        description,
        isPublished,
        closeDate: toISOWithTZ(closeDate),
        maxTotalResponses: parseInt(maxTotalResponses) || 0,
        schemaJson: { questions },
      }, { withCredentials: true });
      setLastSavedTime(new Date());
    } catch {
      setSaveError(true);
    }
    setIsSaving(false);
  }, [title, description, questions, publicId, isPublished, closeDate, maxTotalResponses]);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(false);
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title,
        description,
        isPublished,
        closeDate: toISOWithTZ(closeDate),
        maxTotalResponses: parseInt(maxTotalResponses) || 0,
        schemaJson: { questions },
      }, { withCredentials: true });
      setLastSavedTime(new Date());
    } catch {
      setSaveError(true);
    }
    setIsSaving(false);
  };

  const handleTogglePublish = async () => {
    const next = !isPublished;
    setIsPublished(next);
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title, description, isPublished: next,
        closeDate: toISOWithTZ(closeDate),
        maxTotalResponses: parseInt(maxTotalResponses) || 0,
        schemaJson: { questions },
      }, { withCredentials: true });
      setLastSavedTime(new Date());
    } catch {
      setIsPublished(!next);
      alert('Failed to update publish status.');
    }
  };

  const handleGenerateQR = async () => {
    setQrLoading(true);
    setQrImage(null);
    try {
      const res = await api.post(
        `${import.meta.env.VITE_API_URL}/forms/${publicId}/qr`,
        { ecc: 'M' },
        { withCredentials: true }
      );
      setQrImage(res.data.image);
    } catch {
      alert('Failed to generate QR code.');
    }
    setQrLoading(false);
  };

  const handleDownloadQR = () => {
    if (!qrImage) return;
    const a = document.createElement('a');
    a.href = qrImage;
    a.download = `${title.replace(/\s+/g, '-')}-qr.png`;
    a.click();
  };

  const copyLink = () => {
    navigator.clipboard.writeText(shareLink);
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), 2000);
  };

  const copyEmbed = () => {
    navigator.clipboard.writeText(embedCode);
    setEmbedCopied(true);
    setTimeout(() => setEmbedCopied(false), 2000);
  };

  // ── Question helpers ──────────────────────────────────────────────────────

  const addQuestion = (type) => {
    const newId = 'q' + (Date.now());
    let newQuestion;
    if (type === 'grid') {
      const rows = Array.from({ length: 4 }, (_, i) => ({ id: `r${i+1}`, label: '' }));
      const columns = Array.from({ length: 3 }, (_, i) => ({ id: `c${i+1}`, label: '' }));
      const cells = {};
      rows.forEach(row => columns.forEach(col => {
        cells[`${row.id}-${col.id}`] = { text: '', max: 0, enabled: true, used: 0 };
      }));
      newQuestion = { id: newId, label: '', description: '', type: 'grid', required: false, singlePerRow: false, singlePerColumn: false, rows, columns, cells };
    } else {
      newQuestion = {
        id: newId, label: '', description: '', type, required: false,
        options: type === 'yes_no' ? ['Yes','No'] : (type === 'radio' || type === 'checkbox' || type === 'select') ? ['',''] : [],
      };
    }
    setQuestions(prev => { const next = [...prev, newQuestion]; return next; });
    setSelectedQuestionIndex(questions.length);
    setSelectedCellKey(null);
    setShowAddModal(false);
  };

  const getSelectedQuestion = () => questions[selectedQuestionIndex] || null;

  const updateQuestion = (field, value) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex] = { ...updated[selectedQuestionIndex], [field]: value };
    setQuestions(updated);
  };

  const addOption = () => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options = [...updated[selectedQuestionIndex].options, ''];
    setQuestions(updated);
  };

  const updateOption = (i, value) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options[i] = value;
    setQuestions(updated);
  };

  const removeOption = (i) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options.splice(i, 1);
    setQuestions(updated);
  };

  const removeQuestion = (index) => {
    setQuestions(questions.filter((_, i) => i !== index));
    if (selectedQuestionIndex === index) { setSelectedQuestionIndex(null); setSelectedCellKey(null); }
    else if (selectedQuestionIndex > index) setSelectedQuestionIndex(selectedQuestionIndex - 1);
  };

  const moveQuestion = (dragIndex, hoverIndex) => {
    const updated = [...questions];
    const [dragged] = updated.splice(dragIndex, 1);
    updated.splice(hoverIndex, 0, dragged);
    setQuestions(updated);
    if (selectedQuestionIndex === dragIndex) setSelectedQuestionIndex(hoverIndex);
  };

  // ── Grid helpers ──────────────────────────────────────────────────────────
  const updateGridQuestion = (updater) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex] = updater(updated[selectedQuestionIndex]);
    setQuestions(updated);
  };

  const addRow = () => updateGridQuestion(q => {
    const newId = `r${q.rows.length + 1}`;
    const newCells = { ...q.cells };
    q.columns.forEach(col => { newCells[`${newId}-${col.id}`] = { text: '', max: 0, enabled: true, used: 0 }; });
    return { ...q, rows: [...q.rows, { id: newId, label: '' }], cells: newCells };
  });

  const addColumn = () => updateGridQuestion(q => {
    const newId = `c${q.columns.length + 1}`;
    const newCells = { ...q.cells };
    q.rows.forEach(row => { newCells[`${row.id}-${newId}`] = { text: '', max: 0, enabled: true, used: 0 }; });
    return { ...q, columns: [...q.columns, { id: newId, label: '' }], cells: newCells };
  });

  const removeRow = (rowIndex) => updateGridQuestion(q => {
    const rowId = q.rows[rowIndex].id;
    const newCells = { ...q.cells };
    Object.keys(newCells).forEach(k => { if (k.startsWith(`${rowId}-`)) delete newCells[k]; });
    return { ...q, rows: q.rows.filter((_, i) => i !== rowIndex), cells: newCells };
  });

  const removeColumn = (colIndex) => updateGridQuestion(q => {
    const colId = q.columns[colIndex].id;
    const newCells = { ...q.cells };
    Object.keys(newCells).forEach(k => { if (k.endsWith(`-${colId}`)) delete newCells[k]; });
    return { ...q, columns: q.columns.filter((_, i) => i !== colIndex), cells: newCells };
  });

  const updateRowLabel = (rowIndex, value) => updateGridQuestion(q => {
    const newRows = [...q.rows]; newRows[rowIndex] = { ...newRows[rowIndex], label: value };
    return { ...q, rows: newRows };
  });

  const updateColumnLabel = (colIndex, value) => updateGridQuestion(q => {
    const newCols = [...q.columns]; newCols[colIndex] = { ...newCols[colIndex], label: value };
    return { ...q, columns: newCols };
  });

  const updateCell = (cellKey, field, value) => updateGridQuestion(q => ({
    ...q, cells: { ...q.cells, [cellKey]: { ...q.cells[cellKey], [field]: value } }
  }));

  // ── Save indicator text ───────────────────────────────────────────────────
  function saveStatus() {
    if (saveError) return { text: 'Save failed', cls: 'edit-save-status--error' };
    if (isSaving) return { text: 'Saving…', cls: 'edit-save-status--saving' };
    if (lastSavedTime) {
      const diff = Math.floor((Date.now() - lastSavedTime) / 1000);
      const label = diff < 10 ? 'Saved just now' : diff < 60 ? `Saved ${diff}s ago` : `Saved ${Math.floor(diff/60)}m ago`;
      return { text: label, cls: 'edit-save-status--ok' };
    }
    return null;
  }

  if (loading) return (
    <div className="edit-loading">
      <div className="edit-spinner" />
      <p>Loading form…</p>
    </div>
  );
  if (error) return <div className="edit-error-page">{error}</div>;

  const selectedQuestion = getSelectedQuestion();
  const isGrid = selectedQuestion?.type === 'grid';
  const status = saveStatus();

  // Derived form status
  const isClosed = isPublished && (
    (closeDate && new Date() > new Date(closeDate)) ||
    (maxTotalResponses > 0 && submissionCount >= Number(maxTotalResponses))
  );
  const formStatus = !isPublished ? 'draft' : isClosed ? 'closed' : 'published';

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="edit-page-shell">

        {/* ── Top bar ── */}
        <header className="edit-topbar">
          <div className="edit-topbar-left">
            <button className="edit-back-btn" onClick={() => navigate('/dashboard')}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M19 12H5M12 5l-7 7 7 7"/>
              </svg>
            </button>
            <div className="edit-topbar-title-group">
              <span className="edit-topbar-formname">{title || 'Untitled Form'}</span>
              <span className={`edit-topbar-badge edit-topbar-badge--${formStatus}`}>
                {formStatus === 'published' ? 'Published' : formStatus === 'closed' ? 'Closed' : 'Draft'}
              </span>
            </div>
          </div>

          <nav className="edit-tabs">
            {['edit','settings','deliver'].map(tab => (
              <button
                key={tab}
                className={`edit-tab ${currentTab === tab ? 'edit-tab--active' : ''}`}
                onClick={() => setCurrentTab(tab)}
              >
                {tab === 'edit' ? 'Edit' : tab === 'settings' ? 'Settings' : 'Deliver'}
              </button>
            ))}
          </nav>

          <div className="edit-topbar-right">
            {status && (
              <span className={`edit-save-status ${status.cls}`}>
                {isSaving && <span className="edit-save-spinner" />}
                {status.text}
              </span>
            )}
            <button className="edit-preview-btn" onClick={() => navigate(`/preview/${publicId}`)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
              Preview
            </button>
            <button className="edit-save-btn" onClick={handleSave} disabled={isSaving}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/>
                <polyline points="17,21 17,13 7,13 7,21"/>
                <polyline points="7,3 7,8 15,8"/>
              </svg>
              Save
            </button>
          </div>
        </header>

        <div className="edit-body">

          {/* ── Left sidebar ── */}
          <aside className="edit-left">
            <div className="edit-left-header">
              <span className="edit-left-title">Questions</span>
              <span className="edit-left-count">{questions.length}</span>
            </div>
            <button className="edit-add-btn" onClick={() => setShowAddModal(true)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              Add Question
            </button>

            <div className="edit-question-list">
              {questions.length === 0 ? (
                <div className="edit-left-empty">
                  <p>No questions yet.<br/>Click "Add Question" to start.</p>
                </div>
              ) : (
                questions.map((q, index) => (
                  <QuestionCard
                    key={q.id}
                    question={q}
                    index={index}
                    isSelected={index === selectedQuestionIndex}
                    onSelect={() => { setSelectedQuestionIndex(index); setSelectedCellKey(null); }}
                    moveQuestion={moveQuestion}
                    onDelete={() => removeQuestion(index)}
                  />
                ))
              )}
            </div>
          </aside>

          {/* ── Middle canvas ── */}
          <main className="edit-canvas">

            {/* EDIT TAB */}
            {currentTab === 'edit' && (
              selectedQuestion ? (
                <div className="edit-form-card">
                  <div className="edit-q-meta">
                    <span className="edit-q-num">Q{selectedQuestionIndex + 1}</span>
                    <span className="edit-q-type-badge">
                      {TYPE_META[selectedQuestion.type]?.icon} {TYPE_META[selectedQuestion.type]?.label}
                    </span>
                  </div>

                  <input
                    className="edit-q-label"
                    value={selectedQuestion.label}
                    onChange={e => updateQuestion('label', e.target.value)}
                    placeholder="Your question here…"
                  />
                  <input
                    className="edit-q-desc"
                    value={selectedQuestion.description || ''}
                    onChange={e => updateQuestion('description', e.target.value)}
                    placeholder="Description (optional)"
                  />

                  <div className="edit-answer-area">
                    {isGrid ? (
                      <div className="matrix-grid-wrapper">
                        <table className="matrix-grid">
                          <thead>
                            <tr>
                              <th className="matrix-corner"></th>
                              {selectedQuestion.columns.map((col, ci) => (
                                <th key={col.id}>
                                  <input className="header-input" value={col.label} onChange={e => updateColumnLabel(ci, e.target.value)} placeholder="Column…" />
                                  <button className="remove-header-btn" onClick={() => removeColumn(ci)}>×</button>
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {selectedQuestion.rows.map((row, ri) => (
                              <tr key={row.id}>
                                <td className="row-label-cell">
                                  <input className="header-input" value={row.label} onChange={e => updateRowLabel(ri, e.target.value)} placeholder="Row…" />
                                  <button className="remove-header-btn" onClick={() => removeRow(ri)}>×</button>
                                </td>
                                {selectedQuestion.columns.map(col => {
                                  const cellKey = `${row.id}-${col.id}`;
                                  const cell = selectedQuestion.cells[cellKey] || { text: '', max: 0, enabled: true };
                                  const isSel = selectedCellKey === cellKey;
                                  return (
                                    <td key={col.id} className={`matrix-cell ${isSel ? 'selected' : ''} ${!cell.enabled ? 'disabled' : ''}`} onClick={() => setSelectedCellKey(cellKey)}>
                                      <div className="cell-content">
                                        <textarea className="cell-text-input" value={cell.text} onChange={e => updateCell(cellKey, 'text', e.target.value)} placeholder="Text…" />
                                        <div className="cell-controls">
                                          <div className="cell-max">
                                            Max:
                                            <input type="number" min="0" className="cell-max-input" value={cell.max || ''} onChange={e => updateCell(cellKey, 'max', parseInt(e.target.value) || 0)} placeholder="∞" />
                                          </div>
                                          <label className="cell-toggle">
                                            <input type="checkbox" checked={cell.enabled} onChange={e => updateCell(cellKey, 'enabled', e.target.checked)} />
                                            On
                                          </label>
                                        </div>
                                      </div>
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        <div className="grid-action-buttons">
                          <button className="add-header-btn" onClick={addRow}>+ Row</button>
                          <button className="add-header-btn" onClick={addColumn}>+ Column</button>
                        </div>
                      </div>
                    ) : (
                      <>
                        {selectedQuestion.type === 'short_text' && <input className="edit-preview-input" disabled placeholder="Short answer…" />}
                        {selectedQuestion.type === 'long_text' && <textarea className="edit-preview-input edit-preview-textarea" disabled placeholder="Long answer…" />}
                        {selectedQuestion.type === 'number' && <input type="number" className="edit-preview-input" disabled placeholder="0" />}
                        {selectedQuestion.type === 'date' && <input type="date" className="edit-preview-input" disabled />}
                        {selectedQuestion.type === 'time' && <input type="time" className="edit-preview-input" disabled />}
                        {selectedQuestion.type === 'email' && <input type="email" className="edit-preview-input" disabled placeholder="your@email.com" />}
                        {selectedQuestion.type === 'phone' && <input type="tel" className="edit-preview-input" disabled placeholder="+1 234 567 8900" />}
                        {selectedQuestion.type === 'url' && <input type="url" className="edit-preview-input" disabled placeholder="https://example.com" />}
                        {selectedQuestion.type === 'rating' && (
                          <div className="edit-preview-rating">
                            {[1,2,3,4,5].map(i => <span key={i} className="edit-star">★</span>)}
                          </div>
                        )}
                        {selectedQuestion.type === 'yes_no' && (
                          <div className="edit-yesno">
                            <button className="edit-yesno-btn" disabled>✓ Yes</button>
                            <button className="edit-yesno-btn" disabled>✗ No</button>
                          </div>
                        )}
                        {(selectedQuestion.type === 'radio' || selectedQuestion.type === 'checkbox' || selectedQuestion.type === 'select') && (
                          <div className="edit-options">
                            {selectedQuestion.options.map((opt, i) => (
                              <div key={i} className="edit-option-row">
                                <span className="edit-option-bullet">
                                  {selectedQuestion.type === 'radio' ? '◯' : selectedQuestion.type === 'checkbox' ? '☐' : `${i+1}.`}
                                </span>
                                <input
                                  className="edit-option-input"
                                  value={opt}
                                  onChange={e => updateOption(i, e.target.value)}
                                  placeholder={`Option ${i + 1}`}
                                />
                                <button className="edit-option-remove" onClick={() => removeOption(i)}>×</button>
                              </div>
                            ))}
                            <button className="edit-add-option" onClick={addOption}>
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                              Add option
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              ) : (
                <div className="edit-canvas-empty">
                  <div className="edit-canvas-empty-icon">
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#cfd9f4" strokeWidth="1.2">
                      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                      <polyline points="14,2 14,8 20,8"/>
                      <line x1="12" y1="18" x2="12" y2="12"/>
                      <line x1="9" y1="15" x2="15" y2="15"/>
                    </svg>
                  </div>
                  <h3>No question selected</h3>
                  <p>Click a question from the left panel, or add a new one.</p>
                  <button className="edit-add-btn" style={{marginTop:'1rem'}} onClick={() => setShowAddModal(true)}>+ Add Question</button>
                </div>
              )
            )}

            {/* SETTINGS TAB */}
            {currentTab === 'settings' && (
              <div className="edit-settings-card">
                <h2 className="edit-section-title">Form Settings</h2>

                <div className="edit-settings-group">
                  <label className="edit-settings-label">Form Title</label>
                  <input
                    className="edit-settings-input"
                    value={title}
                    onChange={e => setTitle(e.target.value)}
                    placeholder="Enter form title…"
                  />
                </div>

                <div className="edit-settings-group">
                  <label className="edit-settings-label">Description</label>
                  <textarea
                    className="edit-settings-input edit-settings-textarea"
                    value={description}
                    onChange={e => setDescription(e.target.value)}
                    placeholder="Describe what this form is for…"
                    rows={4}
                  />
                </div>

                <div className="edit-settings-divider"/>

                <h3 className="edit-settings-subtitle">Response Controls</h3>

                <div className="edit-settings-group">
                  <label className="edit-settings-label">
                    Close Date
                    <span className="edit-settings-hint">Stop accepting responses after this date & time</span>
                  </label>
                  <input
                    className="edit-settings-input"
                    type="datetime-local"
                    value={closeDate}
                    onChange={e => setCloseDate(e.target.value)}
                  />
                  {closeDate && (
                    <button className="edit-settings-clear" onClick={() => setCloseDate('')}>
                      ✕ Remove close date
                    </button>
                  )}
                </div>

                <div className="edit-settings-group">
                  <label className="edit-settings-label">
                    Max Total Responses
                    <span className="edit-settings-hint">0 = unlimited</span>
                  </label>
                  <input
                    className="edit-settings-input edit-settings-input--sm"
                    type="number"
                    min="0"
                    value={maxTotalResponses}
                    onChange={e => setMaxTotalResponses(e.target.value)}
                    placeholder="0"
                  />
                </div>

                <div className="edit-settings-divider"/>

                <button className="edit-save-btn edit-settings-save-btn" onClick={handleSave} disabled={isSaving}>
                  {isSaving ? 'Saving…' : 'Save Settings'}
                </button>
              </div>
            )}

            {/* DELIVER TAB */}
            {currentTab === 'deliver' && (
              <div className="edit-deliver-wrap">

                {/* Publish card */}
                <div className="edit-deliver-card">
                  <div className="edit-deliver-card-header">
                    <div className="edit-deliver-card-icon" style={{
                      background: isClosed ? '#f5f0ff' : isPublished ? '#e7f9f0' : '#fff8ec',
                      color:      isClosed ? '#7c4fff' : isPublished ? '#1a7a4a' : '#a06000'
                    }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        {isClosed
                          ? <><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></>
                          : isPublished
                            ? <><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></>
                            : <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></>
                        }
                      </svg>
                    </div>
                    <div>
                      <div className="edit-deliver-card-title">
                        {isClosed ? 'Form is Closed' : isPublished ? 'Form is Live' : 'Form is Unpublished'}
                      </div>
                      <div className="edit-deliver-card-sub">
                        {isClosed
                          ? closeDate && new Date() > new Date(closeDate)
                            ? `Closed on ${new Date(closeDate).toLocaleString()}`
                            : `Response limit of ${maxTotalResponses} reached`
                          : isPublished
                            ? 'Your form is accepting responses.'
                            : 'Publish your form to start collecting responses.'
                        }
                      </div>
                    </div>
                    <button
                      className={`edit-publish-btn ${isPublished ? 'edit-publish-btn--unpublish' : 'edit-publish-btn--publish'}`}
                      onClick={handleTogglePublish}
                    >
                      {isPublished ? 'Unpublish' : 'Publish Form'}
                    </button>
                  </div>
                </div>

                {/* Share link card */}
                <div className="edit-deliver-card">
                  <div className="edit-deliver-card-label">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                      <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                    </svg>
                    Share Link
                  </div>
                  <div className="edit-deliver-link-row">
                    <span className="edit-deliver-link-text">{shareLink}</span>
                    <button className={`edit-deliver-copy-btn ${linkCopied ? 'edit-deliver-copy-btn--copied' : ''}`} onClick={copyLink}>
                      {linkCopied ? '✓ Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>

                {/* QR code card */}
                <div className="edit-deliver-card">
                  <div className="edit-deliver-card-label">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="3" width="5" height="5"/><rect x="16" y="3" width="5" height="5"/>
                      <rect x="3" y="16" width="5" height="5"/><path d="M21 16h-3v3"/><path d="M21 21h-3"/><path d="M16 16v3"/><path d="M3 10h3"/><path d="M10 3v3"/><path d="M10 10h5v3h-5z"/>
                    </svg>
                    QR Code
                  </div>
                  {!qrImage ? (
                    <div className="edit-qr-placeholder">
                      <button className="edit-qr-generate-btn" onClick={handleGenerateQR} disabled={qrLoading}>
                        {qrLoading
                          ? <><span className="edit-save-spinner" style={{borderTopColor:'#fff',borderColor:'rgb(255,255,255,0.3)'}}/> Generating…</>
                          : <><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="5" height="5"/><rect x="16" y="3" width="5" height="5"/><rect x="3" y="16" width="5" height="5"/><path d="M21 16h-3v3"/><path d="M21 21h-3"/><path d="M16 16v3"/></svg> Generate QR Code</>
                        }
                      </button>
                      <p className="edit-qr-hint">Creates a scannable QR code pointing to your form's share link.</p>
                    </div>
                  ) : (
                    <div className="edit-qr-result">
                      <img src={qrImage} alt="QR Code" className="edit-qr-img" />
                      <div className="edit-qr-actions">
                        <button className="edit-deliver-copy-btn" onClick={handleDownloadQR}>
                          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                          Download PNG
                        </button>
                        <button className="edit-deliver-copy-btn" onClick={handleGenerateQR} disabled={qrLoading}>
                          Regenerate
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Embed card */}
                <div className="edit-deliver-card">
                  <div className="edit-deliver-card-label">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/>
                    </svg>
                    Embed Code
                  </div>
                  <div className="edit-embed-box">
                    <code className="edit-embed-code">{embedCode}</code>
                    <button className={`edit-deliver-copy-btn edit-embed-copy ${embedCopied ? 'edit-deliver-copy-btn--copied' : ''}`} onClick={copyEmbed}>
                      {embedCopied ? '✓ Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>

              </div>
            )}
          </main>

          {/* ── Right sidebar ── */}
          <aside className={`edit-right ${selectedQuestion && currentTab === 'edit' ? 'edit-right--visible' : ''}`}>
            {selectedQuestion && currentTab === 'edit' && (
              <div className="edit-right-inner">
                <div className="edit-right-header">
                  <span className="edit-right-title">Question Settings</span>
                </div>

                <div className="edit-right-section">
                  <Toggle
                    label="Required"
                    checked={selectedQuestion.required}
                    onChange={v => updateQuestion('required', v)}
                  />
                </div>

                {isGrid && (
                  <div className="edit-right-section">
                    <div className="edit-right-section-label">Grid Rules</div>
                    <Toggle label="One selection per row" checked={selectedQuestion.singlePerRow || false} onChange={v => updateQuestion('singlePerRow', v)} />
                    <Toggle label="One selection per column" checked={selectedQuestion.singlePerColumn || false} onChange={v => updateQuestion('singlePerColumn', v)} />
                  </div>
                )}

                <div className="edit-right-section edit-right-section--type">
                  <div className="edit-right-section-label">Type</div>
                  <div className="edit-right-type-chip">
                    {TYPE_META[selectedQuestion.type]?.icon} {TYPE_META[selectedQuestion.type]?.label}
                  </div>
                </div>

                <div className="edit-right-section edit-right-section--id">
                  <div className="edit-right-section-label">Question ID</div>
                  <code className="edit-right-id">{selectedQuestion.id}</code>
                </div>
              </div>
            )}
          </aside>

        </div>
      </div>

      {/* ── Add Question Modal ── */}
      {showAddModal && (
        <div className="edit-modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="edit-modal" onClick={e => e.stopPropagation()}>
            <div className="edit-modal-header">
              <h3>Choose Question Type</h3>
              <button className="edit-modal-close" onClick={() => setShowAddModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
            <div className="edit-type-grid">
              {Object.entries(TYPE_META).map(([type, meta]) => (
                <button key={type} className="edit-type-card" onClick={() => addQuestion(type)}>
                  <span className="edit-type-card-icon">{meta.icon}</span>
                  <span className="edit-type-card-label">{meta.label}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </DndProvider>
  );
}

// ─── Question Card (draggable) ────────────────────────────────────────────────
function QuestionCard({ question, index, isSelected, onSelect, moveQuestion, onDelete }) {
  const [, drop] = useDrop({
    accept: ITEM_TYPE,
    hover: (item) => {
      if (item.index !== index) { moveQuestion(item.index, index); item.index = index; }
    },
  });
  const [{ isDragging }, drag] = useDrag({
    type: ITEM_TYPE,
    item: { index },
    collect: monitor => ({ isDragging: monitor.isDragging() }),
  });

  const meta = TYPE_META[question.type];

  return (
    <div
      ref={node => drag(drop(node))}
      className={`edit-qcard ${isSelected ? 'edit-qcard--active' : ''} ${isDragging ? 'edit-qcard--dragging' : ''}`}
      onClick={onSelect}
    >
      <div className="edit-qcard-drag">
        <svg width="12" height="16" viewBox="0 0 8 14" fill="#9aabcc">
          <circle cx="2" cy="2" r="1.5"/><circle cx="6" cy="2" r="1.5"/>
          <circle cx="2" cy="7" r="1.5"/><circle cx="6" cy="7" r="1.5"/>
          <circle cx="2" cy="12" r="1.5"/><circle cx="6" cy="12" r="1.5"/>
        </svg>
      </div>
      <div className="edit-qcard-body">
        <div className="edit-qcard-type">{meta?.icon} {meta?.label}</div>
        <div className="edit-qcard-label">{question.label || 'Untitled question'}</div>
      </div>
      <button
        className="edit-qcard-delete"
        onClick={e => { e.stopPropagation(); onDelete(); }}
        title="Delete"
      >
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
          <polyline points="3,6 5,6 21,6"/>
          <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a1,1,0,0,1,1-1h6a1,1,0,0,1,1,1v2"/>
        </svg>
      </button>
    </div>
  );
}

export default Edit;