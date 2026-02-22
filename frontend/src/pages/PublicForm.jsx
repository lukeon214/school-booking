import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import '../PublicForm.css';

function PublicForm() {
  const { publicId } = useParams();

  const [form, setForm]           = useState(null);
  const [answers, setAnswers]     = useState({});
  const [loading, setLoading]     = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError]         = useState('');
  const [closedReason, setClosedReason] = useState(null); // 'closeDate' | 'maxResponses' | 'unpublished'
  const [validationErrors, setValidationErrors] = useState({});
  // Live cell usage counts from backend { [qId]: { [cellKey]: count } }
  const [liveCounts, setLiveCounts] = useState({});

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/f/${publicId}`)
      .then(res => {
        const data = res.data;
        // Backend returns status: 'published' | 'closed'
        if (data.status === 'closed') {
          setClosedReason(
            data.closeDate && new Date() > new Date(data.closeDate)
              ? 'closeDate'
              : 'maxResponses'
          );
          setForm(data);
        } else {
          setForm(data);
        }
        setLoading(false);
      })
      .catch(err => {
        const msg = err.response?.data?.error || '';
        if (msg.includes('not published') || err.response?.status === 404) {
          setClosedReason('unpublished');
        } else {
          setError(msg || 'Something went wrong loading this form.');
        }
        setLoading(false);
      });
  }, [publicId]);

  // ── Live grid counts (polling) ───────────────────────────────────────────
  const fetchLiveCounts = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/f/${publicId}/grid-counts`);
      setLiveCounts(res.data);
    } catch {
      // silently ignore — stale counts are better than crashing
    }
  };

  useEffect(() => {
    if (!form || closedReason || submitted) return;
    // Fetch immediately on load, then every 5 seconds
    fetchLiveCounts();
    const interval = setInterval(fetchLiveCounts, 5000);
    return () => clearInterval(interval);
  }, [form, closedReason, submitted]);

  // ── Progress ──────────────────────────────────────────────────────────────
  const totalQuestions = form?.schemaJson?.questions?.length || 0;
  const answeredCount = form
    ? form.schemaJson.questions.filter(q => {
        const a = answers[q.id];
        if (a === undefined || a === null || a === '') return false;
        if (Array.isArray(a)) return a.length > 0;
        return true;
      }).length
    : 0;
  const progressPct = totalQuestions > 0 ? Math.round((answeredCount / totalQuestions) * 100) : 0;

  // ── Answer helpers ────────────────────────────────────────────────────────
  const updateAnswer = (qId, value) => {
    setAnswers(prev => ({ ...prev, [qId]: value }));
    if (validationErrors[qId]) {
      setValidationErrors(prev => { const n = { ...prev }; delete n[qId]; return n; });
    }
  };

  // ── Grid handler ──────────────────────────────────────────────────────────
  const getLiveUsed = (qId, cellKey) => liveCounts?.[qId]?.[cellKey] || 0;

  const handleGridClick = (qId, cellKey, question) => {
    const cell = question.cells[cellKey];
    if (!cell?.enabled) return;

    let current = answers[qId] || [];

    if (current.includes(cellKey)) {
      updateAnswer(qId, current.filter(k => k !== cellKey));
      return;
    }

    // Max capacity: use live submission count from backend
    if (cell.max > 0) {
      const liveUsed = getLiveUsed(qId, cellKey);
      if (liveUsed >= cell.max) return;
    }

    let newSelection = [...current, cellKey];

    if (question.singlePerRow) {
      const rowId = cellKey.split('-')[0];
      newSelection = newSelection.filter(k => !k.startsWith(`${rowId}-`) || k === cellKey);
    }
    if (question.singlePerColumn) {
      const colId = cellKey.split('-').slice(1).join('-');
      newSelection = newSelection.filter(k => !k.endsWith(`-${colId}`) || k === cellKey);
    }

    updateAnswer(qId, newSelection);
  };

  // ── Submit ────────────────────────────────────────────────────────────────
  const handleSubmit = async () => {
    const errors = {};
    form.schemaJson.questions.forEach(q => {
      if (!q.required) return;
      const a = answers[q.id];
      const empty = a === undefined || a === null || a === '' || (Array.isArray(a) && a.length === 0);
      if (empty) errors[q.id] = 'This question is required.';
    });

    if (Object.keys(errors).length > 0) {
      setValidationErrors(errors);
      // Scroll to first error
      const firstId = Object.keys(errors)[0];
      document.getElementById(`q-${firstId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }

    setSubmitting(true);
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/f/${publicId}`, answers);
      await fetchLiveCounts(); // refresh so counts update before thank-you screen
      setSubmitted(true);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      const msg = err.response?.data?.error || '';
      const reason = err.response?.data?.reason;
      if (err.response?.status === 403) {
        // Form was closed between page load and submit
        setClosedReason(reason === 'closeDate' ? 'closeDate' : 'maxResponses');
      } else {
        alert('Failed to submit. Please try again.');
      }
    }
    setSubmitting(false);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Special screens
  // ─────────────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="pf-shell pf-shell--center">
        <div className="pf-spinner" />
        <p className="pf-loading-text">Loading form…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="pf-shell pf-shell--center">
        <div className="pf-state-card">
          <div className="pf-state-icon pf-state-icon--error">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <h2 className="pf-state-title">Something went wrong</h2>
          <p className="pf-state-sub">{error}</p>
        </div>
      </div>
    );
  }

  if (closedReason === 'unpublished') {
    return (
      <div className="pf-shell pf-shell--center">
        <div className="pf-state-card">
          <div className="pf-state-icon pf-state-icon--grey">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14,2 14,8 20,8"/>
            </svg>
          </div>
          <h2 className="pf-state-title">Form not available</h2>
          <p className="pf-state-sub">This form doesn't exist or hasn't been published yet.</p>
        </div>
      </div>
    );
  }

  if (closedReason) {
    return (
      <div className="pf-shell pf-shell--center">
        <div className="pf-state-card">
          <div className="pf-state-icon pf-state-icon--closed">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
          </div>
          <h2 className="pf-state-title">This form is closed</h2>
          <p className="pf-state-sub">
            {closedReason === 'closeDate'
              ? `This form stopped accepting responses on ${new Date(form.closeDate).toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })}.`
              : 'This form has reached its maximum number of responses.'}
          </p>
          {form?.title && <p className="pf-state-form-name">"{form.title}"</p>}
        </div>
      </div>
    );
  }

  if (submitted) {
    return (
      <div className="pf-shell pf-shell--center">
        <div className="pf-state-card pf-state-card--success">
          <div className="pf-state-icon pf-state-icon--success">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
              <polyline points="22,4 12,14.01 9,11.01"/>
            </svg>
          </div>
          <h2 className="pf-state-title">Thank you!</h2>
          <p className="pf-state-sub">Your responses have been recorded successfully.</p>
          {form?.title && <p className="pf-state-form-name">"{form.title}"</p>}
        </div>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Main form
  // ─────────────────────────────────────────────────────────────────────────

  const questions = form.schemaJson.questions;

  return (
    <div className="pf-shell">
      {/* Progress bar */}
      <div className="pf-progress-bar-wrap">
        <div className="pf-progress-bar" style={{ width: `${progressPct}%` }} />
      </div>

      <main className="pf-main">
        {/* Header */}
        <div className="pf-header">
          <h1 className="pf-title">{form.title}</h1>
          {form.description && <p className="pf-description">{form.description}</p>}
          <div className="pf-progress-label">
            {answeredCount} of {totalQuestions} answered
          </div>
        </div>

        {/* Questions */}
        <div className="pf-questions">
          {questions.map((q, idx) => {
            const qId = q.id;
            const ans = answers[qId];
            const hasError = !!validationErrors[qId];

            return (
              <div
                key={qId}
                id={`q-${qId}`}
                className={`pf-question ${hasError ? 'pf-question--error' : ''}`}
              >
                <div className="pf-question-header">
                  <span className="pf-q-num">{idx + 1}</span>
                  <label className="pf-q-label">
                    {q.label}
                    {q.required && <span className="pf-required"> *</span>}
                  </label>
                </div>

                {q.description && <p className="pf-q-desc">{q.description}</p>}

                <div className="pf-answer-area">

                  {/* Short text */}
                  {q.type === 'short_text' && (
                    <input
                      type="text"
                      className="pf-input"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="Type your answer here…"
                    />
                  )}

                  {/* Long text */}
                  {q.type === 'long_text' && (
                    <textarea
                      className="pf-input pf-textarea"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="Type your answer here…"
                      rows={5}
                    />
                  )}

                  {/* Number */}
                  {q.type === 'number' && (
                    <input
                      type="number"
                      className="pf-input pf-input--sm"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="0"
                    />
                  )}

                  {/* Date */}
                  {q.type === 'date' && (
                    <input
                      type="date"
                      className="pf-input pf-input--sm"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                    />
                  )}

                  {/* Time */}
                  {q.type === 'time' && (
                    <input
                      type="time"
                      className="pf-input pf-input--sm"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                    />
                  )}

                  {/* Email */}
                  {q.type === 'email' && (
                    <input
                      type="email"
                      className="pf-input"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="your@email.com"
                    />
                  )}

                  {/* Phone */}
                  {q.type === 'phone' && (
                    <input
                      type="tel"
                      className="pf-input pf-input--sm"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="+0 123 456 789"
                    />
                  )}

                  {/* URL */}
                  {q.type === 'url' && (
                    <input
                      type="url"
                      className="pf-input"
                      value={ans || ''}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      placeholder="https://example.com"
                    />
                  )}

                  {/* Rating */}
                  {q.type === 'rating' && (
                    <div className="pf-rating">
                      {[5, 4, 3, 2, 1].map(star => (
                        <React.Fragment key={star}>
                          <input
                            type="radio"
                            id={`star-${qId}-${star}`}
                            name={`rating-${qId}`}
                            value={star}
                            checked={ans === String(star)}
                            onChange={e => updateAnswer(qId, e.target.value)}
                          />
                          <label htmlFor={`star-${qId}-${star}`}>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                              <path pathLength="360" d="M12,17.27L18.18,21L16.54,13.97L22,9.24L14.81,8.62L12,2L9.19,8.62L2,9.24L7.45,13.97L5.82,21L12,17.27Z"/>
                            </svg>
                          </label>
                        </React.Fragment>
                      ))}
                    </div>
                  )}

                  {/* Yes / No */}
                  {q.type === 'yes_no' && (
                    <div className="pf-yesno">
                      {['Yes', 'No'].map(opt => (
                        <React.Fragment key={opt}>
                          <input
                            type="radio"
                            id={`${opt.toLowerCase()}-${qId}`}
                            name={`yesno-${qId}`}
                            value={opt}
                            checked={ans === opt}
                            onChange={e => updateAnswer(qId, e.target.value)}
                            style={{ display: 'none' }}
                          />
                          <label
                            htmlFor={`${opt.toLowerCase()}-${qId}`}
                            className={`pf-yesno-btn ${ans === opt ? 'pf-yesno-btn--selected' : ''}`}
                          >
                            {opt === 'Yes'
                              ? <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg> Yes</>
                              : <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> No</>
                            }
                          </label>
                        </React.Fragment>
                      ))}
                    </div>
                  )}

                  {/* Radio / Checkbox */}
                  {(q.type === 'radio' || q.type === 'checkbox') && (
                    <div className="pf-choices">
                      {q.options.map((opt, i) => {
                        const isChecked = q.type === 'radio'
                          ? ans === opt
                          : (ans || []).includes(opt);
                        return (
                          <label
                            key={i}
                            className={`pf-choice ${isChecked ? 'pf-choice--selected' : ''}`}
                          >
                            <input
                              type={q.type === 'radio' ? 'radio' : 'checkbox'}
                              name={`choice-${qId}`}
                              checked={isChecked}
                              onChange={() => {
                                if (q.type === 'radio') {
                                  updateAnswer(qId, opt);
                                } else {
                                  const current = ans || [];
                                  updateAnswer(qId, current.includes(opt)
                                    ? current.filter(o => o !== opt)
                                    : [...current, opt]
                                  );
                                }
                              }}
                            />
                            <span className="pf-choice-indicator" />
                            <span className="pf-choice-label">{opt}</span>
                          </label>
                        );
                      })}
                    </div>
                  )}

                  {/* Select / Dropdown */}
                  {q.type === 'select' && (
                    <div className="pf-select-wrap">
                      <select
                        className="pf-select"
                        value={ans || ''}
                        onChange={e => updateAnswer(qId, e.target.value)}
                      >
                        <option value="">Select an option…</option>
                        {q.options.map((opt, i) => (
                          <option key={i} value={opt}>{opt}</option>
                        ))}
                      </select>
                      <svg className="pf-select-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="6 9 12 15 18 9"/>
                      </svg>
                    </div>
                  )}

                  {/* Grid / Matrix */}
                  {q.type === 'grid' && (
                    <div className="pf-grid-wrap">
                      <table className="pf-matrix">
                        <thead>
                          <tr>
                            <th className="pf-matrix-corner"></th>
                            {q.columns.map(col => (
                              <th key={col.id} className="pf-matrix-col-header">{col.label}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {q.rows.map(row => (
                            <tr key={row.id}>
                              <td className="pf-matrix-row-label">{row.label}</td>
                              {q.columns.map(col => {
                                const cellKey = `${row.id}-${col.id}`;
                                const cell = q.cells[cellKey] || { text: '', max: 0, enabled: true, used: 0 };
                                const usage = getLiveUsed(q.id, cellKey);
                                const isFull = cell.max > 0 && usage >= cell.max;
                                const isDisabled = !cell.enabled;
                                const isSelected = (ans || []).includes(cellKey);

                                return (
                                  <td
                                    key={col.id}
                                    className={[
                                      'pf-matrix-cell',
                                      isSelected  ? 'pf-matrix-cell--selected'  : '',
                                      isDisabled  ? 'pf-matrix-cell--disabled'  : '',
                                      isFull && !isSelected ? 'pf-matrix-cell--full' : '',
                                    ].join(' ')}
                                    onClick={() => !isDisabled && !(isFull && !isSelected) && handleGridClick(qId, cellKey, q)}
                                  >
                                    {!isDisabled && (
                                      <>
                                        <div className="pf-cell-text">{cell.text || ''}</div>
                                        {cell.max > 0 && (
                                          <div className={`pf-cell-badge ${isFull ? 'pf-cell-badge--full' : ''}`}>
                                            {usage}/{cell.max}
                                          </div>
                                        )}
                                        {isSelected && (
                                          <div className="pf-cell-check">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                              <polyline points="20 6 9 17 4 12"/>
                                            </svg>
                                          </div>
                                        )}
                                        {isFull && !isSelected && (
                                          <div className="pf-cell-full-overlay">Full</div>
                                        )}
                                      </>
                                    )}
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                </div>

                {hasError && (
                  <div className="pf-error-msg">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="8" x2="12" y2="12"/>
                      <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    {validationErrors[qId]}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Submit */}
        <div className="pf-submit-wrap">
          <button
            className="pf-submit-btn"
            onClick={handleSubmit}
            disabled={submitting}
          >
            {submitting
              ? <><span className="pf-btn-spinner" /> Submitting…</>
              : 'Submit Responses'
            }
          </button>
          <p className="pf-submit-hint">
            {Object.keys(validationErrors).length > 0
              ? `${Object.keys(validationErrors).length} required question${Object.keys(validationErrors).length > 1 ? 's' : ''} still need${Object.keys(validationErrors).length === 1 ? 's' : ''} an answer`
              : 'Your responses are saved securely.'
            }
          </p>
        </div>

        {/* Footer */}
        <div className="pf-footer">
          Powered by <span className="pf-footer-brand">data<span>booq</span></span>
        </div>
      </main>
    </div>
  );
}

export default PublicForm;



/* 600 lines yeaaa! */