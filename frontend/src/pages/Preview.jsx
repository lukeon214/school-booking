import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../lib/axios';
import '../Preview.css';

function Preview() {
  const { publicId } = useParams();
  const navigate = useNavigate();

  const [form, setForm]       = useState(null);
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    api.get(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, { withCredentials: true })
      .then(res => { setForm(res.data); setLoading(false); })
      .catch(() => { setError('Could not load form.'); setLoading(false); });
  }, [publicId]);

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

  const updateAnswer = (qId, value) =>
    setAnswers(prev => ({ ...prev, [qId]: value }));

  const handleGridClick = (qId, cellKey, question) => {
    const cell = question.cells[cellKey];
    if (!cell?.enabled) return;

    let current = answers[qId] || [];

    if (current.includes(cellKey)) {
      updateAnswer(qId, current.filter(k => k !== cellKey));
      return;
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

  if (loading) return (
    <div className="pv-shell pv-shell--center">
      <div className="pf-spinner" />
      <p className="pf-loading-text">Loading preview…</p>
    </div>
  );

  if (error) return (
    <div className="pv-shell pv-shell--center">
      <div className="pf-state-card">
        <div className="pf-state-icon pf-state-icon--error">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <h2 className="pf-state-title">Could not load form</h2>
        <p className="pf-state-sub">{error}</p>
        <button className="pv-back-btn-inline" onClick={() => navigate(-1)}>← Go back</button>
      </div>
    </div>
  );

  const questions = form.schemaJson.questions;

  return (
    <div className="pv-shell">

      {/* ── Preview banner ── */}
      <div className="pv-banner">
        <button className="pv-back-btn" onClick={() => navigate(-1)}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M19 12H5M12 5l-7 7 7 7"/>
          </svg>
          Back
        </button>
        <div className="pv-banner-center">
          <span className="pv-banner-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </span>
          Preview Mode — responses will not be saved
        </div>
        <div className="pv-banner-right">
          <span className={`pv-status-badge pv-status-badge--${form.isPublished ? 'published' : 'draft'}`}>
            {form.isPublished ? 'Published' : 'Draft'}
          </span>
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="pf-progress-bar-wrap">
        <div className="pf-progress-bar" style={{ width: `${progressPct}%` }} />
      </div>

      <main className="pf-main">

        {/* Header */}
        <div className="pf-header">
          <h1 className="pf-title">{form.title}</h1>
          {form.description && <p className="pf-description">{form.description}</p>}
          <div className="pf-progress-label">{answeredCount} of {totalQuestions} answered</div>
        </div>

        {/* Questions */}
        <div className="pf-questions">
          {questions.map((q, idx) => {
            const qId = q.id;
            const ans = answers[qId];

            return (
              <div key={qId} className="pf-question">
                <div className="pf-question-header">
                  <span className="pf-q-num">{idx + 1}</span>
                  <label className="pf-q-label">
                    {q.label || <em style={{ color: '#b0bdda' }}>Untitled question</em>}
                    {q.required && <span className="pf-required"> *</span>}
                  </label>
                </div>

                {q.description && <p className="pf-q-desc">{q.description}</p>}

                <div className="pf-answer-area">

                  {q.type === 'short_text' && (
                    <input type="text" className="pf-input" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="Short answer…" />
                  )}
                  {q.type === 'long_text' && (
                    <textarea className="pf-input pf-textarea" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="Long answer…" rows={5} />
                  )}
                  {q.type === 'number' && (
                    <input type="number" className="pf-input pf-input--sm" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="0" />
                  )}
                  {q.type === 'date' && (
                    <input type="date" className="pf-input pf-input--sm" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} />
                  )}
                  {q.type === 'time' && (
                    <input type="time" className="pf-input pf-input--sm" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} />
                  )}
                  {q.type === 'email' && (
                    <input type="email" className="pf-input" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="your@email.com" />
                  )}
                  {q.type === 'phone' && (
                    <input type="tel" className="pf-input pf-input--sm" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="+0 123 456 789" />
                  )}
                  {q.type === 'url' && (
                    <input type="url" className="pf-input" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)} placeholder="https://example.com" />
                  )}

                  {q.type === 'rating' && (
                    <div className="pf-rating">
                      {[5, 4, 3, 2, 1].map(star => (
                        <React.Fragment key={star}>
                          <input type="radio" id={`star-${qId}-${star}`} name={`rating-${qId}`} value={star}
                            checked={ans === String(star)} onChange={e => updateAnswer(qId, e.target.value)} />
                          <label htmlFor={`star-${qId}-${star}`}>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                              <path pathLength="360" d="M12,17.27L18.18,21L16.54,13.97L22,9.24L14.81,8.62L12,2L9.19,8.62L2,9.24L7.45,13.97L5.82,21L12,17.27Z"/>
                            </svg>
                          </label>
                        </React.Fragment>
                      ))}
                    </div>
                  )}

                  {q.type === 'yes_no' && (
                    <div className="pf-yesno">
                      {['Yes', 'No'].map(opt => (
                        <React.Fragment key={opt}>
                          <input type="radio" id={`${opt.toLowerCase()}-${qId}`} name={`yesno-${qId}`}
                            value={opt} checked={ans === opt} onChange={e => updateAnswer(qId, e.target.value)} style={{ display: 'none' }} />
                          <label htmlFor={`${opt.toLowerCase()}-${qId}`} className={`pf-yesno-btn ${ans === opt ? 'pf-yesno-btn--selected' : ''}`}>
                            {opt === 'Yes'
                              ? <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg> Yes</>
                              : <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> No</>
                            }
                          </label>
                        </React.Fragment>
                      ))}
                    </div>
                  )}

                  {(q.type === 'radio' || q.type === 'checkbox') && (
                    <div className="pf-choices">
                      {q.options.map((opt, i) => {
                        const isChecked = q.type === 'radio' ? ans === opt : (ans || []).includes(opt);
                        return (
                          <label key={i} className={`pf-choice ${isChecked ? 'pf-choice--selected' : ''}`}>
                            <input type={q.type === 'radio' ? 'radio' : 'checkbox'} name={`choice-${qId}`}
                              checked={isChecked}
                              onChange={() => {
                                if (q.type === 'radio') { updateAnswer(qId, opt); }
                                else {
                                  const current = ans || [];
                                  updateAnswer(qId, current.includes(opt) ? current.filter(o => o !== opt) : [...current, opt]);
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

                  {q.type === 'select' && (
                    <div className="pf-select-wrap">
                      <select className="pf-select" value={ans || ''} onChange={e => updateAnswer(qId, e.target.value)}>
                        <option value="">Select an option…</option>
                        {q.options.map((opt, i) => <option key={i} value={opt}>{opt}</option>)}
                      </select>
                      <svg className="pf-select-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="6 9 12 15 18 9"/>
                      </svg>
                    </div>
                  )}

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
                                const cell = q.cells[cellKey] || { text: '', max: 0, enabled: true };
                                const isDisabled = !cell.enabled;
                                const isSelected = (ans || []).includes(cellKey);
                                return (
                                  <td
                                    key={col.id}
                                    className={[
                                      'pf-matrix-cell',
                                      isSelected ? 'pf-matrix-cell--selected' : '',
                                      isDisabled ? 'pf-matrix-cell--disabled' : '',
                                    ].join(' ')}
                                    onClick={() => !isDisabled && handleGridClick(qId, cellKey, q)}
                                  >
                                    {!isDisabled && (
                                      <>
                                        <div className="pf-cell-text">{cell.text || ''}</div>
                                        {cell.max > 0 && (
                                          <div className="pf-cell-badge">max {cell.max}</div>
                                        )}
                                        {isSelected && (
                                          <div className="pf-cell-check">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                              <polyline points="20 6 9 17 4 12"/>
                                            </svg>
                                          </div>
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
              </div>
            );
          })}
        </div>

        {/* Disabled submit */}
        <div className="pf-submit-wrap">
          <button className="pf-submit-btn pv-submit-disabled" disabled>
            Submit Responses
          </button>
          <p className="pf-submit-hint">This is a preview — submissions are disabled.</p>
        </div>

        <div className="pf-footer">
          Powered by <span className="pf-footer-brand">data<span>booq</span></span>
        </div>
      </main>
    </div>
  );
}

export default Preview;