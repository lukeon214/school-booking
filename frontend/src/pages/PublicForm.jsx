import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

function PublicForm() {
  const { publicId } = useParams();
  const navigate = useNavigate();

  const [form, setForm] = useState(null);
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/f/${publicId}`)
      .then(res => {
        setForm(res.data);
        setLoading(false);
      })
      .catch(() => {
        setError('Form not found or not published');
        setLoading(false);
      });
  }, [publicId]);

  const updateAnswer = (qId, value) => {
    setAnswers(prev => ({ ...prev, [qId]: value }));
  };

  // ==================== GRID HANDLER ====================
  const handleGridClick = (qId, cellKey, question) => {
    let current = answers[qId] || [];
    let newSelection;

    if (current.includes(cellKey)) {
      newSelection = current.filter(k => k !== cellKey);
    } else {
      newSelection = [...current, cellKey];

      if (question.singlePerRow) {
        const rowId = cellKey.split('-')[0];
        newSelection = newSelection.filter(k => !k.startsWith(rowId) || k === cellKey);
      }
      if (question.singlePerColumn) {
        const colId = cellKey.split('-')[1];
        newSelection = newSelection.filter(k => !k.endsWith(`-${colId}`) || k === cellKey);
      }
    }

    // Max limit check
    const cell = question.cells[cellKey];
    if (cell.max > 0) {
      const count = newSelection.filter(k => k === cellKey).length;
      if (count > cell.max) return;
    }

    updateAnswer(qId, newSelection);
  };

  const handleSubmit = async () => {
    const requiredMissing = form.schemaJson.questions.some(q =>
      q.required && !answers[q.id]
    );

    if (requiredMissing) {
      alert('Please answer all required questions');
      return;
    }

    setSubmitting(true);
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/f/${publicId}/submit`, {
        data: answers
      });
      setSubmitted(true);
    } catch (err) {
      alert('Failed to submit. Please try again.');
    }
    setSubmitting(false);
  };

  if (loading) return <div style={{ textAlign: 'center', padding: '4rem' }}>Loading form...</div>;
  if (error) return <div style={{ textAlign: 'center', padding: '4rem', color: '#e83b4e' }}>{error}</div>;
  if (submitted) {
    return (
      <div style={{ textAlign: 'center', padding: '6rem 1rem', fontFamily: "'Poppins', Arial, sans-serif" }}>
        <h1 style={{ color: '#2c3a75', fontSize: '2.8rem' }}>Thank you!</h1>
        <p style={{ fontSize: '1.3rem', color: '#465183', marginTop: '1rem' }}>
          Your responses have been recorded.
        </p>
        <button onClick={() => navigate('/')} className="submit-btn" style={{ marginTop: '2rem' }}>
          Back to Home
        </button>
      </div>
    );
  }

  return (
    <div className="public-form-body">
      <main>
        <h1>{form.title}</h1>
        {form.description && <p className="description-top">{form.description}</p>}
        <hr></hr>

        {form.schemaJson.questions.map((q, idx) => {
          const qId = q.id;
          const ans = answers[qId];

          return (
            <div key={qId} className="question-block">
              <label>
                {idx + 1}. {q.label}
                {q.required && <span style={{ color: '#e83b4e' }}> *</span>}
              </label>
              {q.description && <p className="description">{q.description}</p>}

              <div className="answer-area">
                {/* ==================== SIMPLE TYPES ==================== */}
                {q.type === 'short_text' && (
                  <input
                    type="text"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="Type your answer here..."
                  />
                )}

                {q.type === 'long_text' && (
                  <textarea
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="Type your answer here..."
                    rows={5}
                  />
                )}

                {q.type === 'number' && (
                  <input
                    type="number"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="Enter a number..."
                  />
                )}

                {q.type === 'date' && (
                  <input
                    type="date"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                  />
                )}

                {q.type === 'time' && (
                  <input
                    type="time"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                  />
                )}

                {q.type === 'email' && (
                  <input
                    type="email"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="your@email.com"
                  />
                )}

                {q.type === 'phone' && (
                  <input
                    type="tel"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="+0 123 456 789"
                  />
                )}

                {q.type === 'url' && (
                  <input
                    type="url"
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                    placeholder="www.example.com"
                  />
                )}

                {/* ==================== RATING ==================== */}
                {q.type === 'rating' && (
                  <div className="rating">
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
                            <path 
                              pathLength="360" 
                              d="M12,17.27L18.18,21L16.54,13.97L22,9.24L14.81,8.62L12,2L9.19,8.62L2,9.24L7.45,13.97L5.82,21L12,17.27Z"
                            />
                          </svg>
                        </label>
                      </React.Fragment>
                    ))}
                  </div>
                )}

                {/* ==================== YES/NO ==================== */}
                {q.type === 'yes_no' && (
                  <div className="yesno-container">
                    <input
                      type="radio"
                      id={`yes-${qId}`}
                      name={`yesno-${qId}`}
                      value="Yes"
                      checked={ans === 'Yes'}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      style={{ display: 'none'}}
                    />
                    <label htmlFor={`yes-${qId}`}>Yes</label>

                    <input
                      type="radio"
                      id={`no-${qId}`}
                      name={`yesno-${qId}`}
                      value="No"
                      checked={ans === 'No'}
                      onChange={e => updateAnswer(qId, e.target.value)}
                      style={{ display: 'none'}}
                    />
                    <label htmlFor={`no-${qId}`}>No</label>
                  </div>
                )}

                {/* ==================== RADIO / CHECKBOX / SELECT ==================== */}
                {(q.type === 'radio' || q.type === 'checkbox') && (
                  <div className="choice-options">
                    {q.options.map((opt, i) => (
                      <label key={i}>
                        <input
                          type={q.type === 'radio' ? 'radio' : 'checkbox'}
                          name={`choice-${qId}`}
                          checked={q.type === 'radio' ? ans === opt : (ans || []).includes(opt)}
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
                        <span>{opt}</span>
                      </label>
                    ))}
                  </div>
                )}

                {q.type === 'select' && (
                  <select
                    className="input-field"
                    value={ans || ''}
                    onChange={e => updateAnswer(qId, e.target.value)}
                  >
                    <option value="">Select an option...</option>
                    {q.options.map((opt, i) => (
                      <option key={i} value={opt}>{opt}</option>
                    ))}
                  </select>
                )}

                {/* ==================== GRID / MATRIX ==================== */}
                {q.type === 'grid' && (
                  <div className="grid-container">
                    <table className="matrix-grid">
                      <thead>
                        <tr>
                          <th></th>
                          {q.columns.map(col => <th key={col.id}>{col.label}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {q.rows.map(row => (
                          <tr key={row.id}>
                            <td className="row-label">{row.label}</td>
                            {q.columns.map(col => {
                              const cellKey = `${row.id}-${col.id}`;
                              const cell = q.cells[cellKey] || { text: '', max: 0, enabled: true, used: 0 };
                              const usage = cell.used || 0;
                              const isFull = cell.max > 0 && usage >= cell.max;
                              const isEditorDisabled = !cell.enabled;
                              const selected = (ans || []).includes(cellKey);

                              return (
                                <td
                                  key={col.id}
                                  className={`grid-cell 
                                    ${selected ? 'selected' : ''} 
                                    ${isEditorDisabled ? 'editor-disabled' : ''} 
                                    ${isFull ? 'max-full' : ''}`}
                                  onClick={() => !isEditorDisabled && !isFull && handleGridClick(qId, cellKey, q)}
                                >
                                  <div className="cell-value">{cell.text || ''}</div>

                                  {cell.max > 0 && !isEditorDisabled && (
                                    <div className="max-badge">
                                      {usage}/{cell.max}
                                    </div>
                                  )}

                                  {selected && <span className="selection-checkbox"></span>}

                                  {isFull && !isEditorDisabled && (
                                    <div className="full-overlay">Full</div>
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

        <button
          className="submit-btn"
          onClick={handleSubmit}
          disabled={submitting}
        >
          {submitting ? 'Submitting...' : 'Submit Responses'}
        </button>
      </main>
    </div>
  );
}

export default PublicForm;