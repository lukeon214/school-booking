import { useEffect, useState } from 'react';
import api from '../lib/axios';
import { useParams, useNavigate } from 'react-router-dom';
import { DndProvider, useDrag, useDrop } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';

const ITEM_TYPE = 'question';

function Edit() {
  const {publicId} = useParams();
  const [form, setForm] = useState(null);
  const [questions, setQuestions] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [selectedQuestionIndex, setSelectedQuestionIndex] = useState(null);
  const [selectedCellKey, setSelectedCellKey] = useState(null); // for grid cell selection
  const [currentTab, setCurrentTab] = useState('edit');
  const [showAddModal, setShowAddModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const [isSaving, setIsSaving] = useState(false);
  const [lastSavedTime, setLastSavedTime] = useState(null);

  useEffect(() => {
    api.get(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, { withCredentials: true })
      .then(res => {
        setForm(res.data);
        setTitle(res.data.title);
        setDescription(res.data.description || '');
        setQuestions(res.data.schemaJson.questions || []);
        setLoading(false);
      })
      .catch(() => {
        setError('Error loading form');
        setLoading(false);
      });
  }, [publicId]);

  useEffect(() => {
    if (loading || !publicId) return;

    const interval = setInterval(() => {
      silentSave();
    }, 60000);

    return () => clearInterval(interval);
  }, [title, description, questions, publicId, form?.isPublished, loading]);
  useEffect(() => {
    return () => {
      silentSave();
    };
  }, [title, description, questions]);

  const questionTypes = [
    { type: 'short_text', label: 'Short Text' },
    { type: 'long_text', label: 'Long Text' },
    { type: 'number', label: 'Number' },
    { type: 'radio', label: 'Single Choice' },
    { type: 'checkbox', label: 'Multiple Choice' },
    { type: 'select', label: 'Dropdown' },
    { type: 'date', label: 'Date' },
    { type: 'time', label: 'Time' },
    { type: 'email', label: 'Email' },
    { type: 'phone', label: 'Phone' },
    { type: 'url', label: 'URL' },
    { type: 'rating', label: 'Rating' },
    { type: 'yes_no', label: 'Yes/No' },
    { type: 'grid', label: 'Grid Table' },
  ];

  const addQuestion = (type) => {
    const newId = 'q' + (questions.length + 1);
    let newQuestion;

    if (type === 'grid') {
      const rows = Array.from({ length: 4 }, (_, i) => ({
        id: `r${i + 1}`,
        label: ``,
      }));
      const columns = Array.from({ length: 3 }, (_, i) => ({
        id: `c${i + 1}`,
        label: ``,
      }));
      const cells = {};
      rows.forEach(row => {
        columns.forEach(col => {
          cells[`${row.id}-${col.id}`] = { text: '', max: 0, enabled: true, used: 0 };
        });
      });

      newQuestion = {
        id: newId,
        label: '',
        description: '',
        type: 'grid',
        required: false,
        singlePerRow: false,
        singlePerColumn: false,
        rows,
        columns,
        cells,
      };
    } else {
      newQuestion = {
        id: newId,
        label: '',
        description: '',
        type,
        required: false,
        maxResponses: 0,
        options: type === 'yes_no' ? ['Yes', 'No'] : type === 'radio' || type === 'checkbox' || type === 'select' ? ['', ''] : [],
      };
    }

    setQuestions([...questions, newQuestion]);
    setSelectedQuestionIndex(questions.length);
    setSelectedCellKey(null);
    setShowAddModal(false);
  };

  // ====================== GRID HELPERS ======================
  const getSelectedQuestion = () => questions[selectedQuestionIndex] || null;

  const updateGridQuestion = (updater) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex] = updater(updated[selectedQuestionIndex]);
    setQuestions(updated);
  };

  const addRow = () => {
    updateGridQuestion(q => {
      const newId = `r${q.rows.length + 1}`;
      const newRow = { id: newId, label: `` };
      const newCells = { ...q.cells };
      q.columns.forEach(col => {
        newCells[`${newId}-${col.id}`] = { text: '', max: 0, enabled: true, used: 0 };
      });
      return { ...q, rows: [...q.rows, newRow], cells: newCells };
    });
  };

  const addColumn = () => {
    updateGridQuestion(q => {
      const newId = `c${q.columns.length + 1}`;
      const newCol = { id: newId, label: `` };
      const newCells = { ...q.cells };
      q.rows.forEach(row => {
        newCells[`${row.id}-${newId}`] = { text: '', max: 0, enabled: true, used: 0 };
      });
      return { ...q, columns: [...q.columns, newCol], cells: newCells };
    });
  };

  const removeRow = (rowIndex) => {
    updateGridQuestion(q => {
      const rowId = q.rows[rowIndex].id;
      const newRows = q.rows.filter((_, i) => i !== rowIndex);
      const newCells = { ...q.cells };
      Object.keys(newCells).forEach(k => {
        if (k.startsWith(`${rowId}-`)) delete newCells[k];
      });
      return { ...q, rows: newRows, cells: newCells };
    });
    setSelectedCellKey(null);
  };

  const removeColumn = (colIndex) => {
    updateGridQuestion(q => {
      const colId = q.columns[colIndex].id;
      const newCols = q.columns.filter((_, i) => i !== colIndex);
      const newCells = { ...q.cells };
      Object.keys(newCells).forEach(k => {
        if (k.endsWith(`-${colId}`)) delete newCells[k];
      });
      return { ...q, columns: newCols, cells: newCells };
    });
    setSelectedCellKey(null);
  };

  const updateRowLabel = (rowIndex, value) => {
    updateGridQuestion(q => {
      const newRows = [...q.rows];
      newRows[rowIndex].label = value;
      return { ...q, rows: newRows };
    });
  };

  const updateColumnLabel = (colIndex, value) => {
    updateGridQuestion(q => {
      const newCols = [...q.columns];
      newCols[colIndex].label = value;
      return { ...q, columns: newCols };
    });
  };

  const updateCell = (cellKey, field, value) => {
    updateGridQuestion(q => ({
      ...q,
      cells: { ...q.cells, [cellKey]: { ...q.cells[cellKey], [field]: value } }
    }));
  };

  // ====================== OTHER HELPERS ======================
  const updateQuestion = (field, value) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex][field] = value;
    setQuestions(updated);
  };

  const addOption = () => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options.push('');
    setQuestions(updated);
  };

  const updateOption = (optIndex, value) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options[optIndex] = value;
    setQuestions(updated);
  };

  const removeOption = (optIndex) => {
    if (selectedQuestionIndex === null) return;
    const updated = [...questions];
    updated[selectedQuestionIndex].options.splice(optIndex, 1);
    setQuestions(updated);
  };

  const removeQuestion = (index) => {
    setQuestions(questions.filter((_, i) => i !== index));
    if (selectedQuestionIndex === index) {
      setSelectedQuestionIndex(null);
      setSelectedCellKey(null);
    } else if (selectedQuestionIndex > index) {
      setSelectedQuestionIndex(selectedQuestionIndex - 1);
    }
  };

  const silentSave = async () => {
    if (!publicId) return;

    setIsSaving(true);
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title,
        description,
        isPublished: form.isPublished,
        schemaJson: { questions },
      }, { withCredentials: true });

      setLastSavedTime(new Date());
    } catch (err) {
      console.error('Auto-save failed:', err);
    }
    setIsSaving(false);
  };

  const handleSave = async (publish = false) => {
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title,
        description,
        isPublished: form.isPublished = true,
        schemaJson: { questions },
      }, { withCredentials: true });

      if (publish) navigate('/dashboard');
    } catch (err) {
      alert('Error saving');
    }
  };

  const handleSavebtn = async (publish = false) => {
    try {
      await api.put(`${import.meta.env.VITE_API_URL}/forms/${publicId}`, {
        title,
        description,
        isPublished: form.isPublished,
        schemaJson: { questions },
      }, { withCredentials: true });

      if (publish) navigate('/dashboard');
    } catch (err) {
      alert('Error saving');
    }
  };

  const handlePreview = () => navigate(`/preview/${publicId}`);

  const moveQuestion = (dragIndex, hoverIndex) => {
    const updated = [...questions];
    const [dragged] = updated.splice(dragIndex, 1);
    updated.splice(hoverIndex, 0, dragged);
    setQuestions(updated);
    if (selectedQuestionIndex === dragIndex) setSelectedQuestionIndex(hoverIndex);
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">{error}</p>;

  const selectedQuestion = getSelectedQuestion();
  const isGrid = selectedQuestion?.type === 'grid';

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="editor-container">
        <div className='top-bar-wrapper'>
          <div className="editor-top-bar">

            <div className="breadcrumb">
              <button 
                onClick={() => navigate('/dashboard')} 
                className="breadcrumb-link"
              >
                Dashboard
              </button>
              <span className="breadcrumb-separator">›</span>
              <span className="breadcrumb-current">
                 Edit
              </span>
            </div>

            <div className="tab-buttons">
              <button 
                onClick={() => setCurrentTab('edit')} 
                className={currentTab === 'edit' ? 'active-tab' : ''}
              >
                Edit
              </button>
              <button 
                onClick={() => setCurrentTab('settings')} 
                className={currentTab === 'settings' ? 'active-tab' : ''}
              >
                Form Settings
              </button>
              <button 
                onClick={() => setCurrentTab('deliver')} 
                className={currentTab === 'deliver' ? 'active-tab' : ''}
              >
                Deliver
              </button>
            </div>

            <div className="top-bar-right">
              <div class="btn-container">
                <button onClick={() => handleSavebtn(false)} className="save-draft-btn">
                  <span class="text-save">Save</span>
                  <span class="text-saved">Saved!</span>
                </button>
              </div>
            </div>

          </div>
        </div>

        <div className="editor-main">
          <div className="editor-left-sidebar">
            <div className='left-nav-button'>
              <h3
                style={{
                  fontSize: '1.08rem',
                  marginBottom: '1rem',
                  color: '#27469d',
                  fontWeight: '700' }}
              >
                Questions
              </h3>
              <button className='add-qustion-button' onClick={() => setShowAddModal(true)}>+ Add Question</button>
            </div>
            <hr />
            <div className="questions-list">
              {questions.map((q, index) => (
                <QuestionCard
                  key={q.id}
                  question={q}
                  index={index}
                  isSelected={index === selectedQuestionIndex}
                  onSelect={() => { setSelectedQuestionIndex(index); setSelectedCellKey(null); }}
                  moveQuestion={moveQuestion}
                  onDelete={() => removeQuestion(index)}
                />
              ))}
            </div>
          </div>

          <div className="editor-middle">
            {currentTab === 'edit' && (
              <div className="centered-content">
                {selectedQuestion ? (
                  <div className="modern-form">
                    <div className="question-number">{selectedQuestionIndex + 1} →</div>
                    <input
                      className="question-label"
                      value={selectedQuestion.label}
                      onChange={(e) => updateQuestion('label', e.target.value)}
                      placeholder="Your question here."
                    />
                    <input
                      className="question-description"
                      value={selectedQuestion.description || ''}
                      onChange={(e) => updateQuestion('description', e.target.value)}
                      placeholder="Description (optional)"
                    />

                    <div className="answer-area">
                    {isGrid ? (
                      <div className="matrix-grid-wrapper">
                        <table className="matrix-grid">
                          <thead>
                            <tr>
                              <th></th>
                              {selectedQuestion.columns.map((col, colIndex) => (
                                <th key={col.id}>
                                  <input
                                    className="header-input"
                                    value={col.label}
                                    onChange={(e) => updateColumnLabel(colIndex, e.target.value)}
                                    placeholder="Column label"
                                  />
                                  <button
                                    className="remove-header-btn"
                                    onClick={() => removeColumn(colIndex)}
                                  >×</button>
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {selectedQuestion.rows.map((row, rowIndex) => (
                              <tr key={row.id}>
                                <td className="row-label-cell">
                                  <input
                                    className="header-input"
                                    value={row.label}
                                    onChange={(e) => updateRowLabel(rowIndex, e.target.value)}
                                    placeholder="Row label"
                                  />
                                  <button
                                    className="remove-header-btn"
                                    onClick={() => removeRow(rowIndex)}
                                  >×</button>
                                </td>
                                {selectedQuestion.columns.map((col) => {
                                  const cellKey = `${row.id}-${col.id}`;
                                  const cell = selectedQuestion.cells[cellKey] || { text: '', max: 0, enabled: true };
                                  const isSelected = selectedCellKey === cellKey;

                                  return (
                                    <td
                                      key={col.id}
                                      className={`matrix-cell ${isSelected ? 'selected' : ''} ${!cell.enabled ? 'disabled' : ''}`}
                                      onClick={() => setSelectedCellKey(cellKey)}
                                    >
                                      <div className="cell-content">
                                        <textarea
                                          className="cell-text-input"
                                          value={cell.text}
                                          onChange={(e) => updateCell(cellKey, 'text', e.target.value)}
                                          placeholder=""
                                        />
                                        <div className="cell-controls">
                                          <div className="cell-max">
                                            Max: 
                                            <input
                                              type="number"
                                              min="0"
                                              className="cell-max-input"
                                              value={cell.max || ''}
                                              onChange={(e) => updateCell(cellKey, 'max', parseInt(e.target.value) || 0)}
                                              placeholder="∞"
                                            />
                                          </div>
                                          <label className="cell-toggle">
                                            <input
                                              type="checkbox"
                                              checked={cell.enabled}
                                              onChange={(e) => updateCell(cellKey, 'enabled', e.target.checked)}
                                            />
                                            Enabled
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

                        {/* + Row and + Column buttons now under the entire grid */}
                        <div className="grid-action-buttons">
                          <button className="add-header-btn" onClick={addRow}>+ Add Row</button>
                          <button className="add-header-btn" onClick={addColumn}>+ Add Column</button>
                        </div>
                      </div>
                    ) : (
                        <>
                          {selectedQuestion.type === 'short_text' && <input className="input-field" disabled placeholder="Type your answer here..." />}
                          {selectedQuestion.type === 'long_text' && <textarea className="input-field" disabled placeholder="Type your answer here..." />}
                          {selectedQuestion.type === 'number' && <input type="number" className="input-field" disabled placeholder="Enter a number..." />}
                          {selectedQuestion.type === 'date' && <input type="date" className="input-field" disabled />}
                          {selectedQuestion.type === 'time' && <input type="time" className="input-field" disabled />}
                          {selectedQuestion.type === 'email' && <input type="email" className="input-field" disabled placeholder="your@email.com" />}
                          {selectedQuestion.type === 'phone' && <input type="tel" className="input-field" disabled placeholder="+0 123 456 789" />}
                          {selectedQuestion.type === 'url' && <input type="url" className="input-field" disabled placeholder="www.example.com" />}
                          {selectedQuestion.type === 'rating' && <div className="preview-rating">★★★★★</div>}
                          {(selectedQuestion.type === 'radio') && (
                            <div className="choice-options-edit">
                              {selectedQuestion.options.map((opt, i) => (
                                <label key={i}>
                                  <input placeholder='option...' className='option-input' value={opt} onChange={(e) => updateOption(i, e.target.value)} />
                                  <button onClick={() => removeOption(i)} className="remove-option">×</button>
                                </label>
                              ))}
                              <button onClick={addOption} className="add-choice"><span style={{fontSize: '1.2em', marginRight: '7px'}}>+</span>Add option</button>
                            </div>
                          )}
                          {(selectedQuestion.type === 'yes_no') && (
                            <div className="choice-options-yes-no">
                              <button className='button-yes-no' disabled>Yes</button><button className='button-yes-no' disabled>No</button>
                            </div>
                          )}
                          {selectedQuestion.type === 'checkbox' && (
                            <div className="choice-options-edit">
                              {selectedQuestion.options.map((opt, i) => (
                                <label key={i}>
                                  <input placeholder='multiple option...' className='option-input' value={opt} onChange={(e) => updateOption(i, e.target.value)} />
                                  <button onClick={() => removeOption(i)} className="remove-option">×</button>
                                </label>
                              ))}
                              <button onClick={addOption} className="add-choice">+ Add choice</button>
                            </div>
                          )}
                          {selectedQuestion.type === 'select' && (
                            <div className="choice-options-edit">
                              {selectedQuestion.options.map((opt, i) => (
                                <label key={i}>
                                  <input placeholder='select option...' className='option-input' value={opt} onChange={(e) => updateOption(i, e.target.value)} />
                                  <button onClick={() => removeOption(i)} className="remove-option">×</button>
                                </label>
                              ))}
                              <button onClick={addOption} className="add-choice">+ Add choice</button>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                ) : (
                  <p>Select a question from the left to edit.</p>
                )}
              </div>
            )}

            {currentTab === 'settings' && (
              <div className="centered-content">
                <h2>Form Settings</h2>
                <label>Title:</label>
                <input value={title} onChange={(e) => setTitle(e.target.value)} />
                <label>Description:</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} />
              </div>
            )}

            {currentTab === 'deliver' && (
              <div className="centered-content">
                <h2>Deliver</h2>
                <button onClick={() => handleSave(true)}>Publish</button>
                <button onClick={handlePreview}>Preview</button>
              </div>
            )}
          </div>

          <div className="editor-right-sidebar">
            {currentTab === 'edit' && selectedQuestion && (
              <div>
                <h3
                  style={{
                    fontSize: '1.08rem',
                    marginBottom: '1rem',
                    color: '#27469d',
                    fontWeight: '700' }}
                >
                  Question settings
                </h3>
                <hr />
                <label>Required:</label>
                <input
                  type="checkbox"
                  checked={selectedQuestion.required}
                  onChange={(e) => updateQuestion('required', e.target.checked)}
                />

                {isGrid && (
                  <>
                    <label>One selection per row only</label>
                    <input
                      type="checkbox"
                      checked={selectedQuestion.singlePerRow || false}
                      onChange={(e) => updateQuestion('singlePerRow', e.target.checked)}
                    />

                    <label>One selection per column only</label>
                    <input
                      type="checkbox"
                      checked={selectedQuestion.singlePerColumn || false}
                      onChange={(e) => updateQuestion('singlePerColumn', e.target.checked)}
                    />
                  </>
                )}

                {!isGrid && (
                  <>
                    <label>Max Available Responses (0 = unlimited):</label>
                    <input
                      type="number"
                      min="0"
                      value={selectedQuestion.maxResponses || 0}
                      onChange={(e) => updateQuestion('maxResponses', parseInt(e.target.value))}
                    />
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ width: '620px' }}>
            <h3>Select Question Type</h3>
            <div className="type-cards">
              {questionTypes.map((qt) => (
                <div key={qt.type} className="type-card" onClick={() => addQuestion(qt.type)}>
                  {qt.label}
                </div>
              ))}
            </div>
            <button className='add-qustion-button-cancel' onClick={() => setShowAddModal(false)}>Cancel</button>
          </div>
        </div>
      )}
    </DndProvider>
  );
}

function QuestionCard({ question, index, isSelected, onSelect, moveQuestion, onDelete }) {
  const [, drop] = useDrop({
    accept: ITEM_TYPE,
    hover: (item) => {
      if (item.index !== index) {
        moveQuestion(item.index, index);
        item.index = index;
      }
    },
  });
  const [{ isDragging }, drag] = useDrag({
    type: ITEM_TYPE,
    item: { index },
    collect: (monitor) => ({ isDragging: monitor.isDragging() }),
  });
  return (
    <div
      ref={(node) => drag(drop(node))}
      onClick={onSelect}
      style={{
        opacity: isDragging ? 0.5 : 1,
        cursor: 'move',
        background: isSelected ? '#4f7fff' : '#e3ebfc',
        color: isSelected ? '#fff' : '#234',
        padding: '0.75rem',
        marginBottom: '0.5rem',
        borderRadius: '8px',
        border: 'none',
        position: 'relative',
      }}
    >
      {question.label || 'Untitled Question'}
      <button
        onClick={(e) => { e.stopPropagation(); onDelete(); }}
        style={{
          position: 'absolute',
          right: '8px',
          top: '8px',
          background: 'none',
          border: 'none',
          color: isSelected ? '#fff' : '#234',
          fontSize: '1.3rem',
          cursor: 'pointer' }}
      >
        ×
      </button>
    </div>
  );
}

export default Edit;