import { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import { DndProvider, useDrag, useDrop } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';

const ITEM_TYPE = 'question';

function Edit() {
  const { id } = useParams();
  const [form, setForm] = useState(null);
  const [questions, setQuestions] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [selectedQuestionIndex, setSelectedQuestionIndex] = useState(null);
  const [currentTab, setCurrentTab] = useState('edit');
  const [showAddModal, setShowAddModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/forms/${id}`, { withCredentials: true })
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
  }, [id]);

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
    { type: 'grid', label: 'Grid' },
  ];

  const addQuestion = (type) => {
    const newId = 'q' + (questions.length + 1);
    const newQuestion = {
      id: newId,
      label: '',
      description: '',
      type,
      required: false,
      maxResponses: 0,
      options: type === 'yes_no' ? ['Yes', 'No'] : type === 'radio' || type === 'checkbox' || type === 'select' ? ['Option 1', 'Option 2'] : [],
    };
    setQuestions([...questions, newQuestion]);
    setSelectedQuestionIndex(questions.length);
    setShowAddModal(false);
  };

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
    if (selectedQuestionIndex === index) setSelectedQuestionIndex(null);
    else if (selectedQuestionIndex > index) setSelectedQuestionIndex(selectedQuestionIndex - 1);
  };

  const handleSave = async (publish = false) => {
    try {
      await axios.put(`${import.meta.env.VITE_API_URL}/forms/${id}`, {
        title,
        description,
        isPublished: publish ? true : form.isPublished,
        schemaJson: { questions },
      }, { withCredentials: true });
      alert('Saved!');
      if (publish) alert('Published!');
      navigate('/dashboard');
    } catch (err) {
      alert('Error saving');
    }
  };

  const handlePreview = () => navigate(`/preview/${id}`);

  const moveQuestion = (dragIndex, hoverIndex) => {
    const updated = [...questions];
    const [dragged] = updated.splice(dragIndex, 1);
    updated.splice(hoverIndex, 0, dragged);
    setQuestions(updated);
    if (selectedQuestionIndex === dragIndex) setSelectedQuestionIndex(hoverIndex);
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">{error}</p>;

  const selectedQuestion = selectedQuestionIndex !== null ? questions[selectedQuestionIndex] : null;

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="editor-container">
        <div className='top-bar-wrapper'>
          <div className="editor-top-bar">
            <div className="tab-buttons">
              <button onClick={() => setCurrentTab('edit')} className={currentTab === 'edit' ? 'active-tab' : ''}>Edit</button>
              <button onClick={() => setCurrentTab('settings')} className={currentTab === 'settings' ? 'active-tab' : ''}>Form Settings</button>
              <button onClick={() => setCurrentTab('deliver')} className={currentTab === 'deliver' ? 'active-tab' : ''}>Deliver</button>
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
            <hr></hr>
            <div className="questions-list">
              {questions.map((q, index) => (
                <QuestionCard
                  key={q.id}
                  question={q}
                  index={index}
                  isSelected={index === selectedQuestionIndex}
                  onSelect={() => setSelectedQuestionIndex(index)}
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
                      {selectedQuestion.type === 'short_text' && <input className="input-field" disabled placeholder="Type your answer here..." />}
                      {selectedQuestion.type === 'long_text' && <textarea className="input-field" disabled placeholder="Type your answer here..." />}
                      {selectedQuestion.type === 'number' && <input type="number" className="input-field" disabled placeholder="Enter a number..." />}
                      {selectedQuestion.type === 'date' && <input type="date" className="input-field" disabled />}
                      {selectedQuestion.type === 'time' && <input type="time" className="input-field" disabled />}
                      {selectedQuestion.type === 'email' && <input type="email" className="input-field" disabled placeholder="your@email.com" />}
                      {selectedQuestion.type === 'phone' && <input type="tel" className="input-field" disabled placeholder="+0 123 456 789" />}
                      {selectedQuestion.type === 'url' && <input type="url" className="input-field" disabled placeholder="https://example.com" />}
                      {selectedQuestion.type === 'rating' && <div className="preview-rating">★★★★★</div>}

                      {(selectedQuestion.type === 'radio' || selectedQuestion.type === 'yes_no') && (
                        <div className="choice-options">
                          {selectedQuestion.options.map((opt, i) => (
                            <label key={i}>
                              <input placeholder='option...' className='option-input' value={opt} onChange={(e) => updateOption(i, e.target.value)} />
                              <button onClick={() => removeOption(i)} className="remove-option">×</button>
                            </label>
                          ))}
                          <button onClick={addOption} className="add-choice"><span style={{fontSize: '1.2em', marginRight: '7px'}}>+</span>Add option</button>
                        </div>
                      )}

                      {selectedQuestion.type === 'checkbox' && (
                        <div className="choice-options">
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
                        <div className="choice-options">
                          {selectedQuestion.options.map((opt, i) => (
                            <label key={i}>
                              <input placeholder='select option...' className='option-input' value={opt} onChange={(e) => updateOption(i, e.target.value)} />
                              <button onClick={() => removeOption(i)} className="remove-option">×</button>
                            </label>
                          ))}
                          <button onClick={addOption} className="add-choice">+ Add choice</button>
                        </div>
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
                <h3>Question Settings</h3>
                <label>Required:</label>
                <input type="checkbox" checked={selectedQuestion.required} onChange={(e) => updateQuestion('required', e.target.checked)} />
                <label>Max Available Responses (0 = unlimited):</label>
                <input type="number" min="0" value={selectedQuestion.maxResponses || 0} onChange={(e) => updateQuestion('maxResponses', parseInt(e.target.value))} />
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
            <button onClick={() => setShowAddModal(false)}>Cancel</button>
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