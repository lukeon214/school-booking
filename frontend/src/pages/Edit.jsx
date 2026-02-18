import { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

function Edit() {
  const { id } = useParams();
  const [form, setForm] = useState(null);
  const [questions, setQuestions] = useState([]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
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

  const addQuestion = () => {
    const newId = 'q' + (questions.length + 1);
    setQuestions([...questions, { id: newId, label: '', type: 'text', required: false, options: [] }]);
  };

  const updateQuestion = (index, field, value) => {
    const updated = [...questions];
    updated[index][field] = value;
    setQuestions(updated);
  };

  const removeQuestion = (index) => {
    setQuestions(questions.filter((_, i) => i !== index));
  };

  const moveQuestion = (index, direction) => {
    const updated = [...questions];
    const [moved] = updated.splice(index, 1);
    updated.splice(index + direction, 0, moved);
    setQuestions(updated);
  };

  const handleSave = async () => {
    try {
      await axios.put(`${import.meta.env.VITE_API_URL}/forms/${id}`, {
        title,
        description,
        schemaJson: { questions },
      }, { withCredentials: true });
      alert('Saved!');
      navigate('/dashboard');
    } catch (err) {
      alert('Error saving');
    }
  };

  const handlePreview = () => {
    navigate(`/preview/${id}`);
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div className="edit-page">
      <h1>Edit Form</h1>
      <label>Title: </label>
      <input value={title} onChange={(e) => setTitle(e.target.value)} />
      <br />
      <label>Description: </label>
      <textarea value={description} onChange={(e) => setDescription(e.target.value)} />
      <br />
      <h2>Questions</h2>
      <table className="edit-table">
        <thead>
          <tr>
            <th>Label</th>
            <th>Type</th>
            <th>Required</th>
            <th>Options (comma separated)</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {questions.map((q, index) => (
            <tr key={q.id}>
              <td>
                <input
                  value={q.label}
                  onChange={(e) => updateQuestion(index, 'label', e.target.value)}
                />
              </td>
              <td>
                <select
                  value={q.type}
                  onChange={(e) => updateQuestion(index, 'type', e.target.value)}
                >
                  <option value="text">Text</option>
                  <option value="checkbox">Checkbox</option>
                  <option value="radio">Radio</option>
                  <option value="select">Select</option>
                  <option value="rating">Rating (1-5)</option>
                </select>
              </td>
              <td>
                <input
                  type="checkbox"
                  checked={q.required}
                  onChange={(e) => updateQuestion(index, 'required', e.target.checked)}
                />
              </td>
              <td>
                <input
                  value={(q.options || []).join(', ')}
                  onChange={(e) => updateQuestion(index, 'options', e.target.value.split(',').map(o => o.trim()))}
                  disabled={q.type === 'text' || q.type === 'rating'}
                />
              </td>
              <td>
                <button onClick={() => moveQuestion(index, -1)} disabled={index === 0}>Up</button>
                <button onClick={() => moveQuestion(index, 1)} disabled={index === questions.length - 1}>Down</button>
                <button onClick={() => removeQuestion(index)}>Remove</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button onClick={addQuestion}>Add Question</button>
      <button onClick={handleSave}>Save</button>
      <button onClick={handlePreview}>Preview</button>
      <button onClick={() => navigate('/dashboard')}>Back</button>
    </div>
  );
}

export default Edit;