import { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

function Preview() {
  const { id } = useParams();
  const [form, setForm] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_URL}/forms/${id}`, { withCredentials: true })
      .then(res => {
        setForm(res.data);
        setLoading(false);
      })
      .catch(() => {
        alert('Error');
        navigate('/dashboard');
      });
  }, [id, navigate]);

  if (loading) return <p>Loading...</p>;

  return (
    <div style={{ padding: '2rem' }}>
      <h1 style={{ color: '#5c8df6' }}>{form.title}</h1>
      <p>{form.description}</p>
      {form.schemaJson.questions.map(q => (
        <div key={q.id} style={{ marginBottom: '1rem' }}>
          <label style={{ color: '#5c8df6' }}>{q.label} {q.required ? '*' : ''}</label>
          <br />
          {q.type === 'text' && <input style={{ border: '1px solid #5c8df6', borderRadius: '8px', padding: '0.5rem', backgroundColor: '#f0f6ff', width: '100%' }} placeholder="Enter your answer here..." />}
          {q.type === 'number' && <input type="number" style={{ border: '1px solid #5c8df6', borderRadius: '8px', padding: '0.5rem', backgroundColor: '#f0f6ff', width: '100%' }} placeholder="Enter a number..." />}
          {q.type === 'radio' && q.options.map(opt => (
            <label key={opt} style={{ marginRight: '1rem' }}>
              <input type="radio" name={q.id} /> {opt}
            </label>
          ))}
          {q.type === 'checkbox' && q.options.map(opt => (
            <label key={opt} style={{ marginRight: '1rem' }}>
              <input type="checkbox" /> {opt}
            </label>
          ))}
          {q.type === 'select' && <select style={{ border: '1px solid #5c8df6', borderRadius: '8px', padding: '0.5rem', backgroundColor: '#f0f6ff', width: '100%' }}>{q.options.map(opt => <option key={opt}>{opt}</option>)}</select>}
          {q.type === 'rating' && [1,2,3,4,5].map(n => <span key={n} style={{ color: n <= 3 ? '#ffd700' : '#ccc', fontSize: '1.5rem' }}>★</span>)}
          {q.type === 'table' && ( // Stub for table question - will expand later
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th></th>
                  {q.columns.map(col => <th key={col}>{col}</th>)}
                </tr>
              </thead>
              <tbody>
                {q.rows.map((row, rIdx) => (
                  <tr key={rIdx}>
                    <td>{row}</td>
                    {q.columns.map((col, cIdx) => (
                      <td key={cIdx} style={{ textAlign: 'center' }}>
                        <input type="text" style={{ border: 'none', background: 'transparent' }} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
      <button style={{ backgroundColor: '#5c8df6', color: 'white', padding: '1rem', borderRadius: '20px', width: '100%', border: 'none', cursor: 'pointer' }}>Submit</button>
      <button onClick={() => navigate(`/edit/${id}`)}>Back to Edit</button>
    </div>
  );
}

export default Preview;