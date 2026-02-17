import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

function Login() {
  const { register, handleSubmit, formState: { errors } } = useForm({ resolver: zodResolver(schema) });
  const navigate = useNavigate();

  const onSubmit = async (data) => {
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/auth/login`, data, { withCredentials: true });
      navigate('/');
    } catch (error) {
      alert(error.response?.data?.error || 'Error');
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="card p-4">
      <h2>Login</h2>
      <div className="mb-3">
        <input type="email" className="form-control" placeholder="Email" {...register('email')} />
        {errors.email && <p className="text-danger">{errors.email.message}</p>}
      </div>
      <div className="mb-3">
        <input type="password" className="form-control" placeholder="Password" {...register('password')} />
        {errors.password && <p className="text-danger">{errors.password.message}</p>}
      </div>
      <button type="submit" className="btn btn-primary">Login</button>
    </form>
  );
}

export default Login;