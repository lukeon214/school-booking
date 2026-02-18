import { Link } from 'react-router-dom';

function Home() {
  return (
    <div>
      <h1>Welcome</h1>
      <p>Go to login or register.</p>
      <Link to="/login">Login</Link> | <Link to="/register">Register</Link>
    </div>
  );
}

export default Home;