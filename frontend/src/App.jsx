import { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Dashboard from './pages/Dashboard';
import Edit from './pages/Edit';
import Preview from './pages/Preview';
import PublicForm from './pages/PublicForm';
import NavBar from './components/NavBar';
import Stats from './pages/Stats';

function AppContent() {
  const location = useLocation();
  const navigate = useNavigate();
  const showNavBar = location.pathname === '/dashboard';

  useEffect(() => {
    if (location.pathname === '/login') {
      localStorage.removeItem('redirectAfterLogin');
    }
  }, [location.pathname]);

  return (
    <div style={{ display: 'flex' }}>
      {showNavBar && <NavBar />}
      <div style={{ flex: 1, marginLeft: showNavBar ? '232px' : '0' }}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/edit/:publicId" element={<Edit />} />
          <Route path="/preview/:publicId" element={<Preview />} />
          <Route path="/f/:publicId" element={<PublicForm />} />
          <Route path="/stats/:publicId" element={<Stats />} />
        </Routes>
      </div>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;