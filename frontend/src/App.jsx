import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
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

function AppContent() {
  const location = useLocation();
  const showNavBar = location.pathname === '/dashboard';

  return (
    <div style={{ display: 'flex' }}>
      {showNavBar && <NavBar />}
      <div style={{ flex: 1, marginLeft: showNavBar ? '200px' : '0' }}>
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