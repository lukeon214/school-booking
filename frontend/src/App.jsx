import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Dashboard from './pages/Dashboard';
import Edit from './pages/Edit';
import Preview from './pages/Preview';
import NavBar from './components/NavBar';

function AppContent() {
  const location = useLocation();
  const showNavBar = location.pathname.startsWith('/dashboard') || location.pathname.startsWith('/edit') || location.pathname.startsWith('/preview');

  return (
    <div style={{ display: 'flex' }}>
      {showNavBar && <NavBar />}
      <div style={{ flex: 1, marginLeft: showNavBar ? '200px' : '0' }}> {/* Offset content */}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/edit/:id" element={<Edit />} />
          <Route path="/preview/:id" element={<Preview />} />
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