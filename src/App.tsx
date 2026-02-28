import { useEffect, useState } from 'react';

import { AuthScreen } from './components/AuthScreen';
import { ChatScreen } from './components/ChatScreen';
import { AuthProvider } from './context/AuthContext';
import { useAuth } from './context/useAuth';

function AppGate() {
  const { user, loading } = useAuth();
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('chatrix-theme');
    return saved === 'dark' ? 'dark' : 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('chatrix-theme', theme);
  }, [theme]);

  function toggleTheme() {
    setTheme((current) => (current === 'light' ? 'dark' : 'light'));
  }

  if (loading) {
    return (
      <main className="loading-screen">
        <div className="loading-spinner" />
        <p>Loading chatrix...</p>
      </main>
    );
  }

  return user ? (
    <ChatScreen theme={theme} onToggleTheme={toggleTheme} />
  ) : (
    <AuthScreen theme={theme} onToggleTheme={toggleTheme} />
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppGate />
    </AuthProvider>
  );
}
