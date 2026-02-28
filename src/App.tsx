import { AuthScreen } from './components/AuthScreen';
import { ChatScreen } from './components/ChatScreen';
import { AuthProvider } from './context/AuthContext';
import { useAuth } from './context/useAuth';

function AppGate() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <main className="loading-screen">
        <div className="loading-spinner" />
        <p>Loading ChatWave...</p>
      </main>
    );
  }

  return user ? <ChatScreen /> : <AuthScreen />;
}

export default function App() {
  return (
    <AuthProvider>
      <AppGate />
    </AuthProvider>
  );
}
