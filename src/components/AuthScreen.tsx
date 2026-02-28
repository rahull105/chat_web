import { useState, type FormEvent } from 'react';
import { Mail, Lock, User as UserIcon, MessageCircleMore } from 'lucide-react';

import { useAuth } from '../context/useAuth';

export function AuthScreen() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(name, email, password);
      }
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Unable to continue.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-layout">
      <section className="auth-hero">
        <span className="badge">Real-time messaging</span>
        <h1>ChatWave</h1>
        <p>
          A WhatsApp-inspired chat experience with private messages, group conversations, read receipts,
          media sharing, typing status, and online presence.
        </p>
        <div className="auth-hero-card">
          <MessageCircleMore size={28} />
          <div>
            <h2>Stay connected</h2>
            <p>Fast, responsive and fully functional on desktop and mobile.</p>
          </div>
        </div>
      </section>

      <section className="auth-panel">
        <form className="auth-form" onSubmit={handleSubmit}>
          <h2>{mode === 'login' ? 'Welcome back' : 'Create account'}</h2>
          <p>Use your email to access the chat platform.</p>

          {mode === 'signup' ? (
            <label>
              <span>Full name</span>
              <div className="field">
                <UserIcon size={17} />
                <input
                  type="text"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Your display name"
                  required
                  minLength={2}
                  maxLength={30}
                />
              </div>
            </label>
          ) : null}

          <label>
            <span>Email</span>
            <div className="field">
              <Mail size={17} />
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@example.com"
                required
              />
            </div>
          </label>

          <label>
            <span>Password</span>
            <div className="field">
              <Lock size={17} />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Minimum 6 characters"
                required
                minLength={6}
              />
            </div>
          </label>

          {error ? <p className="error-text">{error}</p> : null}

          <button className="primary-btn" type="submit" disabled={busy}>
            {busy ? 'Please wait...' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>

          <button
            className="ghost-btn"
            type="button"
            onClick={() => {
              setMode((current) => (current === 'login' ? 'signup' : 'login'));
              setError(null);
            }}
          >
            {mode === 'login' ? 'Need an account? Register' : 'Already have an account? Login'}
          </button>
        </form>
      </section>
    </main>
  );
}
