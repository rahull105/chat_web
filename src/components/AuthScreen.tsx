import { useState, type FormEvent } from 'react';
import { Mail, Lock, User as UserIcon, MessageCircleMore, Shield, Sparkles } from 'lucide-react';

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
      <section className="auth-visual" aria-hidden="true">
        <span className="auth-orb orb-one" />
        <span className="auth-orb orb-two" />
        <span className="auth-orb orb-three" />
        <span className="auth-grid-glow" />
        <div className="auth-widget widget-mail">
          <Mail size={18} />
        </div>
        <div className="auth-widget widget-lock">
          <Shield size={18} />
        </div>
        <div className="auth-widget widget-spark">
          <Sparkles size={18} />
        </div>
      </section>
      <section className="auth-panel">
        <form className="auth-form auth-minimal" onSubmit={handleSubmit}>
          <span className="auth-mark" aria-hidden="true">
            <MessageCircleMore size={20} />
          </span>
          <div className="auth-mode-toggle" role="tablist" aria-label="Authentication mode">
            <button
              className={`mode-btn ${mode === 'login' ? 'active' : ''}`}
              type="button"
              aria-label="Login mode"
              aria-selected={mode === 'login'}
              onClick={() => {
                setMode('login');
                setError(null);
              }}
            >
              <Lock size={15} />
            </button>
            <button
              className={`mode-btn ${mode === 'signup' ? 'active' : ''}`}
              type="button"
              aria-label="Register mode"
              aria-selected={mode === 'signup'}
              onClick={() => {
                setMode('signup');
                setError(null);
              }}
            >
              <UserIcon size={15} />
            </button>
          </div>
          {mode === 'signup' ? (
            <div className="field compact-field">
              <UserIcon size={17} />
              <input
                type="text"
                value={name}
                onChange={(event) => setName(event.target.value)}
                aria-label="Full name"
                required
                minLength={2}
                maxLength={30}
              />
            </div>
          ) : null}
          <div className="field compact-field">
            <Mail size={17} />
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              aria-label="Email"
              required
            />
          </div>
          <div className="field compact-field">
            <Lock size={17} />
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-label="Password"
              required
              minLength={6}
            />
          </div>

          {error ? <p className="error-text">{error}</p> : null}

          <button
            className="primary-btn auth-submit"
            type="submit"
            disabled={busy}
            aria-label={mode === 'login' ? 'Sign in' : 'Create account'}
          >
            {busy ? (
              <span className="btn-loader" aria-hidden="true" />
            ) : mode === 'login' ? (
              <Lock size={16} />
            ) : (
              <UserIcon size={16} />
            )}
          </button>
        </form>
      </section>
    </main>
  );
}
