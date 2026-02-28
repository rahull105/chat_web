/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import { api, setAuthToken } from '../lib/api';
import { disconnectSocket } from '../lib/socket';
import type { User } from '../types';

export interface AuthContextValue {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  updateProfile: (name: string, about: string) => Promise<void>;
  uploadAvatar: (file: File) => Promise<void>;
  removeAvatar: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
const TOKEN_KEY = 'chatwave-token';

function withMessage(error: unknown) {
  if (typeof error === 'object' && error && 'response' in error) {
    const response = (error as { response?: { data?: { message?: string } } }).response;
    if (response?.data?.message) {
      return response.data.message;
    }
  }

  return error instanceof Error ? error.message : 'Request failed.';
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [loading, setLoading] = useState(true);

  const persistToken = useCallback((nextToken: string | null) => {
    setToken(nextToken);
    setAuthToken(nextToken);

    if (nextToken) {
      localStorage.setItem(TOKEN_KEY, nextToken);
      return;
    }

    localStorage.removeItem(TOKEN_KEY);
  }, []);

  const hydrate = useCallback(async () => {
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      setAuthToken(token);
      const { data } = await api.get<{ user: User }>('/auth/me');
      setUser(data.user);
    } catch {
      persistToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [persistToken, token]);

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  const login = useCallback(
    async (email: string, password: string) => {
      try {
        const { data } = await api.post<{ token: string; user: User }>('/auth/login', {
          email,
          password,
        });
        persistToken(data.token);
        setUser(data.user);
      } catch (error) {
        throw new Error(withMessage(error));
      }
    },
    [persistToken],
  );

  const register = useCallback(
    async (name: string, email: string, password: string) => {
      try {
        const { data } = await api.post<{ token: string; user: User }>('/auth/register', {
          name,
          email,
          password,
        });
        persistToken(data.token);
        setUser(data.user);
      } catch (error) {
        throw new Error(withMessage(error));
      }
    },
    [persistToken],
  );

  const logout = useCallback(() => {
    disconnectSocket();
    persistToken(null);
    setUser(null);
    setLoading(false);
  }, [persistToken]);

  const updateProfile = useCallback(async (name: string, about: string) => {
    try {
      const { data } = await api.patch<{ user: User }>('/auth/me', {
        name,
        about,
      });
      setUser(data.user);
    } catch (error) {
      throw new Error(withMessage(error));
    }
  }, []);

  const uploadAvatar = useCallback(async (file: File) => {
    try {
      const payload = new FormData();
      payload.append('avatar', file);
      const { data } = await api.patch<{ user: User }>('/auth/me/avatar', payload, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setUser(data.user);
    } catch (error) {
      throw new Error(withMessage(error));
    }
  }, []);

  const removeAvatar = useCallback(async () => {
    try {
      const { data } = await api.delete<{ user: User }>('/auth/me/avatar');
      setUser(data.user);
    } catch (error) {
      throw new Error(withMessage(error));
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      loading,
      login,
      register,
      logout,
      updateProfile,
      uploadAvatar,
      removeAvatar,
    }),
    [loading, login, logout, register, token, updateProfile, uploadAvatar, removeAvatar, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
