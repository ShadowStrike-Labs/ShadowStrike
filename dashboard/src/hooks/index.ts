/* ============================================================================
 * ShadowStrike Phantom Dashboard — Custom Hooks
 * ============================================================================ */

import { useState, useEffect, useRef, useCallback } from 'react';
import { connectEventStream, ApiError } from '@/api/client';

// ============================================================================
// usePolling — Fetch data on interval with error/loading state
// ============================================================================

interface UsePollingResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refetch: () => void;
}

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number = 5000,
): UsePollingResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mountedRef = useRef(true);

  const doFetch = useCallback(async () => {
    try {
      const result = await fetcher();
      if (mountedRef.current) {
        setData(result);
        setError(null);
      }
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof ApiError ? e.message : 'Connection failed');
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [fetcher]);

  useEffect(() => {
    mountedRef.current = true;
    void doFetch();

    const timer = setInterval(() => void doFetch(), intervalMs);

    return () => {
      mountedRef.current = false;
      clearInterval(timer);
    };
  }, [doFetch, intervalMs]);

  return { data, error, loading, refetch: doFetch };
}

// ============================================================================
// useSSE — Server-Sent Events subscription
// ============================================================================

interface UseSSEResult {
  lastEvent: { type: string; data: unknown } | null;
  connected: boolean;
}

export function useSSE(): UseSSEResult {
  const [lastEvent, setLastEvent] = useState<{ type: string; data: unknown } | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const source = connectEventStream(
      (event) => {
        setLastEvent(event);
        setConnected(true);
      },
      () => {
        setConnected(false);
      },
    );

    source.onopen = () => setConnected(true);

    return () => {
      source.close();
      setConnected(false);
    };
  }, []);

  return { lastEvent, connected };
}

// ============================================================================
// useDebounce — Debounce a value
// ============================================================================

export function useDebounce<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}

// ============================================================================
// useLocalStorage — Persist state in localStorage
// ============================================================================

export function useLocalStorage<T>(
  key: string,
  initialValue: T,
): [T, (value: T | ((prev: T) => T)) => void] {
  const [stored, setStored] = useState<T>(() => {
    try {
      const item = localStorage.getItem(key);
      return item ? (JSON.parse(item) as T) : initialValue;
    } catch {
      return initialValue;
    }
  });

  const setValue = useCallback(
    (value: T | ((prev: T) => T)) => {
      setStored((prev) => {
        const next = value instanceof Function ? value(prev) : value;
        try {
          localStorage.setItem(key, JSON.stringify(next));
        } catch {
          // Storage full or unavailable
        }
        return next;
      });
    },
    [key],
  );

  return [stored, setValue];
}
