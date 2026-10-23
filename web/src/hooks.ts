import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type ApiError } from './api.ts';

export interface ApiState<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  refresh: () => void;
}

/**
 * Fetches JSON from the API. Stale data is kept visible when a refresh fails, and optional polling
 * is used where the view is expected to update on its own (overview, scan activity).
 */
export function useApi<T>(path: string | null, options: { intervalMs?: number } = {}): ApiState<T> {
  const [state, setState] = useState<{ data: T | null; error: ApiError | null; loading: boolean }>({
    data: null,
    error: null,
    loading: Boolean(path),
  });
  const [revision, setRevision] = useState(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (!path) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    let cancelled = false;
    setState((previous) => ({ ...previous, loading: true }));
    api
      .get<T>(path)
      .then((data) => {
        if (!cancelled) setState({ data, error: null, loading: false });
      })
      .catch((error: ApiError) => {
        if (!cancelled) setState((previous) => ({ ...previous, error, loading: false }));
      });
    return () => {
      cancelled = true;
    };
    // options.enabled is intentionally part of the dependency list; callers pass simple values.
  }, [path, revision]);

  useEffect(() => {
    if (!options.intervalMs) return;
    const timer = setInterval(() => setRevision((value) => value + 1), options.intervalMs);
    return () => clearInterval(timer);
  }, [options.intervalMs]);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  return { ...state, refresh };
}

export function useDebounced<T>(value: T, delayMs = 250): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}


export type Route = {
  path: string;
  params: URLSearchParams;
};

export function parseRoute(): Route {
  const url = new URL(window.location.href);
  return { path: url.pathname.replace(/\/+$/, '') || '/', params: url.searchParams };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(parseRoute);
  useEffect(() => {
    const onChange = (): void => setRoute(parseRoute());
    window.addEventListener('popstate', onChange);
    return () => window.removeEventListener('popstate', onChange);
  }, []);
  return route;
}

export function navigate(path: string): void {
  window.history.pushState(null, '', path);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo({ top: 0 });
}
