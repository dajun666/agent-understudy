// Talking to an engine's control API (token from ~/.agent-understudy/api.token).
import type { Config } from './config.ts';
import { apiToken } from './core/api-token.ts';
import { engineFor } from './engine.ts';

/**
 * Which engine: the one named in AGENT_UNDERSTUDY_GATEWAY (`understudy run` sets it), else the one the parent
 * agent started (the Claude Code mod's session engine, found by our shared parent), else `understudy up`.
 */
export function gatewayBase(config: Config): string {
  return (process.env.AGENT_UNDERSTUDY_GATEWAY ?? engineFor(config.home, process.ppid) ?? `http://127.0.0.1:${config.port}`).replace(/\/+$/, '');
}

export function gatewayClient(config: Config) {
  const base = gatewayBase(config);
  return {
    base,
    async post<T = any>(path: string, body: unknown, timeoutMs = 30_000): Promise<T> {
      let r: Response;
      try {
        r = await fetch(base + path, {
          method: 'POST', signal: AbortSignal.timeout(timeoutMs),
          headers: { 'content-type': 'application/json', authorization: `Bearer ${apiToken(config.home)}` },
          body: JSON.stringify(body),
        });
      } catch { throw new Error(`no agent-understudy engine reachable at ${base} (launch the agent with \`understudy run\`, or load the plugin)`); }
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `gateway ${r.status}`);
      return j as T;
    },
  };
}
