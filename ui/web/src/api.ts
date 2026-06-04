// Thin client for the BFF JSON API.
export async function get<T = any>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export interface AuditEvent {
  ts: number; // unix ns
  event?: string;
  status?: string;
  peer?: string;
  user?: string;
  session?: number | string;
  reason?: string;
  data?: string;
  [k: string]: any;
}

export interface FlowSession {
  session: string;
  started: number;
  count: number;
  events: AuditEvent[];
}

export interface Alert {
  severity: "critical" | "warning" | "info";
  title: string;
  detail: string;
  at: number;
}

export interface AuthConfig {
  auth_source: "icam" | "ldap" | "local";
  icam?: {
    endpoint: string;
    client_id: string;
    groups_claim: string;
    reachable: boolean | null;
  };
  ldap?: {
    url: string;
  };
}

export const fmtTs = (ns: number) => new Date(ns / 1e6).toLocaleString();
export const nadIp = (peer?: string) =>
  peer ? peer.replace(/^\[/, "").replace(/\]:\d+$/, "").replace(/^::ffff:/, "") : "";
