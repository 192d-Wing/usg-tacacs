import { useEffect, useRef, useState } from "react";
import {
  Container,
  Header,
  Table,
  Box,
  Badge,
  Button,
  Spinner,
  Alert,
  StatusIndicator,
} from "@cloudscape-design/components";
import { get } from "../api";

interface Session {
  id: number;
  peer: string;
  user: string | null;
  session_id: number | null;
  connected_at: number;
  last_active: number;
  idle_secs: number;
  requests: number;
}

interface SessionsResponse {
  count: number;
  sessions: Session[];
}

const POLL_INTERVAL_MS = 5000;

function idleLabel(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function idleStatus(secs: number): "success" | "warning" | "error" {
  if (secs < 60) return "success";
  if (secs < 300) return "warning";
  return "error";
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [count, setCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string>("");
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = () => {
    setLoading(true);
    get<SessionsResponse>("/api/sessions")
      .then((data) => {
        setSessions(data.sessions ?? []);
        setCount(data.count ?? 0);
        setLastUpdated(new Date().toLocaleTimeString());
        setError(null);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    timerRef.current = setInterval(load, POLL_INTERVAL_MS);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  const columns = [
    {
      id: "peer",
      header: "Peer",
      cell: (s: Session) => <code style={{ fontSize: "0.85em" }}>{s.peer}</code>,
    },
    {
      id: "user",
      header: "User",
      cell: (s: Session) =>
        s.user ? (
          <Badge color="blue">{s.user}</Badge>
        ) : (
          <Box color="text-body-secondary">—</Box>
        ),
    },
    {
      id: "session_id",
      header: "Session ID",
      cell: (s: Session) =>
        s.session_id != null ? (
          <code style={{ fontSize: "0.85em" }}>{s.session_id}</code>
        ) : (
          <Box color="text-body-secondary">—</Box>
        ),
    },
    {
      id: "idle",
      header: "Idle",
      cell: (s: Session) => (
        <StatusIndicator type={idleStatus(s.idle_secs)}>
          {idleLabel(s.idle_secs)}
        </StatusIndicator>
      ),
    },
    {
      id: "requests",
      header: "Requests",
      cell: (s: Session) => s.requests,
    },
  ];

  return (
    <Container
      header={
        <Header
          variant="h2"
          counter={loading ? undefined : `(${count})`}
          actions={
            <Button iconName="refresh" onClick={load} disabled={loading} />
          }
          description={
            lastUpdated
              ? `Auto-refreshes every ${POLL_INTERVAL_MS / 1000}s · Last updated ${lastUpdated}`
              : "Auto-refreshes every 5s"
          }
        >
          Active Sessions
        </Header>
      }
    >
      {error && <Alert type="error">{error}</Alert>}
      {!error && sessions.length === 0 && !loading && (
        <Box textAlign="center" color="text-body-secondary" padding="xl">
          No active sessions
        </Box>
      )}
      {loading && sessions.length === 0 ? (
        <Spinner />
      ) : (
        <Table
          items={sessions}
          columnDefinitions={columns}
          trackBy="id"
          empty={
            <Box textAlign="center" color="text-body-secondary">
              No active sessions
            </Box>
          }
        />
      )}
    </Container>
  );
}
