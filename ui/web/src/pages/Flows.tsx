import { useState } from "react";
import {
  Container, Header, Input, Button, SpaceBetween, Box, ExpandableSection,
  Badge, StatusIndicator, Table, Spinner, Alert,
} from "@cloudscape-design/components";
import { get, FlowSession, AuditEvent, fmtTs, nadIp } from "../api";

const ST: Record<string, "success" | "error" | "warning" | "info"> = {
  pass: "success", success: "success", fail: "error", error: "error", info: "info",
};

function outcome(evs: AuditEvent[]) {
  const term = evs.find((e) => e.event === "authn_terminal");
  if (term) return term.status === "pass" ? <StatusIndicator type="success">authenticated</StatusIndicator>
    : <StatusIndicator type="error">auth failed</StatusIndicator>;
  if (evs.some((e) => e.event?.startsWith("authz") && e.status === "fail"))
    return <StatusIndicator type="warning">authz denied</StatusIndicator>;
  return <StatusIndicator type="info">connection</StatusIndicator>;
}

export default function FlowsPage() {
  const [peer, setPeer] = useState("");
  const [sessions, setSessions] = useState<FlowSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = () => {
    if (!peer) return;
    setLoading(true); setErr("");
    get<{ sessions: FlowSession[] }>("/api/flows", { peer, minutes: 180 })
      .then((d) => setSessions(d.sessions || []))
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };

  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h2" description="Reconstruct a network access device's sessions (connection → authentication → authorization → accounting).">Trace a NAD</Header>}>
        <SpaceBetween direction="horizontal" size="s">
          <Input value={peer} onChange={(e) => setPeer(e.detail.value)} placeholder="NAD IP, e.g. 10.0.100.47"
            onKeyDown={(e) => { if (e.detail.key === "Enter") load(); }} />
          <Button variant="primary" iconName="search" loading={loading} onClick={load}>Trace</Button>
        </SpaceBetween>
      </Container>

      {err && <Alert type="error" header="Query failed">{err}</Alert>}
      {loading && <Spinner size="large" />}
      {!loading && sessions.length === 0 && peer && !err && <Box color="text-status-inactive">No sessions for {peer} in the last 3h.</Box>}

      {sessions.map((s) => (
        <Container key={s.session}
          header={<Header variant="h3" description={`${s.count} events · started ${fmtTs(s.started)}`}
            actions={outcome(s.events)}>
            Session {s.session} <Badge color="blue">{nadIp(peer)}</Badge>
          </Header>}>
          <Table
            variant="embedded"
            items={s.events}
            columnDefinitions={[
              { id: "ts", header: "Time", cell: (e) => fmtTs(e.ts), width: 210 },
              { id: "event", header: "Step", cell: (e) => <Badge>{e.event}</Badge> },
              { id: "status", header: "Status", cell: (e) => <StatusIndicator type={ST[e.status || "info"] || "info"}>{e.status}</StatusIndicator> },
              { id: "user", header: "User", cell: (e) => e.user || "—" },
              { id: "reason", header: "Reason", cell: (e) => e.reason || "" },
              { id: "data", header: "Detail", cell: (e) => <Box variant="code" fontSize="body-s">{e.data || ""}</Box> },
            ]}
          />
        </Container>
      ))}
    </SpaceBetween>
  );
}
