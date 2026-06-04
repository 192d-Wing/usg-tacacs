import { useEffect, useState } from "react";
import {
  Table, Header, Button, SpaceBetween, Container, Input, Select, Box,
  Badge, StatusIndicator, ColumnLayout, Pagination,
} from "@cloudscape-design/components";
import { get, AuditEvent, fmtTs, nadIp } from "../api";

const STATUS: Record<string, "success" | "error" | "warning" | "info"> = {
  pass: "success", success: "success", fail: "error", error: "error", info: "info",
};
const EVENTS = ["", "conn_open", "conn_close", "authn_terminal", "authz_policy_allow",
  "authz_policy_deny", "acct_accept", "authn_rfc_invalid", "authn_sequence_error"];

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [peer, setPeer] = useState("");
  const [user, setUser] = useState("");
  const [event, setEvent] = useState("");
  const [status, setStatus] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const load = () => {
    setLoading(true);
    get<{ events: AuditEvent[] }>("/api/audit", { peer, user, event, status, minutes, limit: 1000 })
      .then((d) => { setEvents(d.events || []); setPage(1); })
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const pageItems = events.slice((page - 1) * pageSize, page * pageSize);

  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h2">Filters</Header>}>
        <ColumnLayout columns={4}>
          <Box>NAD IP / peer<Input value={peer} onChange={(e) => setPeer(e.detail.value)} placeholder="10.0.100.47" /></Box>
          <Box>User<Input value={user} onChange={(e) => setUser(e.detail.value)} placeholder="admin" /></Box>
          <Box>Event
            <Select selectedOption={{ value: event, label: event || "any" }}
              onChange={(e) => setEvent(e.detail.selectedOption.value || "")}
              options={EVENTS.map((v) => ({ value: v, label: v || "any" }))} />
          </Box>
          <Box>Status
            <Select selectedOption={{ value: status, label: status || "any" }}
              onChange={(e) => setStatus(e.detail.selectedOption.value || "")}
              options={["", "pass", "fail", "error", "info"].map((v) => ({ value: v, label: v || "any" }))} />
          </Box>
          <Box>Window (minutes)<Input value={minutes} type="number" onChange={(e) => setMinutes(e.detail.value)} /></Box>
        </ColumnLayout>
        <Box margin={{ top: "s" }}>
          <Button variant="primary" iconName="search" loading={loading} onClick={load}>Search</Button>
        </Box>
      </Container>

      <Table
        loading={loading}
        loadingText="Querying Loki…"
        variant="container"
        header={<Header counter={`(${events.length})`} actions={<Button iconName="refresh" onClick={load} />}>Audit events</Header>}
        items={pageItems}
        pagination={<Pagination currentPageIndex={page} pagesCount={Math.max(1, Math.ceil(events.length / pageSize))} onChange={(e) => setPage(e.detail.currentPageIndex)} />}
        empty={<Box textAlign="center" color="inherit">No events in window</Box>}
        columnDefinitions={[
          { id: "ts", header: "Time", cell: (e) => fmtTs(e.ts), width: 200 },
          { id: "event", header: "Event", cell: (e) => <Badge>{e.event}</Badge> },
          { id: "status", header: "Status", cell: (e) => <StatusIndicator type={STATUS[e.status || "info"] || "info"}>{e.status}</StatusIndicator> },
          { id: "peer", header: "NAD", cell: (e) => nadIp(e.peer) },
          { id: "user", header: "User", cell: (e) => e.user || "—" },
          { id: "session", header: "Session", cell: (e) => String(e.session ?? "") },
          { id: "reason", header: "Reason", cell: (e) => e.reason || "" },
          { id: "data", header: "Detail", cell: (e) => <Box variant="code" fontSize="body-s">{e.data || ""}</Box> },
        ]}
      />
    </SpaceBetween>
  );
}
