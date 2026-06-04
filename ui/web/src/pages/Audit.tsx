import { useEffect, useState } from "react";
import {
  Table, Header, Button, SpaceBetween, Container, Input, Select, Box,
  Badge, StatusIndicator, ColumnLayout, Pagination, Modal, ExpandableSection,
} from "@cloudscape-design/components";
import { get, AuditEvent, fmtTs, nadIp } from "../api";

const STATUS: Record<string, "success" | "error" | "warning" | "info"> = {
  pass: "success", success: "success", fail: "error", error: "error", info: "info",
};
const EVENTS = ["", "conn_open", "conn_close", "authn_terminal", "authz_policy_allow",
  "authz_policy_deny", "acct_accept", "authn_rfc_invalid", "authn_sequence_error"];

// A labelled value cell for the detail grid.
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <div>{children}</div>
    </div>
  );
}

// Keys rendered as their own fields; everything else falls into the raw JSON.
const KNOWN = new Set(["ts", "event", "status", "peer", "user", "session", "reason", "data"]);

function EventDetail({ e }: { e: AuditEvent }) {
  const iso = (() => { try { return new Date(e.ts / 1e6).toISOString(); } catch { return ""; } })();
  const extra = Object.keys(e).filter((k) => !KNOWN.has(k));
  return (
    <SpaceBetween size="l">
      <ColumnLayout columns={2} variant="text-grid">
        <Field label="Time">{fmtTs(e.ts)}<Box color="text-status-inactive" fontSize="body-s">{iso}</Box></Field>
        <Field label="Event"><Badge>{e.event || "—"}</Badge></Field>
        <Field label="Status">
          <StatusIndicator type={STATUS[e.status || "info"] || "info"}>{e.status || "—"}</StatusIndicator>
        </Field>
        <Field label="NAD (peer)">
          {nadIp(e.peer) || "—"}
          {e.peer && e.peer !== nadIp(e.peer) && (
            <Box color="text-status-inactive" fontSize="body-s">{e.peer}</Box>
          )}
        </Field>
        <Field label="User">{e.user || "—"}</Field>
        <Field label="Session">{String(e.session ?? "—")}</Field>
      </ColumnLayout>

      <Field label="Reason"><Box>{e.reason || "—"}</Box></Field>

      <Field label="Detail">
        {e.data
          ? <Box variant="code" fontSize="body-s">{e.data}</Box>
          : <Box color="text-status-inactive">—</Box>}
      </Field>

      {extra.length > 0 && (
        <ColumnLayout columns={2} variant="text-grid">
          {extra.map((k) => (
            <Field key={k} label={k}><Box variant="code" fontSize="body-s">{String(e[k])}</Box></Field>
          ))}
        </ColumnLayout>
      )}

      <ExpandableSection headerText="Raw event (JSON)">
        <Box variant="code" fontSize="body-s">
          <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(e, null, 2)}</pre>
        </Box>
      </ExpandableSection>
    </SpaceBetween>
  );
}

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [peer, setPeer] = useState("");
  const [user, setUser] = useState("");
  const [event, setEvent] = useState("");
  const [status, setStatus] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
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
        onRowClick={({ detail }) => setSelected(detail.item)}
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
          { id: "view", header: "", width: 90, cell: () => <Box color="text-status-info" fontSize="body-s">Details ›</Box> },
        ]}
      />

      <Modal
        visible={!!selected}
        onDismiss={() => setSelected(null)}
        size="large"
        header={
          <SpaceBetween direction="horizontal" size="s">
            <span>Audit event</span>
            {selected?.event && <Badge>{selected.event}</Badge>}
            {selected?.status && (
              <StatusIndicator type={STATUS[selected.status] || "info"}>{selected.status}</StatusIndicator>
            )}
          </SpaceBetween>
        }
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="copy" onClick={() => selected && navigator.clipboard?.writeText(JSON.stringify(selected, null, 2))}>
                Copy JSON
              </Button>
              <Button variant="primary" onClick={() => setSelected(null)}>Close</Button>
            </SpaceBetween>
          </Box>
        }
      >
        {selected && <EventDetail e={selected} />}
      </Modal>
    </SpaceBetween>
  );
}
