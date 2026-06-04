import { useEffect, useState } from "react";
import {
  Container, Header, ColumnLayout, Box, LineChart, SpaceBetween, Button, Spinner,
} from "@cloudscape-design/components";
import { get } from "../api";

type Matrix = Array<{ metric: Record<string, string>; values: [number, string][] }>;

function toSeries(matrix: Matrix, scale = 1) {
  return (matrix || []).map((m) => ({
    title: (m.metric.pod || "pod").replace(/^tacacs-/, "").slice(0, 16),
    type: "line" as const,
    data: (m.values || []).map(([t, v]) => ({ x: new Date(t * 1000), y: parseFloat(v) * scale })),
  }));
}
const num = (v: any, d = 2) => (v === null || v === undefined ? "—" : Number(v).toFixed(d));

export default function ResourcesPage() {
  const [res, setRes] = useState<any>(null);
  const [met, setMet] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    Promise.all([get("/api/resources", { minutes: 60 }), get("/api/metrics")])
      .then(([r, m]) => { setRes(r); setMet(m); })
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, []);

  const cpu = res ? toSeries(res.cpu_cores) : [];
  const mem = res ? toSeries(res.memory_bytes, 1 / (1024 * 1024)) : [];
  const cpuLimit = res?.cpu_limit_cores ? Number(res.cpu_limit_cores) : undefined;
  const memLimit = res?.memory_limit_bytes ? Number(res.memory_limit_bytes) / (1024 * 1024) : undefined;

  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h2" actions={<Button iconName="refresh" onClick={load} />}
        description="Live server stats; auto-refresh 30s.">Server metrics</Header>}>
        {loading && !met ? <Spinner /> : (
          <ColumnLayout columns={4} variant="text-grid">
            <div><Box variant="awsui-key-label">Active connections</Box><Box variant="h2">{num(met?.connections_active, 0)}</Box></div>
            <div><Box variant="awsui-key-label">Active sessions</Box><Box variant="h2">{num(met?.sessions_active, 0)}</Box></div>
            <div><Box variant="awsui-key-label">Authz p99</Box><Box variant="h2">{met?.authz_p99_seconds ? num(Number(met.authz_p99_seconds) * 1000, 1) + " ms" : "—"}</Box></div>
            <div><Box variant="awsui-key-label">Policy rules</Box><Box variant="h2">{num(met?.policy_rules, 0)}</Box></div>
          </ColumnLayout>
        )}
      </Container>

      <Container header={<Header variant="h3">Container CPU (cores) per replica</Header>}>
        <LineChart
          series={[
            ...cpu,
            ...(cpuLimit ? [{ title: "limit", type: "threshold" as const, y: cpuLimit }] : []),
          ]}
          xScaleType="time" height={260} hideFilter
          yTitle="cores" xTitle="time"
          empty={<Box textAlign="center">No CPU data</Box>}
        />
      </Container>

      <Container header={<Header variant="h3">Container memory (MiB) per replica</Header>}>
        <LineChart
          series={[
            ...mem,
            ...(memLimit ? [{ title: "limit", type: "threshold" as const, y: memLimit }] : []),
          ]}
          xScaleType="time" height={260} hideFilter
          yTitle="MiB" xTitle="time"
          empty={<Box textAlign="center">No memory data</Box>}
        />
      </Container>
    </SpaceBetween>
  );
}
