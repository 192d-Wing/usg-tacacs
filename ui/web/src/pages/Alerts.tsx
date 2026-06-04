import { useEffect, useState } from "react";
import { Cards, Header, Box, Button, StatusIndicator, SpaceBetween } from "@cloudscape-design/components";
import { get, Alert as AlertT } from "../api";

const SEV: Record<string, "error" | "warning" | "info"> = {
  critical: "error", warning: "warning", info: "info",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertT[]>([]);
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    get<{ alerts: AlertT[] }>("/api/alerts").then((d) => setAlerts(d.alerts || [])).finally(() => setLoading(false));
  };
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, []);

  return (
    <SpaceBetween size="l">
      <Cards
        loading={loading}
        items={alerts}
        cardDefinition={{
          header: (a) => <StatusIndicator type={SEV[a.severity] || "info"}>{a.title}</StatusIndicator>,
          sections: [
            { id: "detail", content: (a) => a.detail },
            { id: "sev", header: "Severity", content: (a) => a.severity },
            { id: "at", header: "Observed", content: (a) => new Date(a.at * 1000).toLocaleString() },
          ],
        }}
        cardsPerRow={[{ cards: 1 }, { minWidth: 600, cards: 2 }]}
        header={<Header counter={`(${alerts.length})`} actions={<Button iconName="refresh" onClick={load} />}
          description="Computed from Prometheus + Loki; refreshes every 30s.">System alerts</Header>}
        empty={<Box textAlign="center" color="text-status-inactive" padding="l">
          <StatusIndicator type="success">No active alerts</StatusIndicator>
        </Box>}
      />
    </SpaceBetween>
  );
}
