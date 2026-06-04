import { useEffect, useState } from "react";
import {
  Container,
  Header,
  SpaceBetween,
  ColumnLayout,
  Box,
  Badge,
  StatusIndicator,
  Button,
  Spinner,
  Alert,
} from "@cloudscape-design/components";
import { get, AuthConfig } from "../api";

const SOURCE_LABELS: Record<string, string> = {
  icam: "ICAM / OIDC",
  ldap: "LDAP",
  local: "Local credentials",
};

const SOURCE_COLORS: Record<string, "blue" | "grey" | "green"> = {
  icam: "blue",
  ldap: "grey",
  local: "green",
};

function SourceBadge({ source }: Readonly<{ source: string }>) {
  const color = SOURCE_COLORS[source] ?? "grey";
  return <Badge color={color}>{SOURCE_LABELS[source] ?? source}</Badge>;
}

function realmFromEndpoint(endpoint: string): string {
  const m = /\/realms\/([^/]+)\//.exec(endpoint);
  return m ? m[1] : "—";
}

function ReachabilityIndicator({
  reachable,
}: Readonly<{ reachable: boolean | null }>) {
  if (reachable === null) {
    return <StatusIndicator type="pending">Not checked</StatusIndicator>;
  }
  if (reachable) {
    return <StatusIndicator type="success">Reachable</StatusIndicator>;
  }
  return <StatusIndicator type="error">Unreachable</StatusIndicator>;
}

function IcamDetail({
  icam,
}: Readonly<{ icam: NonNullable<AuthConfig["icam"]> }>) {
  const realm = realmFromEndpoint(icam.endpoint);
  const base = icam.endpoint.replace(/\/realms\/.+$/, "");

  return (
    <ColumnLayout columns={2} variant="text-grid">
      <div>
        <Box variant="awsui-key-label">Provider URL</Box>
        <Box>{base}</Box>
      </div>
      <div>
        <Box variant="awsui-key-label">Realm</Box>
        <Box>{realm}</Box>
      </div>
      <div>
        <Box variant="awsui-key-label">Client ID</Box>
        <Box>{icam.client_id || "—"}</Box>
      </div>
      <div>
        <Box variant="awsui-key-label">Groups claim</Box>
        <Box>
          <code>{icam.groups_claim || "groups"}</code>
        </Box>
      </div>
      <div>
        <Box variant="awsui-key-label">Token endpoint</Box>
        <Box>
          <code style={{ wordBreak: "break-all", fontSize: "0.85em" }}>
            {icam.endpoint}
          </code>
        </Box>
      </div>
      <div>
        <Box variant="awsui-key-label">Provider reachable</Box>
        <Box>
          <ReachabilityIndicator reachable={icam.reachable} />
        </Box>
      </div>
    </ColumnLayout>
  );
}

function LdapDetail({
  ldap,
}: Readonly<{ ldap: NonNullable<AuthConfig["ldap"]> }>) {
  return (
    <ColumnLayout columns={2} variant="text-grid">
      <div>
        <Box variant="awsui-key-label">LDAP URL</Box>
        <Box>
          <code>{ldap.url}</code>
        </Box>
      </div>
    </ColumnLayout>
  );
}

export default function ConfigurationPage() {
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    get<AuthConfig>("/api/config")
      .then(setCfg)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <SpaceBetween size="l">
      <Container
        header={
          <Header
            variant="h2"
            actions={<Button iconName="refresh" onClick={load} />}
            description="Authentication source currently active on the TACACS+ server."
          >
            Authentication source
          </Header>
        }
      >
        {loading && !cfg ? (
          <Spinner />
        ) : error ? (
          <Alert type="error">{error}</Alert>
        ) : (
          <SpaceBetween size="m">
            <ColumnLayout columns={2} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">Active source</Box>
                <Box>
                  <SourceBadge source={cfg?.auth_source ?? "local"} />
                </Box>
              </div>
              <div>
                <Box variant="awsui-key-label">Change source</Box>
                <Box color="text-body-secondary" fontSize="body-s">
                  Auth source is configured via server CLI flags
                  (<code>--icam-token-endpoint</code> / <code>--ldap-url</code>).
                  See deployment manifest to change.
                </Box>
              </div>
            </ColumnLayout>

            {cfg?.auth_source === "icam" && cfg.icam && (
              <Container
                header={<Header variant="h3">ICAM / OIDC configuration</Header>}
              >
                <IcamDetail icam={cfg.icam} />
              </Container>
            )}

            {cfg?.auth_source === "ldap" && cfg.ldap && (
              <Container
                header={<Header variant="h3">LDAP configuration</Header>}
              >
                <LdapDetail ldap={cfg.ldap} />
              </Container>
            )}

            {cfg?.auth_source === "local" && (
              <Alert type="warning">
                Local credential storage is active. For production deployments,
                migrate to ICAM or LDAP to eliminate local password hashes.
              </Alert>
            )}
          </SpaceBetween>
        )}
      </Container>
    </SpaceBetween>
  );
}
