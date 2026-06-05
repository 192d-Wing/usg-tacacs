import { useEffect, useState } from "react";
import { Routes, Route, useNavigate, useLocation, Navigate } from "react-router-dom";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import { get } from "./api";
import AuditPage from "./pages/Audit";
import FlowsPage from "./pages/Flows";
import AlertsPage from "./pages/Alerts";
import ResourcesPage from "./pages/Resources";
import ConfigurationPage from "./pages/Configuration";
import SessionsPage from "./pages/Sessions";

export default function App() {
  const nav = useNavigate();
  const loc = useLocation();
  const [me, setMe] = useState<{ email?: string; user?: string }>({});
  useEffect(() => {
    get("/api/me").then(setMe).catch(() => {});
  }, []);

  return (
    <>
      <div id="top-nav">
        <TopNavigation
          identity={{ href: "/", title: "usg-tacacs — Operations" }}
          utilities={[
            {
              type: "button",
              iconName: "user-profile",
              text: me.email || me.user || "operator",
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        toolsHide
        navigation={
          <SideNavigation
            activeHref={loc.pathname}
            header={{ href: "/", text: "Observability" }}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                nav(e.detail.href);
              }
            }}
            items={[
              { type: "link", text: "Audit logs", href: "/audit" },
              { type: "link", text: "NAD flow", href: "/flows" },
              { type: "link", text: "Alerts", href: "/alerts" },
              { type: "link", text: "Resources", href: "/resources" },
              { type: "link", text: "Sessions", href: "/sessions" },
              { type: "divider" },
              { type: "link", text: "Configuration", href: "/configuration" },
            ]}
          />
        }
        content={
          <Routes>
            <Route path="/" element={<Navigate to="/audit" replace />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/flows" element={<FlowsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/resources" element={<ResourcesPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/configuration" element={<ConfigurationPage />} />
          </Routes>
        }
      />
    </>
  );
}
