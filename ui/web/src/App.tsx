import { useCallback, useEffect, useState } from "react";
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

function pageFor(pathname: string) {
  switch (pathname) {
    case "/audit":
      return <AuditPage />;
    case "/flows":
      return <FlowsPage />;
    case "/alerts":
      return <AlertsPage />;
    case "/resources":
      return <ResourcesPage />;
    case "/sessions":
      return <SessionsPage />;
    case "/configuration":
      return <ConfigurationPage />;
    default:
      return null;
  }
}

export default function App() {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  const [me, setMe] = useState<{ email?: string; user?: string }>({});

  useEffect(() => {
    get("/api/me").then(setMe).catch(() => {});
  }, []);

  useEffect(() => {
    if (window.location.pathname === "/") {
      window.history.replaceState(null, "", "/audit");
      setPathname("/audit");
    }

    const followHistory = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", followHistory);
    return () => window.removeEventListener("popstate", followHistory);
  }, []);

  const navigate = useCallback((href: string) => {
    window.history.pushState(null, "", href);
    setPathname(window.location.pathname);
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
            activeHref={pathname}
            header={{ href: "/", text: "Observability" }}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                navigate(e.detail.href);
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
        content={pageFor(pathname)}
      />
    </>
  );
}
