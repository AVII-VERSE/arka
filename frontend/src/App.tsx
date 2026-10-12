import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ExplorerView } from './components/ExplorerView';
import { AlertsView } from './components/AlertsView';
import { IncidentsView } from './components/IncidentsView';
import { AgentsView } from './components/AgentsView';
import { RulesView } from './components/RulesView';
import { SCAView } from './components/SCAView';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import { ThreatHuntingView } from './components/ThreatHuntingView';
import { ReportsView } from './components/ReportsView';
import { ActiveResponseView } from './components/ActiveResponseView';
import { ASQLQueryView } from './components/ASQLQueryView';
import { AuthModal } from './components/AuthModal';
import { NotificationDrawer } from './components/NotificationDrawer';
import { SiemConfigModal } from './components/SiemConfigModal';
import { api } from './api/client';
import {
  DashboardSummary,
  SecurityEvent,
  Alert,
  Incident,
  Agent,
  DetectionRule,
  UserProfile,
} from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [summary, setSummary] = useState<DashboardSummary | undefined>();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [timeRange, setTimeRange] = useState<string>('1h');

  // Modals & Drawers state
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [showNotificationDrawer, setShowNotificationDrawer] = useState<boolean>(false);
  const [showConfigModal, setShowConfigModal] = useState<boolean>(false);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);

  // Initialize Auth state
  useEffect(() => {
    api.getMe()
      .then((user) => setCurrentUser(user))
      .catch(() => {
        // Fallback default dev profile if auth is in dev mode
        setCurrentUser({
          id: 'dev-user-01',
          full_name: 'Lead SOC Analyst',
          email: 'analyst@arka-siem.org',
          role: 'SUPER_ADMIN',
          tenant_id: 'default-tenant',
        });
      });
  }, []);

  const loadData = async (isInitial = false) => {
    if (isInitial) setIsLoading(true);
    try {
      const results = await Promise.allSettled([
        api.getDashboardSummary(),
        api.getEvents({ limit: 100 }),
        api.getAlerts({ limit: 50 }),
        api.getIncidents({ limit: 50 }),
        api.getAgents(),
        api.getRules(),
      ]);

      if (results[0].status === 'fulfilled') setSummary(results[0].value);
      if (results[1].status === 'fulfilled') setEvents(results[1].value);
      if (results[2].status === 'fulfilled') setAlerts(results[2].value);
      if (results[3].status === 'fulfilled') setIncidents(results[3].value);
      if (results[4].status === 'fulfilled') setAgents(results[4].value);
      if (results[5].status === 'fulfilled') setRules(results[5].value);
    } catch (e) {
      console.error('Failed to connect to ARKA backend API cluster:', e);
    } finally {
      if (isInitial) setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
    const interval = setInterval(() => loadData(false), 5000); // Silent background poll every 5s
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
    loadData(false);
  };

  const criticalAlertCount = summary ? summary.critical_alerts : alerts.filter(a => a.severity === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <Navbar
        timeRange={timeRange}
        setTimeRange={setTimeRange}
        criticalAlertCount={criticalAlertCount}
        onOpenNotifications={() => setShowNotificationDrawer(true)}
        onOpenAuth={() => setShowAuthModal(true)}
        currentUser={currentUser}
        onLogout={handleLogout}
        onOpenConfig={() => setShowConfigModal(true)}
      />

      {/* Main Container */}
      <div className="flex flex-1">
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          alertCount={alerts.length}
          incidentCount={incidents.length}
          agentCount={agents.length}
          onOpenConfig={() => setShowConfigModal(true)}
        />

        {/* View Content Area */}
        <main className="flex-1 overflow-y-auto bg-slate-900/40">
          {activeTab === 'dashboard' && (
            <DashboardView
              summary={summary}
              isLoading={isLoading}
              onNavigateTab={setActiveTab}
              onRefresh={() => loadData(false)}
            />
          )}
          {activeTab === 'explorer' && (
            <ExplorerView events={events} isLoading={isLoading} onRefresh={() => loadData(false)} />
          )}
          {activeTab === 'alerts' && <AlertsView alerts={alerts} onRefresh={() => loadData(false)} />}
          {activeTab === 'incidents' && <IncidentsView incidents={incidents} onRefresh={() => loadData(false)} />}
          {activeTab === 'agents' && (
            <AgentsView
              agents={agents}
              onRefresh={() => loadData(false)}
              onAgentAdded={(newAgent) => setAgents((prev) => [newAgent, ...prev])}
            />
          )}
          {activeTab === 'rules' && <RulesView rules={rules} />}
          {activeTab === 'sca' && <SCAView />}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesView />}
          {activeTab === 'playbooks' && <ThreatHuntingView />}
          {activeTab === 'reports' && <ReportsView />}
          {activeTab === 'active_response' && <ActiveResponseView />}
          {activeTab === 'asql' && <ASQLQueryView />}
        </main>
      </div>

      {/* Modals & Slide-out Drawers */}
      <AuthModal
        isOpen={showAuthModal}
        onClose={() => setShowAuthModal(false)}
        onAuthSuccess={(user) => {
          setCurrentUser(user);
          loadData(true);
        }}
      />

      <NotificationDrawer
        isOpen={showNotificationDrawer}
        onClose={() => setShowNotificationDrawer(false)}
        alerts={alerts}
        onInspectAlert={() => {
          setActiveTab('alerts');
        }}
        onAcknowledgeAlert={async (alertId) => {
          try {
            await api.updateAlertStatus(alertId, 'ACKNOWLEDGED');
            loadData(false);
          } catch (e) {
            console.error(e);
          }
        }}
      />

      <SiemConfigModal
        isOpen={showConfigModal}
        onClose={() => setShowConfigModal(false)}
        onSimulateSuccess={() => loadData(false)}
      />
    </div>
  );
};

export default App;
