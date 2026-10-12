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
  const [isSidebarOpen, setIsSidebarOpen] = useState<boolean>(false);
  const [summary, setSummary] = useState<DashboardSummary | undefined>();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [timeRange, setTimeRange] = useState<string>('24h');

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
        setCurrentUser({
          id: 'dev-user-01',
          full_name: 'Wazuh Administrator',
          email: 'admin@wazuh.local',
          role: 'ADMIN',
          tenant_id: 'wazuh',
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
      console.error('Failed to connect to backend cluster:', e);
    } finally {
      if (isInitial) setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
    const interval = setInterval(() => loadData(false), 5000); // Background poll
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
    loadData(false);
  };

  const moduleNamesMap: Record<NavTab, string> = {
    dashboard: 'Incident Response',
    explorer: 'Security Events',
    alerts: 'Alert Triage',
    incidents: 'Incidents Workspace',
    agents: 'Endpoint Agents',
    rules: 'Rules & Decoders',
    sca: 'Policy Monitoring',
    vulnerabilities: 'Vulnerability Detection',
    active_response: 'Active Response',
    playbooks: 'Threat Hunting',
    reports: 'Executive Reports',
    asql: 'Dev Tools',
  };

  return (
    <div className="min-h-screen bg-[#f5f7fa] text-slate-800 flex flex-col font-sans">
      {/* Top Wazuh Header, Sub-navigation & Filters (Matching Image 1) */}
      <Navbar
        onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        timeRange={timeRange}
        setTimeRange={setTimeRange}
        onRefresh={() => loadData(false)}
        onOpenAuth={() => setShowAuthModal(true)}
        currentUser={currentUser}
        onLogout={handleLogout}
        onOpenConfig={() => setShowConfigModal(true)}
        onExploreAgent={() => setActiveTab('agents')}
        onGenerateReport={() => setActiveTab('reports')}
        currentModuleName={moduleNamesMap[activeTab] || 'Incident Response'}
      />

      {/* Wazuh Slide-out Navigation Drawer Menu */}
      <Sidebar
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertCount={alerts.length}
        incidentCount={incidents.length}
        agentCount={agents.length}
        onOpenConfig={() => setShowConfigModal(true)}
      />

      {/* Main View Area */}
      <main className="flex-1 overflow-y-auto">
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

      {/* Modals & Dialogs */}
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
