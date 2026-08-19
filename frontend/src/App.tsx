import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ExplorerView } from './components/ExplorerView';
import { AlertsView } from './components/AlertsView';
import { IncidentsView } from './components/IncidentsView';
import { AgentsView } from './components/AgentsView';
import { RulesView } from './components/RulesView';
import { api } from './api/client';
import { DashboardSummary, SecurityEvent, Alert, Incident, Agent, DetectionRule } from './types';

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

  const criticalAlertCount = summary ? summary.critical_alerts : 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar
        timeRange={timeRange}
        setTimeRange={setTimeRange}
        criticalAlertCount={criticalAlertCount}
      />
      <div className="flex flex-1">
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          alertCount={alerts.length}
          incidentCount={incidents.length}
          agentCount={agents.length}
        />
        <main className="flex-1 overflow-y-auto bg-slate-900/40">
          {activeTab === 'dashboard' && (
            <DashboardView summary={summary} isLoading={isLoading} onNavigateTab={setActiveTab} />
          )}
          {activeTab === 'explorer' && (
            <ExplorerView events={events} isLoading={isLoading} onRefresh={loadData} />
          )}
          {activeTab === 'alerts' && <AlertsView alerts={alerts} onRefresh={loadData} />}
          {activeTab === 'incidents' && <IncidentsView incidents={incidents} onRefresh={loadData} />}
          {activeTab === 'agents' && <AgentsView agents={agents} />}
          {activeTab === 'rules' && <RulesView rules={rules} />}
        </main>
      </div>
    </div>
  );
};

export default App;
