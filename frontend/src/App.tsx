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

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [sumRes, evRes, alRes, incRes, agRes, rlRes] = await Promise.all([
        api.getDashboardSummary(),
        api.getEvents({ limit: 100 }),
        api.getAlerts({ limit: 50 }),
        api.getIncidents({ limit: 50 }),
        api.getAgents(),
        api.getRules(),
      ]);

      setSummary(sumRes);
      setEvents(evRes);
      setAlerts(alRes);
      setIncidents(incRes);
      setAgents(agRes);
      setRules(rlRes);
    } catch (e) {
      console.error('Failed to connect to ARKA backend API cluster:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // Live poll every 5s
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
