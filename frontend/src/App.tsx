import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ExplorerView } from './components/ExplorerView';
import { AlertsView } from './components/AlertsView';
import { IncidentsView } from './components/IncidentsView';
import { AgentsView } from './components/AgentsView';
import { RulesView } from './components/RulesView';
import { api } from './api/client';
import {
  Agent,
  Alert,
  DashboardSummary,
  DetectionRule,
  Incident,
  SecurityEvent,
} from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [summary, setSummary] = useState<DashboardSummary | undefined>();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [sumRes, evRes, alRes, incRes, agRes, rlRes] = await Promise.allSettled([
        api.getDashboardSummary(),
        api.getEvents(),
        api.getAlerts(),
        api.getIncidents(),
        api.getAgents(),
        api.getRules(),
      ]);

      if (sumRes.status === 'fulfilled') setSummary(sumRes.value);
      if (evRes.status === 'fulfilled') setEvents(evRes.value);
      if (alRes.status === 'fulfilled') setAlerts(alRes.value);
      if (incRes.status === 'fulfilled') setIncidents(incRes.value);
      if (agRes.status === 'fulfilled') setAgents(agRes.value);
      if (rlRes.status === 'fulfilled') setRules(rlRes.value);
    } catch (e) {
      console.error('API Load Error:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000); // 10s auto-refresh
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col font-sans">
      <Navbar />

      <div className="flex-1 flex">
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        <main className="flex-1 overflow-y-auto bg-slate-900/50">
          {activeTab === 'dashboard' && <DashboardView summary={summary} isLoading={isLoading} />}
          {activeTab === 'explorer' && <ExplorerView events={events} isLoading={isLoading} onRefresh={loadData} />}
          {activeTab === 'alerts' && <AlertsView alerts={alerts} isLoading={isLoading} onRefresh={loadData} />}
          {activeTab === 'incidents' && <IncidentsView incidents={incidents} isLoading={isLoading} onRefresh={loadData} />}
          {activeTab === 'agents' && <AgentsView agents={agents} isLoading={isLoading} onRefresh={loadData} />}
          {activeTab === 'rules' && <RulesView rules={rules} isLoading={isLoading} />}
        </main>
      </div>
    </div>
  );
};
export default App;
