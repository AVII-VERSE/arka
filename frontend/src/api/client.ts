import axios from 'axios';
import {
  ActiveResponseTask,
  Agent,
  Alert,
  AlertStatus,
  CloudContainerRecord,
  CommandAuditRecord,
  DashboardSummary,
  DetectionRule,
  ExecutiveReport,
  Incident,
  IncidentStatus,
  SCAReport,
  SecurityEvent,
  ThreatHuntingPlaybook,
  UserProfile,
  VulnerabilityFinding,
  WebhookConfig,
} from '../types';

const API_BASE = '/api/v1';

const client = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to attach JWT Authorization header if available
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('arka_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const api = {
  // Authentication & Tenants
  login: async (email: string, password: string): Promise<{ access_token: string; token_type: string }> => {
    const res = await client.post('/auth/login', { email, password });
    if (res.data?.access_token) {
      localStorage.setItem('arka_token', res.data.access_token);
    }
    return res.data;
  },

  registerTenant: async (name: string, slug: string): Promise<any> => {
    const res = await client.post('/auth/register-tenant', { name, slug });
    return res.data;
  },

  registerUser: async (data: {
    email: string;
    password: string;
    full_name: string;
    tenant_id: string;
    role?: string;
  }): Promise<any> => {
    const res = await client.post('/auth/register-user', {
      ...data,
      role: data.role || 'SECURITY_ANALYST',
    });
    return res.data;
  },

  getMe: async (): Promise<UserProfile> => {
    const res = await client.get('/auth/me');
    return res.data;
  },

  logout: () => {
    localStorage.removeItem('arka_token');
  },

  // SOC Executive Dashboard
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    const res = await client.get('/dashboard/summary');
    return res.data;
  },

  // Security Events & Telemetry
  getEvents: async (params?: Record<string, any>): Promise<SecurityEvent[]> => {
    const res = await client.get('/events', { params });
    return res.data;
  },

  ingestEvent: async (eventData: Record<string, any>): Promise<any> => {
    const res = await client.post('/events/ingest', eventData);
    return res.data;
  },

  // Alert Triage
  getAlerts: async (params?: Record<string, any>): Promise<Alert[]> => {
    const res = await client.get('/alerts', { params });
    return res.data;
  },

  updateAlertStatus: async (alertId: string, status: AlertStatus): Promise<Alert> => {
    const res = await client.patch(`/alerts/${alertId}`, { status });
    return res.data;
  },

  // Incident Workspace
  getIncidents: async (params?: Record<string, any>): Promise<Incident[]> => {
    const res = await client.get('/incidents', { params });
    return res.data;
  },

  updateIncidentStatus: async (incidentId: string, status: IncidentStatus, note?: string): Promise<Incident> => {
    const res = await client.patch(`/incidents/${incidentId}`, { status, note });
    return res.data;
  },

  // Endpoint Agent Fleet
  getAgents: async (): Promise<Agent[]> => {
    const res = await client.get('/agents');
    return res.data;
  },

  enrollAgent: async (data: {
    hostname: string;
    ip_address: string;
    os_type: string;
    os_version: string;
    agent_version?: string;
    enrollment_token?: string;
  }): Promise<Agent> => {
    const res = await client.post('/agents/enroll', {
      ...data,
      agent_version: data.agent_version || '0.1.0',
      enrollment_token: data.enrollment_token || 'arka-default-enroll-token',
    });
    return res.data;
  },

  // Detection Rules & MITRE
  getRules: async (): Promise<DetectionRule[]> => {
    const res = await client.get('/rules');
    return res.data;
  },

  // Security Configuration Assessment (SCA / CIS)
  getSCA: async (): Promise<SCAReport[]> => {
    const res = await client.get('/sca');
    return res.data;
  },

  // Vulnerability Detector (NVD CVE)
  getVulnerabilities: async (): Promise<VulnerabilityFinding[]> => {
    const res = await client.get('/vulnerabilities');
    return res.data;
  },

  scanVulnerabilities: async (agentId: string, packages: Array<{ name: string; version: string }>): Promise<any> => {
    const res = await client.post('/vulnerabilities/scan', {
      agent_id: agentId,
      packages,
    });
    return res.data;
  },

  // Active Response
  getActiveResponseTasks: async (): Promise<ActiveResponseTask[]> => {
    const res = await client.get('/active_response/tasks');
    return res.data;
  },

  triggerActiveResponse: async (data: {
    agent_id: string;
    action: string;
    target: string;
    parameters?: Record<string, any>;
  }): Promise<ActiveResponseTask> => {
    const res = await client.post('/active_response/trigger', data);
    return res.data;
  },

  // Threat Hunting Playbooks
  getThreatHuntingPlaybooks: async (): Promise<ThreatHuntingPlaybook[]> => {
    const res = await client.get('/threat_hunting');
    return res.data;
  },

  executePlaybook: async (playbookId: string, analyst: string = 'SOC Analyst'): Promise<any> => {
    const res = await client.post(`/threat_hunting/${playbookId}/execute`, { analyst });
    return res.data;
  },

  // Executive Compliance Reports
  getReports: async (): Promise<ExecutiveReport[]> => {
    const res = await client.get('/reports');
    return res.data;
  },

  generateReport: async (title: string = 'SOC Executive Security Briefing'): Promise<ExecutiveReport> => {
    const res = await client.post('/reports/generate', { title });
    return res.data;
  },

  // Webhook Alerting
  getWebhooks: async (): Promise<WebhookConfig[]> => {
    const res = await client.get('/webhooks');
    return res.data;
  },

  createWebhook: async (data: {
    name: string;
    url: string;
    event_types: string[];
    secret?: string;
  }): Promise<WebhookConfig> => {
    const res = await client.post('/webhooks', data);
    return res.data;
  },

  // Command & Syscall Auditor
  getCommandAudits: async (): Promise<CommandAuditRecord[]> => {
    const res = await client.get('/command_audit');
    return res.data;
  },

  // Container & Cloud Security
  getCloudContainers: async (): Promise<CloudContainerRecord[]> => {
    const res = await client.get('/cloud_container');
    return res.data;
  },

  // ARKA Security Query Language (ASQL)
  executeASQL: async (query: string): Promise<any> => {
    const res = await client.post('/query/execute', { query });
    return res.data;
  },

  // Simulate Telemetry Attack Injection (for immediate live demo / testing)
  simulateAttackEvent: async (attackType: 'BRUTE_FORCE' | 'POWERSHELL_OBFUSCATION' | 'PRIVILEGE_ESCALATION'): Promise<any> => {
    const payloadMap = {
      BRUTE_FORCE: {
        source_type: 'windows_event_log',
        host: 'dc-primary-01.corp.local',
        source_ip: '185.220.101.5',
        destination_ip: '10.0.0.10',
        event_type: 'authentication',
        action: 'logon_failed',
        severity: 'HIGH',
        user: 'Administrator',
        message: 'Security Event 4625: An account failed to log on with bad password.',
        metadata: { failure_count: 5, port: 445 },
      },
      POWERSHELL_OBFUSCATION: {
        source_type: 'windows_event_log',
        host: 'workstation-dev-08.corp.local',
        source_ip: '10.0.4.88',
        destination_ip: '45.154.255.88',
        event_type: 'process',
        action: 'powershell_exec',
        severity: 'CRITICAL',
        user: 'jdoe',
        process: 'powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
        message: 'Security Event 4104: Base64 encoded hidden PowerShell payload executed via cmd.',
        metadata: { parent_process: 'cmd.exe', euid: 1000 },
      },
      PRIVILEGE_ESCALATION: {
        source_type: 'linux_syslog',
        host: 'srv-db-cluster-01',
        source_ip: '10.0.1.25',
        destination_ip: '10.0.1.25',
        event_type: 'privilege',
        action: 'sudo_su',
        severity: 'CRITICAL',
        user: 'www-data',
        process: 'sudo /usr/bin/python3 -c "import pty; pty.spawn(\'/bin/bash\')"',
        message: 'Unauthorized sudo shell escape detected from service account www-data.',
        metadata: { pid: 9142, euid: 0, ruid: 33 },
      },
    };

    const res = await client.post('/events/ingest', {
      events: [
        {
          event_id: `sim-${Date.now()}`,
          tenant_id: 'default-tenant',
          agent_id: 'agt-sim-01',
          timestamp: new Date().toISOString(),
          ...payloadMap[attackType],
        },
      ],
    });
    return res.data;
  },
};
