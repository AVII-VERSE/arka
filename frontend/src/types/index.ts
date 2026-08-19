export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type AgentStatus = 'ONLINE' | 'OFFLINE' | 'DISCONNECTED' | 'UNENROLLED';

export interface DashboardSummary {
  event_volume: number;
  events_per_second: number;
  critical_alerts: number;
  high_alerts: number;
  open_incidents: number;
  active_agents: number;
  offline_agents: number;
  authentication_failures: number;
  top_source_ips: { ip: string; count: number }[];
  affected_hosts: { host: string; count: number }[];
  severity_distribution: Record<Severity, number>;
  mitre_techniques: { technique_id: string; count: number }[];
  recent_alerts: Alert[];
}

export interface SecurityEvent {
  event_id: string;
  tenant_id: string;
  agent_id: string;
  timestamp: string;
  source_type: string;
  host: string;
  source_ip?: string;
  destination_ip?: string;
  user?: string;
  event_type: string;
  action: string;
  severity: Severity;
  message: string;
  process?: string;
  metadata: Record<string, any>;
  ingested_at?: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  rule_id?: string;
  rule_code: string;
  severity: Severity;
  host: string;
  user?: string;
  source_ip?: string;
  destination_ip?: string;
  reason: string;
  mitre_technique_id: string;
  status: AlertStatus;
  related_events: string[];
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  assigned_analyst_id?: string;
  notes: { user_id: string; author: string; text: string }[];
  created_at: string;
  updated_at: string;
}

export interface Agent {
  id: string;
  tenant_id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  os_version: string;
  agent_version: string;
  status: AgentStatus;
  last_heartbeat: string;
  created_at: string;
}

export interface DetectionRule {
  id: string;
  tenant_id: string;
  rule_code: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: bool;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  conditions: Record<string, any>;
  threshold: Record<string, any>;
  created_at: string;
}
