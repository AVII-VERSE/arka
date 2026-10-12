export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'OPEN';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type AgentStatus = 'ONLINE' | 'OFFLINE' | 'DISCONNECTED' | 'UNENROLLED';

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  tenant_id: string;
  role: string;
  is_active?: boolean;
}

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
  metadata?: Record<string, any>;
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
  related_events?: string[];
  created_at: string;
  updated_at?: string;
}

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  assigned_analyst_id?: string;
  notes?: { user_id?: string; author?: string; text: string; created_at?: string }[];
  created_at: string;
  updated_at?: string;
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
  enabled: boolean;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  conditions: Record<string, any>;
  threshold: Record<string, any>;
  created_at: string;
}

export interface SCAReport {
  id?: string;
  policy_id: string;
  policy_name: string;
  agent_id: string;
  tenant_id?: string;
  compliance_score: number;
  total_checks?: number;
  passed_checks: number;
  failed_checks: number;
  not_applicable_checks?: number;
  checks?: Array<{
    check_id: string;
    title: string;
    status: 'PASSED' | 'FAILED' | 'NOT_APPLICABLE';
    description?: string;
    remediation?: string;
  }>;
  created_at?: string;
}

export interface VulnerabilityFinding {
  id?: string;
  agent_id: string;
  package_name: string;
  installed_version: string;
  cve_id: string;
  cvss_score: number;
  severity: Severity;
  description: string;
  fixed_version?: string;
  status: 'ACTIVE' | 'MITIGATED' | 'IGNORED';
  detected_at?: string;
}

export interface ActiveResponseTask {
  id: string;
  agent_id: string;
  action: 'BLOCK_IP' | 'KILL_PROCESS' | 'LOCK_ACCOUNT' | 'QUARANTINE_FILE';
  target: string;
  parameters?: Record<string, any>;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'TIMEOUT';
  stdout?: string;
  stderr?: string;
  created_at: string;
  completed_at?: string;
}

export interface ThreatHuntingPlaybook {
  playbook_id: string;
  name: string;
  description: string;
  mitre_tactic: string;
  mitre_technique_ids: string[];
  hypothesis: string;
  steps: Array<{
    step_id: number;
    action: string;
    query_hint?: string;
    expected_evidence?: string;
  }>;
  severity: Severity;
  tags: string[];
  is_builtin?: boolean;
}

export interface ExecutiveReport {
  report_id: string;
  tenant_id: string;
  title: string;
  security_score: number;
  metrics: {
    active_agents: number;
    sca_pass_rate: number;
    total_alerts: number;
    critical_alerts: number;
    high_alerts: number;
    medium_alerts: number;
    low_alerts: number;
    vulnerability_count: number;
  };
  html_content: string;
  created_at: string;
}

export interface WebhookConfig {
  id?: string;
  name: string;
  url: string;
  event_types: string[];
  secret?: string;
  enabled: boolean;
  created_at?: string;
}

export interface CommandAuditRecord {
  id?: string;
  agent_id: string;
  command: string;
  user: string;
  pid: number;
  ppid?: number;
  euid?: number;
  ruid?: number;
  status: 'AUDITED' | 'FLAGGED_SUSPICIOUS' | 'BLOCKED';
  risk_reason?: string;
  timestamp: string;
}

export interface CloudContainerRecord {
  id?: string;
  agent_id: string;
  source_type: 'docker' | 'kubernetes' | 'aws_s3';
  container_id?: string;
  image?: string;
  risk_level: Severity;
  findings: string[];
  timestamp: string;
}
