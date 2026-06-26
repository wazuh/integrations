/*
 * Wazuh Case Management Plugin
 * Common types shared between server and client
 */

// ─── Case Status ──────────────────────────────────────────────
export type CaseStatus = 'open' | 'in_progress' | 'waiting' | 'resolved' | 'closed';

// ─── Case Severity ────────────────────────────────────────────
export type CaseSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

// ─── Case Priority ────────────────────────────────────────────
export type CasePriority = 'P1' | 'P2' | 'P3' | 'P4';

// ─── Case Category ────────────────────────────────────────────
export type CaseCategory =
  | 'malware'
  | 'intrusion_attempt'
  | 'data_exfiltration'
  | 'policy_violation'
  | 'vulnerability'
  | 'phishing'
  | 'denial_of_service'
  | 'insider_threat'
  | 'unauthorized_access'
  | 'other';

// ─── Observable Type ──────────────────────────────────────────
export type ObservableType =
  | 'ip'
  | 'domain'
  | 'url'
  | 'hash_md5'
  | 'hash_sha1'
  | 'hash_sha256'
  | 'email'
  | 'filename'
  | 'hostname'
  | 'port'
  | 'registry_key'
  | 'user_account'
  | 'process'
  | 'other';

// ─── Linked Alert ─────────────────────────────────────────────
export interface LinkedAlert {
  alert_id: string;
  index: string;
  rule_id: number;
  rule_description: string;
  rule_level: number;
  rule_groups: string[];
  agent_id: string;
  agent_name: string;
  timestamp: string;
  manager_name?: string;
  full_log?: string;
}

// ─── Observable ───────────────────────────────────────────────
export interface Observable {
  id: string;
  type: ObservableType;
  value: string;
  description?: string;
  is_ioc: boolean;
  added_at: string;
  added_by: string;
}

// ─── Comment ──────────────────────────────────────────────────
export interface CaseComment {
  comment_id: string;
  author: string;
  content: string;
  created_at: string;
  updated_at?: string;
}

// ─── Case Activity Entry ──────────────────────────────────────
export type ActivityAction =
  | 'case_created'
  | 'status_changed'
  | 'severity_changed'
  | 'priority_changed'
  | 'assigned'
  | 'unassigned'
  | 'comment_added'
  | 'comment_deleted'
  | 'alert_linked'
  | 'alert_unlinked'
  | 'observable_added'
  | 'observable_removed'
  | 'tag_added'
  | 'tag_removed'
  | 'case_closed'
  | 'case_reopened';

export interface CaseActivity {
  id: string;
  action: ActivityAction;
  user: string;
  timestamp: string;
  details?: Record<string, any>;
}

// ─── TLP Level ──────────────────────────────────────────────
export type TlpLevel = 'WHITE' | 'GREEN' | 'AMBER' | 'RED';

// ─── Case Task ──────────────────────────────────────────────
export interface CaseTask {
  task_id: string;
  title: string;
  completed: boolean;
  assigned_to?: string;
  created_at: string;
  completed_at?: string;
}

// ─── Case ───────────────────────────────────────────────────
export interface Case {
  id?: string;
  case_id: string;
  title: string;
  description: string;
  status: CaseStatus;
  severity: CaseSeverity;
  priority: CasePriority;
  category: CaseCategory;
  tlp: TlpLevel;
  tags: string[];
  assignee: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  linked_alerts: LinkedAlert[];
  observables: Observable[];
  comments: CaseComment[];
  tasks: CaseTask[];
  notes: string;
  activity_log: CaseActivity[];
  resolution_summary: string | null;
  time_to_resolve_ms: number | null;
  related_cases: string[];
  custom_fields: Record<string, any>;
}

// ─── Case Create/Update DTOs ──────────────────────────────────
export interface CreateCasePayload {
  title: string;
  description: string;
  severity: CaseSeverity;
  priority: CasePriority;
  category: CaseCategory;
  tlp?: TlpLevel;
  tags?: string[];
  assignee?: string | null;
}

export interface UpdateCasePayload {
  title?: string;
  description?: string;
  status?: CaseStatus;
  severity?: CaseSeverity;
  priority?: CasePriority;
  category?: CaseCategory;
  tlp?: TlpLevel;
  tags?: string[];
  assignee?: string | null;
  resolution_summary?: string | null;
}

// ─── API Response Types ───────────────────────────────────────
export interface CaseListResponse {
  cases: Case[];
  total: number;
  page: number;
  per_page: number;
}

export interface CaseListQuery {
  page?: number;
  per_page?: number;
  sort_field?: string;
  sort_order?: 'asc' | 'desc';
  status?: CaseStatus;
  severity?: CaseSeverity;
  priority?: CasePriority;
  category?: CaseCategory;
  assignee?: string;
  search?: string;
  tags?: string;
  created_from?: string;
  created_to?: string;
}

export interface AnalyticsSummary {
  total_cases: number;
  open_cases: number;
  in_progress_cases: number;
  waiting_cases: number;
  resolved_cases: number;
  closed_cases: number;
  by_severity: Record<CaseSeverity, number>;
  by_priority: Record<CasePriority, number>;
  by_category: Record<string, number>;
  avg_resolution_time_ms: number | null;
  cases_created_today: number;
  cases_closed_today: number;
}

export interface CaseTrend {
  date: string;
  created: number;
  closed: number;
}

// ─── Wazuh Alert Search ───────────────────────────────────────
export interface WazuhAlertSearchQuery {
  search?: string;
  agent_id?: string;
  rule_id?: number;
  level_min?: number;
  level_max?: number;
  from?: string;
  to?: string;
  size?: number;
}

export interface WazuhAlertHit {
  _id: string;
  _index: string;
  _source: {
    timestamp: string;
    rule: {
      id: string;
      description: string;
      level: number;
      groups: string[];
    };
    agent: {
      id: string;
      name: string;
      ip?: string;
    };
    manager?: {
      name: string;
    };
    full_log?: string;
    data?: Record<string, any>;
    [key: string]: any;
  };
}
