/*
 * Wazuh Case Management Plugin
 * Case API service — wraps all HTTP calls to the case management REST API.
 */

import { HttpSetup } from 'opensearch-dashboards/public';
import {
  Case,
  CaseListResponse,
  CaseListQuery,
  CreateCasePayload,
  UpdateCasePayload,
  CaseStatus,
  CaseComment,
  LinkedAlert,
  Observable,
  ObservableType,
  AnalyticsSummary,
  CaseTrend,
  WazuhAlertSearchQuery,
  WazuhAlertHit,
} from '../../common/types';
import { API_ROUTES } from '../../common/constants';

// ─── Utility ─────────────────────────────────────────────────
/** Replace route path parameters like {id}, {commentId}, etc. */
function buildUrl(template: string, params: Record<string, string>): string {
  let url = template;
  for (const [key, value] of Object.entries(params)) {
    url = url.replace(`{${key}}`, encodeURIComponent(value));
  }
  return url;
}

// ─── Case CRUD ───────────────────────────────────────────────

/** Fetch a paginated, filtered list of cases. */
export async function getCases(
  http: HttpSetup,
  query: CaseListQuery = {}
): Promise<CaseListResponse> {
  return http.get(API_ROUTES.CASES, { query: query as Record<string, any> });
}

/** Fetch a single case by its document ID. */
export async function getCase(http: HttpSetup, caseId: string): Promise<Case> {
  const url = buildUrl(API_ROUTES.CASE_BY_ID, { id: caseId });
  return http.get(url);
}

/** Create a new case. Returns the created case. */
export async function createCase(
  http: HttpSetup,
  payload: CreateCasePayload
): Promise<Case> {
  return http.post(API_ROUTES.CASES, { body: JSON.stringify(payload) });
}

/** Update an existing case by document ID. */
export async function updateCase(
  http: HttpSetup,
  caseId: string,
  payload: UpdateCasePayload
): Promise<Case> {
  const url = buildUrl(API_ROUTES.CASE_BY_ID, { id: caseId });
  return http.put(url, { body: JSON.stringify(payload) });
}

/** Delete a case by document ID. */
export async function deleteCase(http: HttpSetup, caseId: string): Promise<void> {
  const url = buildUrl(API_ROUTES.CASE_BY_ID, { id: caseId });
  await http.delete(url);
}

// ─── Status & Assignment ─────────────────────────────────────

/** Update the status of a case. */
export async function updateCaseStatus(
  http: HttpSetup,
  caseId: string,
  status: CaseStatus
): Promise<Case> {
  const url = buildUrl(API_ROUTES.CASE_STATUS, { id: caseId });
  return http.post(url, { body: JSON.stringify({ status }) });
}

/** Assign a user to a case. Pass null to unassign. */
export async function assignCase(
  http: HttpSetup,
  caseId: string,
  assignee: string | null
): Promise<Case> {
  const url = buildUrl(API_ROUTES.CASE_ASSIGN, { id: caseId });
  return http.post(url, { body: JSON.stringify({ assignee }) });
}

// ─── Comments ────────────────────────────────────────────────

/** Add a comment to a case. */
export async function addComment(
  http: HttpSetup,
  caseId: string,
  content: string
): Promise<CaseComment> {
  const url = buildUrl(API_ROUTES.CASE_COMMENTS, { id: caseId });
  return http.post(url, { body: JSON.stringify({ content }) });
}

/** Delete a comment from a case. */
export async function deleteComment(
  http: HttpSetup,
  caseId: string,
  commentId: string
): Promise<void> {
  const url = buildUrl(API_ROUTES.CASE_COMMENT_BY_ID, { id: caseId, commentId });
  await http.delete(url);
}

// ─── Alerts ──────────────────────────────────────────────────

/** Link a Wazuh alert to a case. */
export async function linkAlert(
  http: HttpSetup,
  caseId: string,
  alert: {
    alert_id: string;
    index: string;
    rule_id: number;
    rule_description: string;
    rule_level: number;
    rule_groups: string[];
    agent_id: string;
    agent_name: string;
    timestamp: string;
  }
): Promise<LinkedAlert> {
  const url = buildUrl(API_ROUTES.CASE_ALERTS, { id: caseId });
  return http.post(url, { body: JSON.stringify(alert) });
}

/** Unlink an alert from a case. */
export async function unlinkAlert(
  http: HttpSetup,
  caseId: string,
  alertId: string
): Promise<void> {
  const url = buildUrl(API_ROUTES.CASE_ALERT_BY_ID, { id: caseId, alertId });
  await http.delete(url);
}

/** Search Wazuh alerts (for the alert linker modal). */
export async function searchAlerts(
  http: HttpSetup,
  query: WazuhAlertSearchQuery = {}
): Promise<{ alerts: WazuhAlertHit[]; total: number }> {
  return http.get(API_ROUTES.ALERTS_SEARCH, { query: query as Record<string, any> });
}

// ─── Observables ─────────────────────────────────────────────

/** Add an observable to a case. */
export async function addObservable(
  http: HttpSetup,
  caseId: string,
  observable: {
    type: ObservableType;
    value: string;
    description?: string;
    is_ioc: boolean;
  }
): Promise<Observable> {
  const url = buildUrl(API_ROUTES.CASE_OBSERVABLES, { id: caseId });
  return http.post(url, { body: JSON.stringify(observable) });
}

/** Remove an observable from a case. */
export async function removeObservable(
  http: HttpSetup,
  caseId: string,
  observableId: string
): Promise<void> {
  const url = buildUrl(API_ROUTES.CASE_OBSERVABLE_BY_ID, { id: caseId, observableId });
  await http.delete(url);
}

// ─── Users ───────────────────────────────────────────────────

/** Get the currently logged-in user. */
export async function getCurrentUser(http: HttpSetup): Promise<string> {
  const result = await http.get<{ username: string }>(API_ROUTES.ME);
  return result.username || 'unknown';
}

/** Fetch the list of all Wazuh users (for assignee selector). */
export async function getUsers(http: HttpSetup): Promise<string[]> {
  const result = await http.get<{ users: string[] }>(API_ROUTES.USERS);
  return result.users || [];
}

// ─── Analytics ───────────────────────────────────────────────

/** Fetch the analytics summary (counts, averages, breakdowns). */
export async function getAnalyticsSummary(
  http: HttpSetup
): Promise<AnalyticsSummary> {
  return http.get(API_ROUTES.ANALYTICS_SUMMARY);
}

/** Fetch case trends over time. */
export async function getAnalyticsTrends(
  http: HttpSetup,
  days: number = 30
): Promise<CaseTrend[]> {
  return http.get(API_ROUTES.ANALYTICS_TRENDS, { query: { days } });
}


// ─── Monitor ──────────────────────────────────────────────────

const MONITOR_BASE = '/api/wazuh-case-management/monitor';

export async function getMonitorConfig(http: HttpSetup): Promise<any> {
  return http.get(MONITOR_BASE);
}

export async function saveMonitorConfig(http: HttpSetup, config: Partial<any>): Promise<any> {
  return http.put(MONITOR_BASE, { body: JSON.stringify(config) });
}

export async function runMonitorNow(http: HttpSetup): Promise<{ cases_created: number }> {
  return http.post(`${MONITOR_BASE}/run`);
}

/**
 * Fetch all cases for export by paginating in batches of 100 (server max).
 * Applies the same filters (status, search, sort) as the current list view.
 */
export async function getAllCasesForExport(http: HttpSetup, query: CaseListQuery = {}): Promise<Case[]> {
  const PAGE_SIZE = 100;
  const all: Case[] = [];
  let page = 1;

  while (true) {
    const res: CaseListResponse = await http.get(API_ROUTES.CASES, {
      query: { ...query, page, per_page: PAGE_SIZE } as Record<string, any>,
    });
    const batch = res.cases || [];
    all.push(...batch);
    if (all.length >= (res.total || 0) || batch.length < PAGE_SIZE) break;
    page++;
  }

  return all;
}
