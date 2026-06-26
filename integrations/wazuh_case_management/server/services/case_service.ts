/*
 * Wazuh Case Management Plugin
 * Case Service — Business logic for case management operations
 *
 * Handles case ID generation, CRUD, status transitions, comments,
 * alert linking, observables, activity logging, and analytics.
 */

import { v4 as uuidV4 } from 'crypto';
import {
  Case,
  CreateCasePayload,
  UpdateCasePayload,
  CaseStatus,
  CaseActivity,
  CaseComment,
  LinkedAlert,
  Observable,
  AnalyticsSummary,
  CaseTrend,
  CaseListQuery,
  CaseListResponse,
  WazuhAlertSearchQuery,
} from '../../common/types';
import {
  CASE_INDEX,
  CASE_ID_PREFIX,
  CASE_ID_SEPARATOR,
  STATUS_TRANSITIONS,
  WAZUH_ALERTS_INDEX_PATTERN,
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  DEFAULT_SORT_FIELD,
  DEFAULT_SORT_ORDER,
} from '../../common/constants';
import { OpenSearchService } from './opensearch_service';

/** Generate a UUID v4 without dashes (compact) */
function uuid(): string {
  // Use crypto.randomUUID if available, fallback to manual
  try {
    return crypto.randomUUID().replace(/-/g, '').substring(0, 12);
  } catch {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
  }
}

/**
 * CaseService — all case management business logic.
 * Methods are static; the OpenSearch client is passed in per-request.
 */
export class CaseService {
  // ──────────────────────────────────────────────────────────────
  // Case ID Generation
  // ──────────────────────────────────────────────────────────────

  /**
   * Generate the next human-readable case ID.
   * Format: CASE-2026-0001
   */
  static async generateCaseId(client: any): Promise<string> {
    const counter = await OpenSearchService.getNextCounterValue(client);
    const year = new Date().getFullYear();
    const paddedNum = String(counter).padStart(4, '0');
    return `${CASE_ID_PREFIX}${CASE_ID_SEPARATOR}${year}${CASE_ID_SEPARATOR}${paddedNum}`;
  }

  // ──────────────────────────────────────────────────────────────
  // Activity Log Helper
  // ──────────────────────────────────────────────────────────────

  private static createActivity(
    action: CaseActivity['action'],
    user: string,
    details?: Record<string, any>,
  ): CaseActivity {
    return {
      id: uuid(),
      action,
      user,
      timestamp: new Date().toISOString(),
      details,
    };
  }

  // ──────────────────────────────────────────────────────────────
  // Case CRUD
  // ──────────────────────────────────────────────────────────────

  /** Create a new case */
  static async createCase(
    client: any,
    payload: CreateCasePayload,
    user: string,
  ): Promise<Case> {
    const caseId = await CaseService.generateCaseId(client);
    const now = new Date().toISOString();

    const newCase: Case = {
      case_id: caseId,
      title: payload.title,
      description: payload.description,
      status: 'open',
      severity: payload.severity,
      priority: payload.priority,
      category: payload.category,
      tlp: payload.tlp || 'WHITE',
      tags: payload.tags || [],
      assignee: payload.assignee || null,
      created_by: user,
      created_at: now,
      updated_at: now,
      closed_at: null,
      linked_alerts: [],
      observables: [],
      comments: [],
      tasks: [],
      notes: '',
      activity_log: [
        CaseService.createActivity('case_created', user, {
          case_id: caseId,
          title: payload.title,
        }),
      ],
      resolution_summary: null,
      time_to_resolve_ms: null,
      related_cases: [],
      custom_fields: {},
    };

    // If an assignee was provided, log the assignment
    if (payload.assignee) {
      newCase.activity_log.push(
        CaseService.createActivity('assigned', user, { assignee: payload.assignee }),
      );
    }

    const { _id } = await OpenSearchService.createDocument(client, CASE_INDEX, newCase);
    newCase.id = _id;

    return newCase;
  }

  /** Get a single case by its OpenSearch _id */
  static async getCase(client: any, id: string): Promise<Case | null> {
    const doc = await OpenSearchService.getDocument(client, CASE_INDEX, id);
    if (!doc) return null;
    return { id: doc._id, ...doc._source } as Case;
  }

  /** Update a case (partial update) */
  static async updateCase(
    client: any,
    id: string,
    payload: UpdateCasePayload,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, id);
    if (!existing) return null;

    const now = new Date().toISOString();
    const activities: CaseActivity[] = [];
    const updateDoc: any = { updated_at: now };

    // Track changes for activity log
    if (payload.title !== undefined && payload.title !== existing.title) {
      updateDoc.title = payload.title;
    }
    if (payload.description !== undefined) {
      updateDoc.description = payload.description;
    }
    if (payload.severity !== undefined && payload.severity !== existing.severity) {
      updateDoc.severity = payload.severity;
      activities.push(
        CaseService.createActivity('severity_changed', user, {
          from: existing.severity,
          to: payload.severity,
        }),
      );
    }
    if (payload.priority !== undefined && payload.priority !== existing.priority) {
      updateDoc.priority = payload.priority;
      activities.push(
        CaseService.createActivity('priority_changed', user, {
          from: existing.priority,
          to: payload.priority,
        }),
      );
    }
    if (payload.category !== undefined) {
      updateDoc.category = payload.category;
    }
    if (payload.tlp !== undefined) {
      updateDoc.tlp = payload.tlp;
    }
    if (payload.tags !== undefined) {
      updateDoc.tags = payload.tags;
    }
    if (payload.assignee !== undefined && payload.assignee !== existing.assignee) {
      updateDoc.assignee = payload.assignee;
      activities.push(
        CaseService.createActivity(payload.assignee ? 'assigned' : 'unassigned', user, {
          from: existing.assignee,
          to: payload.assignee,
        }),
      );
    }
    if (payload.resolution_summary !== undefined) {
      updateDoc.resolution_summary = payload.resolution_summary;
    }

    // Append activities
    if (activities.length > 0) {
      updateDoc.activity_log = [...existing.activity_log, ...activities];
    }

    await OpenSearchService.updateDocument(client, CASE_INDEX, id, updateDoc);
    return await CaseService.getCase(client, id);
  }

  /** Delete a case by OpenSearch _id */
  static async deleteCase(client: any, id: string): Promise<boolean> {
    return await OpenSearchService.deleteDocument(client, CASE_INDEX, id);
  }

  /** List cases with filtering, pagination, and sorting */
  static async listCases(client: any, query: CaseListQuery): Promise<CaseListResponse> {
    const page = query.page || 1;
    const perPage = Math.min(query.per_page || DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    const sortField = query.sort_field || DEFAULT_SORT_FIELD;
    const sortOrder = query.sort_order || DEFAULT_SORT_ORDER;

    // Build the query
    const must: any[] = [];

    if (query.status) {
      must.push({ term: { status: query.status } });
    }
    if (query.severity) {
      must.push({ term: { severity: query.severity } });
    }
    if (query.priority) {
      must.push({ term: { priority: query.priority } });
    }
    if (query.category) {
      must.push({ term: { category: query.category } });
    }
    if (query.assignee) {
      must.push({ term: { assignee: query.assignee } });
    }
    if (query.tags) {
      const tagList = query.tags.split(',').map((t) => t.trim());
      must.push({ terms: { tags: tagList } });
    }
    if (query.search) {
      must.push({
        multi_match: {
          query: query.search,
          fields: ['title^3', 'description', 'case_id^2', 'tags'],
          type: 'best_fields',
          fuzziness: 'AUTO',
        },
      });
    }
    if (query.created_from || query.created_to) {
      const range: any = {};
      if (query.created_from) range.gte = query.created_from;
      if (query.created_to) range.lte = query.created_to;
      must.push({ range: { created_at: range } });
    }

    const searchBody = {
      query: must.length > 0 ? { bool: { must } } : { match_all: {} },
      sort: [{ [sortField]: { order: sortOrder } }],
      from: (page - 1) * perPage,
      size: perPage,
      // Exclude heavy nested fields from listing to improve perf
      _source: {
        excludes: ['activity_log', 'comments.content'],
      },
    };

    const { hits, total } = await OpenSearchService.searchDocuments(client, CASE_INDEX, searchBody);

    const cases: Case[] = hits.map((hit: any) => ({
      id: hit._id,
      ...hit._source,
    }));

    return { cases, total, page, per_page: perPage };
  }

  // ──────────────────────────────────────────────────────────────
  // Status Management
  // ──────────────────────────────────────────────────────────────

  /** Change case status with transition validation */
  static async changeStatus(
    client: any,
    id: string,
    newStatus: CaseStatus,
    user: string,
  ): Promise<{ success: boolean; error?: string; case?: Case }> {
    const existing = await CaseService.getCase(client, id);
    if (!existing) {
      return { success: false, error: 'Case not found' };
    }

    // Validate transition
    const allowedTransitions = STATUS_TRANSITIONS[existing.status] || [];
    if (!allowedTransitions.includes(newStatus)) {
      return {
        success: false,
        error: `Cannot transition from '${existing.status}' to '${newStatus}'. Allowed: ${allowedTransitions.join(', ')}`,
      };
    }

    const now = new Date().toISOString();
    const updateDoc: any = {
      status: newStatus,
      updated_at: now,
    };

    // Handle closing
    if (newStatus === 'closed' || newStatus === 'resolved') {
      updateDoc.closed_at = now;
      if (existing.created_at) {
        updateDoc.time_to_resolve_ms = new Date(now).getTime() - new Date(existing.created_at).getTime();
      }
    }

    // Handle reopening
    if (newStatus === 'open' && (existing.status === 'closed' || existing.status === 'resolved')) {
      updateDoc.closed_at = null;
      updateDoc.time_to_resolve_ms = null;
    }

    // Activity
    const activity = CaseService.createActivity(
      newStatus === 'closed' ? 'case_closed' : newStatus === 'open' && existing.status === 'closed' ? 'case_reopened' : 'status_changed',
      user,
      { from: existing.status, to: newStatus },
    );
    updateDoc.activity_log = [...existing.activity_log, activity];

    await OpenSearchService.updateDocument(client, CASE_INDEX, id, updateDoc);
    const updatedCase = await CaseService.getCase(client, id);
    return { success: true, case: updatedCase! };
  }

  /** Assign a case to a user */
  static async assignCase(
    client: any,
    id: string,
    assignee: string | null,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, id);
    if (!existing) return null;

    const activity = CaseService.createActivity(
      assignee ? 'assigned' : 'unassigned',
      user,
      { from: existing.assignee, to: assignee },
    );

    await OpenSearchService.updateDocument(client, CASE_INDEX, id, {
      assignee,
      updated_at: new Date().toISOString(),
      activity_log: [...existing.activity_log, activity],
    });

    return await CaseService.getCase(client, id);
  }

  // ──────────────────────────────────────────────────────────────
  // Tasks
  // ──────────────────────────────────────────────────────────────

  /** Add a task to a case */
  static async addTask(client: any, caseId: string, title: string, user: string): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const newTask = {
      task_id: uuid(),
      title,
      completed: false,
      created_at: new Date().toISOString(),
    };

    const updateDoc = {
      tasks: [...(existing.tasks || []), newTask],
      updated_at: new Date().toISOString(),
    };

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, updateDoc);
    return await CaseService.getCase(client, caseId);
  }

  /** Toggle task completion */
  static async toggleTask(client: any, caseId: string, taskId: string, completed: boolean, user: string): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const tasks = (existing.tasks || []).map((t: any) =>
      t.task_id === taskId ? { ...t, completed, completed_at: completed ? new Date().toISOString() : undefined } : t
    );

    const updateDoc = {
      tasks,
      updated_at: new Date().toISOString(),
    };

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, updateDoc);
    return await CaseService.getCase(client, caseId);
  }

  /** Remove a task */
  static async removeTask(client: any, caseId: string, taskId: string, user: string): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const tasks = (existing.tasks || []).filter((t: any) => t.task_id !== taskId);

    const updateDoc = {
      tasks,
      updated_at: new Date().toISOString(),
    };

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, updateDoc);
    return await CaseService.getCase(client, caseId);
  }

  // ──────────────────────────────────────────────────────────────
  // Notes
  // ──────────────────────────────────────────────────────────────

  /** Update case notes */
  static async updateNotes(client: any, caseId: string, notes: string, user: string): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const updateDoc = {
      notes,
      updated_at: new Date().toISOString(),
    };

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, updateDoc);
    return await CaseService.getCase(client, caseId);
  }

  // ──────────────────────────────────────────────────────────────
  // Comments
  // ──────────────────────────────────────────────────────────────

  /** Add a comment to a case */
  static async addComment(
    client: any,
    caseId: string,
    content: string,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const comment: CaseComment = {
      comment_id: uuid(),
      author: user,
      content,
      created_at: new Date().toISOString(),
    };

    const activity = CaseService.createActivity('comment_added', user, {
      comment_id: comment.comment_id,
    });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      comments: [...existing.comments, comment],
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  /** Delete a comment from a case */
  static async deleteComment(
    client: any,
    caseId: string,
    commentId: string,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const updatedComments = existing.comments.filter((c) => c.comment_id !== commentId);
    if (updatedComments.length === existing.comments.length) {
      return existing; // Comment not found, no change
    }

    const activity = CaseService.createActivity('comment_deleted', user, {
      comment_id: commentId,
    });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      comments: updatedComments,
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  // ──────────────────────────────────────────────────────────────
  // Alert Linking
  // ──────────────────────────────────────────────────────────────

  /** Link an alert to a case */
  static async linkAlert(
    client: any,
    caseId: string,
    alert: LinkedAlert,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    // Check for duplicate
    if (existing.linked_alerts.some((a) => a.alert_id === alert.alert_id)) {
      return existing; // Already linked
    }

    const activity = CaseService.createActivity('alert_linked', user, {
      alert_id: alert.alert_id,
      rule_description: alert.rule_description,
    });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      linked_alerts: [...existing.linked_alerts, alert],
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  /** Unlink an alert from a case */
  static async unlinkAlert(
    client: any,
    caseId: string,
    alertId: string,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const updatedAlerts = existing.linked_alerts.filter((a) => a.alert_id !== alertId);
    const activity = CaseService.createActivity('alert_unlinked', user, { alert_id: alertId });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      linked_alerts: updatedAlerts,
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  /** Search Wazuh alerts in OpenSearch */
  static async searchAlerts(
    client: any,
    query: WazuhAlertSearchQuery,
  ): Promise<{ hits: any[]; total: number }> {
    const must: any[] = [];

    if (query.search) {
      must.push({
        multi_match: {
          query: query.search,
          fields: ['rule.description^2', 'full_log', 'data.*'],
          fuzziness: 'AUTO',
        },
      });
    }
    if (query.agent_id) {
      must.push({ term: { 'agent.id': query.agent_id } });
    }
    if (query.rule_id) {
      must.push({ term: { 'rule.id': String(query.rule_id) } });
    }
    if (query.level_min || query.level_max) {
      const range: any = {};
      if (query.level_min) range.gte = query.level_min;
      if (query.level_max) range.lte = query.level_max;
      must.push({ range: { 'rule.level': range } });
    }
    if (query.from || query.to) {
      const range: any = {};
      if (query.from) range.gte = query.from;
      if (query.to) range.lte = query.to;
      must.push({ range: { timestamp: range } });
    }

    const searchBody = {
      query: must.length > 0 ? { bool: { must } } : { match_all: {} },
      sort: [{ timestamp: { order: 'desc' } }],
      size: Math.min(query.size || 50, 100),
    };

    return await OpenSearchService.searchDocuments(client, WAZUH_ALERTS_INDEX_PATTERN, searchBody);
  }

  // ──────────────────────────────────────────────────────────────
  // Observables
  // ──────────────────────────────────────────────────────────────

  /** Add an observable to a case */
  static async addObservable(
    client: any,
    caseId: string,
    observable: Omit<Observable, 'id' | 'added_at' | 'added_by'>,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const newObservable: Observable = {
      ...observable,
      id: uuid(),
      added_at: new Date().toISOString(),
      added_by: user,
    };

    const activity = CaseService.createActivity('observable_added', user, {
      type: observable.type,
      value: observable.value,
    });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      observables: [...existing.observables, newObservable],
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  /** Remove an observable from a case */
  static async removeObservable(
    client: any,
    caseId: string,
    observableId: string,
    user: string,
  ): Promise<Case | null> {
    const existing = await CaseService.getCase(client, caseId);
    if (!existing) return null;

    const updated = existing.observables.filter((o) => o.id !== observableId);
    const activity = CaseService.createActivity('observable_removed', user, {
      observable_id: observableId,
    });

    await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, {
      observables: updated,
      activity_log: [...existing.activity_log, activity],
      updated_at: new Date().toISOString(),
    });

    return await CaseService.getCase(client, caseId);
  }

  // ──────────────────────────────────────────────────────────────
  // Analytics
  // ──────────────────────────────────────────────────────────────

  /** Get summary analytics for the dashboard */
  static async getAnalyticsSummary(client: any): Promise<AnalyticsSummary> {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayStr = today.toISOString();

    const aggs = await OpenSearchService.aggregateDocuments(client, CASE_INDEX, {
      aggs: {
        by_status: { terms: { field: 'status', size: 10 } },
        by_severity: { terms: { field: 'severity', size: 10 } },
        by_priority: { terms: { field: 'priority', size: 10 } },
        by_category: { terms: { field: 'category', size: 20 } },
        avg_resolution_time: { avg: { field: 'time_to_resolve_ms' } },
        created_today: {
          filter: { range: { created_at: { gte: todayStr } } },
        },
        closed_today: {
          filter: {
            bool: {
              must: [
                { range: { closed_at: { gte: todayStr } } },
                { terms: { status: ['resolved', 'closed'] } },
              ],
            },
          },
        },
        total: { value_count: { field: 'case_id' } },
      },
    });

    // Parse status counts
    const statusCounts: Record<string, number> = {};
    (aggs.by_status?.buckets || []).forEach((b: any) => {
      statusCounts[b.key] = b.doc_count;
    });

    // Parse severity counts
    const severityCounts: Record<string, number> = {};
    (aggs.by_severity?.buckets || []).forEach((b: any) => {
      severityCounts[b.key] = b.doc_count;
    });

    // Parse priority counts
    const priorityCounts: Record<string, number> = {};
    (aggs.by_priority?.buckets || []).forEach((b: any) => {
      priorityCounts[b.key] = b.doc_count;
    });

    // Parse category counts
    const categoryCounts: Record<string, number> = {};
    (aggs.by_category?.buckets || []).forEach((b: any) => {
      categoryCounts[b.key] = b.doc_count;
    });

    const totalCases = aggs.total?.value || 0;

    return {
      total_cases: totalCases,
      open_cases: statusCounts['open'] || 0,
      in_progress_cases: statusCounts['in_progress'] || 0,
      waiting_cases: statusCounts['waiting'] || 0,
      resolved_cases: statusCounts['resolved'] || 0,
      closed_cases: statusCounts['closed'] || 0,
      by_severity: severityCounts as any,
      by_priority: priorityCounts as any,
      by_category: categoryCounts,
      avg_resolution_time_ms: aggs.avg_resolution_time?.value || null,
      cases_created_today: aggs.created_today?.doc_count || 0,
      cases_closed_today: aggs.closed_today?.doc_count || 0,
    };
  }

  /** Get case trends over the last N days */
  static async getCaseTrends(client: any, days: number = 30): Promise<CaseTrend[]> {
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - days);

    const aggs = await OpenSearchService.aggregateDocuments(client, CASE_INDEX, {
      query: {
        range: { created_at: { gte: fromDate.toISOString() } },
      },
      aggs: {
        cases_over_time: {
          date_histogram: {
            field: 'created_at',
            calendar_interval: 'day',
          },
        },
        closed_over_time: {
          filter: { exists: { field: 'closed_at' } },
          aggs: {
            by_day: {
              date_histogram: {
                field: 'closed_at',
                calendar_interval: 'day',
              },
            },
          },
        },
      },
    });

    const createdBuckets = aggs.cases_over_time?.buckets || [];
    const closedBuckets = aggs.closed_over_time?.by_day?.buckets || [];

    // Merge created and closed into a single timeline
    const closedMap: Record<string, number> = {};
    closedBuckets.forEach((b: any) => {
      const dateKey = b.key_as_string?.split('T')[0] || '';
      closedMap[dateKey] = b.doc_count;
    });

    return createdBuckets.map((b: any) => {
      const dateKey = b.key_as_string?.split('T')[0] || '';
      return {
        date: dateKey,
        created: b.doc_count,
        closed: closedMap[dateKey] || 0,
      };
    });
  }

  // ──────────────────────────────────────────────────────────────
  // Automated Alert Handling (Webhooks)
  // ──────────────────────────────────────────────────────────────

  /**
   * Process an incoming alert from a Wazuh webhook.
   * Performs deduplication based on rule.id and agent.id for unresolved cases.
   */
  static async handleAutomatedAlert(client: any, alert: any, user: string): Promise<Case | null> {
    const ruleId = alert.rule?.id;
    const agentId = alert.agent?.id;
    const alertId = alert.id;

    if (!ruleId || !agentId || !alertId) {
      throw new Error('Invalid alert payload: Missing rule.id, agent.id, or id');
    }

    const linkedAlert: LinkedAlert = {
      alert_id: alertId,
      index: alert._index || 'wazuh-alerts-*',
      rule_id: parseInt(ruleId, 10),
      rule_description: alert.rule?.description || 'Unknown Rule',
      rule_level: alert.rule?.level || 0,
      rule_groups: alert.rule?.groups || [],
      agent_id: agentId,
      agent_name: alert.agent?.name || 'Unknown Agent',
      timestamp: alert.timestamp || new Date().toISOString(),
      full_log: alert.full_log,
    };

    // Search for an unresolved case with the exact same rule and agent
    const searchBody = {
      query: {
        bool: {
          must: [
            { terms: { status: ['open', 'in_progress', 'waiting'] } },
            { term: { 'custom_fields.automated_rule_id.keyword': String(ruleId) } },
            { term: { 'custom_fields.automated_agent_id.keyword': String(agentId) } }
          ]
        }
      },
      size: 1,
      sort: [{ created_at: { order: 'desc' } }]
    };

    const searchResult = await OpenSearchService.searchDocuments(client, CASE_INDEX, searchBody);
    
    // IF DUPLICATE FOUND: Append alert and add comment
    if (searchResult.hits.length > 0) {
      const existingCase = searchResult.hits[0];
      const caseId = existingCase._id;
      
      // Avoid linking the exact same alert twice
      const alreadyLinked = existingCase._source.linked_alerts.some((a: any) => a.alert_id === alertId);
      if (alreadyLinked) {
         return { id: caseId, ...existingCase._source } as Case;
      }

      // Add automated comment
      const commentId = uuid();
      const comment: CaseComment = {
        comment_id: commentId,
        author: 'System Automation',
        content: `Duplicate alert detected (Rule ${ruleId} on Agent ${agentId}). Automatically linked.`,
        created_at: new Date().toISOString(),
      };

      const updateDoc = {
        linked_alerts: [...existingCase._source.linked_alerts, linkedAlert],
        comments: [...existingCase._source.comments, comment],
        updated_at: new Date().toISOString(),
      };

      await OpenSearchService.updateDocument(client, CASE_INDEX, caseId, updateDoc);
      return await CaseService.getCase(client, caseId);
    }

    // IF NO DUPLICATE: Create new case
    let severity: CaseSeverity = 'low';
    const level = alert.rule?.level || 0;
    if (level >= 12) severity = 'critical';
    else if (level >= 8) severity = 'high';
    else if (level >= 5) severity = 'medium';

    const payload: CreateCasePayload = {
      title: `[Automated] ${alert.rule?.description || 'Security Alert'}`,
      description: `Automated case created from Wazuh Alert.\n\nRule: ${ruleId}\nAgent: ${alert.agent?.name} (${agentId})\nLevel: ${level}\n\nLog: ${alert.full_log || 'N/A'}`,
      severity,
      priority: 'P2',
      category: 'other',
      tags: ['automated', `rule_${ruleId}`, `agent_${agentId}`],
    };

    const newCase = await CaseService.createCase(client, payload, user);
    
    // Add custom fields for deduplication tracking
    if (newCase.id) {
       await OpenSearchService.updateDocument(client, CASE_INDEX, newCase.id, {
         custom_fields: {
           automated_rule_id: String(ruleId),
           automated_agent_id: String(agentId)
         },
         linked_alerts: [linkedAlert]
       });
       return await CaseService.getCase(client, newCase.id);
    }
    
    return newCase;
  }
}
