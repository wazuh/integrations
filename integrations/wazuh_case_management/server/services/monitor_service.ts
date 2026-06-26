/*
 * Wazuh Case Management Plugin
 * Monitor Service — background polling for automatic case creation
 */

import { Logger } from '../../../../../src/core/server';
import { MONITOR_CONFIG_INDEX, WAZUH_ALERTS_INDEX_PATTERN, CASE_INDEX } from '../../common/constants';
import { CaseService } from './case_service';

export interface MonitorConfig {
  enabled: boolean;
  min_level: number;
  interval_minutes: number;
  default_priority: string;
  default_category: string;
  last_run_at: string | null;
  last_processed_timestamp: string | null;
  cases_created: number;
  updated_at: string;
}

const CONFIG_DOC_ID = 'monitor_config';

const DEFAULT_CONFIG: MonitorConfig = {
  enabled: false,
  min_level: 10,
  interval_minutes: 5,
  default_priority: 'P2',
  default_category: 'other',
  last_run_at: null,
  last_processed_timestamp: null,
  cases_created: 0,
  updated_at: new Date().toISOString(),
};

export class MonitorService {
  private static intervalHandle: ReturnType<typeof setInterval> | null = null;
  private static running = false;

  // ── Config CRUD ──────────────────────────────────────────────

  static async ensureConfigIndex(client: any): Promise<void> {
    try {
      const { body } = await client.indices.exists({ index: MONITOR_CONFIG_INDEX });
      if (!body) {
        await client.indices.create({
          index: MONITOR_CONFIG_INDEX,
          body: {
            settings: { number_of_shards: 1, number_of_replicas: 1 },
            mappings: {
              properties: {
                enabled: { type: 'boolean' },
                min_level: { type: 'integer' },
                interval_minutes: { type: 'integer' },
                default_priority: { type: 'keyword' },
                default_category: { type: 'keyword' },
                last_run_at: { type: 'date' },
                last_processed_timestamp: { type: 'date' },
                cases_created: { type: 'long' },
                updated_at: { type: 'date' },
              },
            },
          },
        });
      }
    } catch (e) {}
  }

  static async getConfig(client: any): Promise<MonitorConfig> {
    try {
      const { body } = await client.get({ index: MONITOR_CONFIG_INDEX, id: CONFIG_DOC_ID });
      return body._source as MonitorConfig;
    } catch (e: any) {
      if (e?.statusCode === 404 || e?.meta?.statusCode === 404) {
        return { ...DEFAULT_CONFIG };
      }
      throw e;
    }
  }

  static async saveConfig(client: any, updates: Partial<MonitorConfig>): Promise<MonitorConfig> {
    const existing = await MonitorService.getConfig(client);
    const merged: MonitorConfig = { ...existing, ...updates, updated_at: new Date().toISOString() };
    await client.index({
      index: MONITOR_CONFIG_INDEX,
      id: CONFIG_DOC_ID,
      body: merged,
      refresh: 'wait_for',
    });
    return merged;
  }

  // ── Background Polling ───────────────────────────────────────

  static start(client: any, logger: Logger): void {
    if (MonitorService.intervalHandle) return;
    MonitorService.intervalHandle = setInterval(async () => {
      try {
        await MonitorService.tick(client, logger);
      } catch (e: any) {
        logger.warn(`Monitor tick error: ${e.message}`);
      }
    }, 60_000);
    logger.info('Auto-monitor background job started (checking every 60s)');
  }

  static stop(): void {
    if (MonitorService.intervalHandle) {
      clearInterval(MonitorService.intervalHandle);
      MonitorService.intervalHandle = null;
    }
  }

  static async tick(client: any, logger: Logger): Promise<void> {
    const config = await MonitorService.getConfig(client);
    if (!config.enabled) return;

    const now = Date.now();
    const intervalMs = (config.interval_minutes || 5) * 60_000;
    const lastRun = config.last_run_at ? new Date(config.last_run_at).getTime() : 0;
    if (now - lastRun < intervalMs) return;

    if (MonitorService.running) return;
    MonitorService.running = true;

    try {
      logger.info(`Auto-monitor: scanning for rule.level >= ${config.min_level}, since=${config.last_processed_timestamp || 'beginning'}`);
      const created = await MonitorService.scanAndCreateCases(client, config, logger);
      await MonitorService.saveConfig(client, {
        last_run_at: new Date().toISOString(),
        cases_created: (config.cases_created || 0) + created,
      });
      logger.info(`Auto-monitor: scan done, created=${created}`);
    } finally {
      MonitorService.running = false;
    }
  }

  // ── Alert scanning ───────────────────────────────────────────

  static async scanAndCreateCases(
    client: any,
    config: MonitorConfig,
    logger: Logger,
  ): Promise<number> {
    // Default: look back 24 hours on first run so existing alerts are picked up
    const since = config.last_processed_timestamp
      || new Date(Date.now() - 24 * 60 * 60_000).toISOString();

    // FIX 1: Wazuh alerts use either "timestamp" or "@timestamp" depending on version.
    // Query both fields with a should clause so alerts are found regardless.
    const searchBody = {
      query: {
        bool: {
          must: [
            { range: { 'rule.level': { gte: Number(config.min_level) } } },
          ],
          should: [
            { range: { timestamp:   { gt: since } } },
            { range: { '@timestamp': { gt: since } } },
          ],
          minimum_should_match: 1,
        },
      },
      sort: [
        { timestamp: { order: 'asc', unmapped_type: 'date' } },
      ],
      size: 100,
    };

    let hits: any[] = [];
    try {
      const { body: result } = await client.search({
        index: WAZUH_ALERTS_INDEX_PATTERN,
        body: searchBody,
        ignore_unavailable: true,
      });
      hits = result.hits?.hits || [];
      logger.info(`Auto-monitor: found ${hits.length} alert(s) with level >= ${config.min_level} since ${since}`);
    } catch (e: any) {
      logger.warn(`Auto-monitor: alert search failed — ${e.message}`);
      return 0;
    }

    if (hits.length === 0) {
      await MonitorService.saveConfig(client, {
        last_processed_timestamp: new Date().toISOString(),
      });
      return 0;
    }

    let created = 0;
    let latestTimestamp = since;

    // FIX 2: Collect alert IDs already linked in open cases so we can deduplicate
    // without relying on custom_fields (which has enabled:false and is not indexed).
    const openCaseAlertIds = await MonitorService.getLinkedAlertIdsFromOpenCases(client, logger);

    for (const hit of hits) {
      const alert = hit._source;
      const alertId = hit._id;

      // Pick timestamp from whichever field exists
      const alertTimestamp: string =
        alert?.timestamp || alert?.['@timestamp'] || new Date().toISOString();

      if (alertTimestamp > latestTimestamp) latestTimestamp = alertTimestamp;

      // Skip alerts already linked to an open case
      if (openCaseAlertIds.has(alertId)) {
        logger.info(`Auto-monitor: alert ${alertId} already linked — skipping`);
        continue;
      }

      const ruleDescription = alert?.rule?.description || 'Security Alert';
      const ruleLevel       = Number(alert?.rule?.level) || 0;
      const ruleId          = String(alert?.rule?.id || '');
      const agentId         = String(alert?.agent?.id || '');

      try {
        let severity = 'low';
        if (ruleLevel >= 13) severity = 'critical';
        else if (ruleLevel >= 10) severity = 'high';
        else if (ruleLevel >= 7)  severity = 'medium';

        const newCase = await CaseService.createCase(
          client,
          {
            title: 'PLACEHOLDER',
            description: MonitorService.buildDescription(alert, hit._index),
            severity: severity as any,
            priority: config.default_priority as any,
            category: config.default_category as any,
            tags: ['auto-created', `level-${ruleLevel}`, ...(ruleId ? [`rule-${ruleId}`] : [])],
          },
          'auto-monitor',
        );

        const caseDocId      = newCase.id!;
        const numericSuffix  = newCase.case_id?.split('-').pop() || '0000';
        const prettyTitle    = `Wazuh-case-${numericSuffix}: ${ruleDescription}`;
        const linkedAlert    = MonitorService.buildLinkedAlert(hit);

        await client.update({
          index: CASE_INDEX,
          id: caseDocId,
          body: {
            doc: {
              title: prettyTitle,
              linked_alerts: [linkedAlert],
              // FIX 3: store dedup keys as indexed tags instead of custom_fields
              tags: ['auto-created', `level-${ruleLevel}`, `auto-alert-${alertId}`],
              updated_at: new Date().toISOString(),
            },
          },
          retry_on_conflict: 3,
        });

        // Add to local set so we don't create duplicates within the same scan batch
        openCaseAlertIds.add(alertId);

        created++;
        logger.info(`Auto-monitor: created ${prettyTitle}`);
      } catch (e: any) {
        logger.warn(`Auto-monitor: failed to process alert ${alertId} — ${e.message}`);
      }
    }

    await MonitorService.saveConfig(client, {
      last_processed_timestamp: latestTimestamp,
    });

    return created;
  }

  /**
   * Returns the set of alert IDs already linked inside any open/in-progress/waiting case.
   * Used for deduplication instead of custom_fields (which is not indexed).
   */
  private static async getLinkedAlertIdsFromOpenCases(
    client: any,
    logger: Logger,
  ): Promise<Set<string>> {
    const ids = new Set<string>();
    try {
      const { body: result } = await client.search({
        index: CASE_INDEX,
        body: {
          query: {
            bool: {
              must: [
                { terms: { status: ['open', 'in_progress', 'waiting'] } },
                { term: { tags: 'auto-created' } },
              ],
            },
          },
          _source: ['linked_alerts'],
          size: 500,
        },
      });
      for (const hit of (result.hits?.hits || [])) {
        for (const la of (hit._source?.linked_alerts || [])) {
          if (la.alert_id) ids.add(la.alert_id);
        }
      }
    } catch (e: any) {
      logger.warn(`Auto-monitor: could not fetch open case alert IDs — ${e.message}`);
    }
    return ids;
  }

  private static buildLinkedAlert(hit: any): any {
    const alert = hit._source;
    return {
      alert_id:         hit._id,
      index:            hit._index || WAZUH_ALERTS_INDEX_PATTERN,
      rule_id:          parseInt(alert?.rule?.id || '0', 10),
      rule_description: alert?.rule?.description || '',
      rule_level:       alert?.rule?.level || 0,
      rule_groups:      alert?.rule?.groups || [],
      agent_id:         alert?.agent?.id || '',
      agent_name:       alert?.agent?.name || '',
      timestamp:        alert?.timestamp || alert?.['@timestamp'] || new Date().toISOString(),
      full_log:         alert?.full_log || '',
    };
  }

  private static buildDescription(alert: any, index: string): string {
    const ruleId    = alert?.rule?.id || 'N/A';
    const ruleDesc  = alert?.rule?.description || 'N/A';
    const ruleLevel = alert?.rule?.level ?? 'N/A';
    const agentName = alert?.agent?.name || 'Unknown';
    const agentId   = alert?.agent?.id || 'N/A';
    const groups    = (alert?.rule?.groups || []).join(', ') || 'N/A';
    const rawTs     = alert?.timestamp || alert?.['@timestamp'];
    const timestamp = rawTs
      ? new Date(rawTs).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'medium' })
      : 'N/A';

    const lines: string[] = [
      `This case was automatically created by the Wazuh Case Monitor.`,
      ``,
      `## Alert Details`,
      ``,
      `- **Rule ID:** ${ruleId}`,
      `- **Description:** ${ruleDesc}`,
      `- **Level:** ${ruleLevel}`,
      `- **Groups:** ${groups}`,
      `- **Agent:** ${agentName} (ID: ${agentId})`,
      `- **Detected:** ${timestamp}`,
    ];

    if (alert?.full_log) {
      const log = String(alert.full_log).trim().substring(0, 600);
      lines.push(``, `## Raw Log`, ``, `\`\`\``, log, `\`\`\``);
    }

    return lines.join('\n');
  }
}
