/*
 * Wazuh Case Management Plugin
 * Monitor Routes — CRUD for auto-case-creation monitor config
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { MonitorService } from '../services/monitor_service';

export function registerMonitorRoutes(router: IRouter, logger: Logger): void {
  // GET /api/wazuh-case-management/monitor — fetch config
  router.get(
    {
      path: '/api/wazuh-case-management/monitor',
      validate: false,
    },
    async (context, _request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const config = await MonitorService.getConfig(client);
        return response.ok({ body: config });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message } });
      }
    },
  );

  // PUT /api/wazuh-case-management/monitor — save config
  router.put(
    {
      path: '/api/wazuh-case-management/monitor',
      validate: {
        body: schema.object({
          enabled: schema.maybe(schema.boolean()),
          min_level: schema.maybe(schema.number({ min: 1, max: 15 })),
          interval_minutes: schema.maybe(schema.number({ min: 1, max: 1440 })),
          default_priority: schema.maybe(schema.string()),
          default_category: schema.maybe(schema.string()),
        }, { unknowns: 'allow' }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const saved = await MonitorService.saveConfig(client, request.body);
        logger.info(`Monitor config updated: enabled=${saved.enabled}, min_level=${saved.min_level}`);
        return response.ok({ body: saved });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message } });
      }
    },
  );

  // POST /api/wazuh-case-management/monitor/run — trigger immediate scan
  router.post(
    {
      path: '/api/wazuh-case-management/monitor/run',
      validate: false,
    },
    async (context, _request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const config = await MonitorService.getConfig(client);
        if (!config.enabled) {
          return response.badRequest({ body: { message: 'Monitor is disabled. Enable it first.' } });
        }
        const created = await MonitorService.scanAndCreateCases(client, config, logger);
        await MonitorService.saveConfig(client, {
          last_run_at: new Date().toISOString(),
          cases_created: (config.cases_created || 0) + created,
        });
        return response.ok({ body: { cases_created: created } });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message } });
      }
    },
  );
}
