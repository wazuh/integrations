/*
 * Wazuh Case Management Plugin
 * Analytics Routes — Dashboard stats and trend data
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';

export function registerAnalyticsRoutes(router: IRouter, logger: Logger): void {
  // ─── ANALYTICS SUMMARY ─────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/analytics/summary',
      validate: false,
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const summary = await CaseService.getAnalyticsSummary(client);
        return response.ok({ body: summary });
      } catch (error: any) {
        logger.error(`Error getting analytics summary: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to get analytics' },
        });
      }
    },
  );

  // ─── CASE TRENDS ───────────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/analytics/trends',
      validate: {
        query: schema.object({
          days: schema.maybe(schema.number({ min: 7, max: 365, defaultValue: 30 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const trends = await CaseService.getCaseTrends(client, request.query.days);
        return response.ok({ body: { trends } });
      } catch (error: any) {
        logger.error(`Error getting case trends: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to get trends' },
        });
      }
    },
  );
}
