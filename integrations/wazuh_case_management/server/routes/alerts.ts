/*
 * Wazuh Case Management Plugin
 * Alert & Observable Routes — Link/unlink alerts, search Wazuh alerts, manage observables
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';
import { getCurrentUsername } from './users';

export function registerAlertRoutes(router: IRouter, logger: Logger): void {
  // ─── LINK ALERT TO CASE ─────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/alerts',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          alert_id: schema.string(),
          index: schema.string(),
          rule_id: schema.number(),
          rule_description: schema.string(),
          rule_level: schema.number(),
          rule_groups: schema.arrayOf(schema.string(), { defaultValue: [] }),
          agent_id: schema.string(),
          agent_name: schema.string(),
          timestamp: schema.string(),
          manager_name: schema.maybe(schema.string()),
          full_log: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.linkAlert(
          client,
          request.params.id,
          request.body,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error linking alert: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to link alert' },
        });
      }
    },
  );

  // ─── UNLINK ALERT FROM CASE ─────────────────────────────────
  router.delete(
    {
      path: '/api/wazuh-case-management/cases/{id}/alerts/{alertId}',
      validate: {
        params: schema.object({
          id: schema.string(),
          alertId: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.unlinkAlert(
          client,
          request.params.id,
          request.params.alertId,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error unlinking alert: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to unlink alert' },
        });
      }
    },
  );

  // ─── SEARCH WAZUH ALERTS ───────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/alerts/search',
      validate: {
        query: schema.object({
          search: schema.maybe(schema.string()),
          agent_id: schema.maybe(schema.string()),
          rule_id: schema.maybe(schema.number()),
          level_min: schema.maybe(schema.number()),
          level_max: schema.maybe(schema.number()),
          from: schema.maybe(schema.string()),
          to: schema.maybe(schema.string()),
          size: schema.maybe(schema.number({ min: 1, max: 100, defaultValue: 50 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result = await CaseService.searchAlerts(client, request.query);
        return response.ok({ body: result });
      } catch (error: any) {
        logger.error(`Error searching alerts: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to search alerts' },
        });
      }
    },
  );

  // ─── ADD OBSERVABLE ─────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/observables',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          type: schema.string(),
          value: schema.string({ minLength: 1 }),
          description: schema.maybe(schema.string()),
          is_ioc: schema.maybe(schema.boolean()),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.addObservable(
          client,
          request.params.id,
          { ...request.body, is_ioc: request.body.is_ioc ?? false },
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error adding observable: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to add observable' },
        });
      }
    },
  );

  // ─── REMOVE OBSERVABLE ──────────────────────────────────────
  router.delete(
    {
      path: '/api/wazuh-case-management/cases/{id}/observables/{observableId}',
      validate: {
        params: schema.object({
          id: schema.string(),
          observableId: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.removeObservable(
          client,
          request.params.id,
          request.params.observableId,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error removing observable: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to remove observable' },
        });
      }
    },
  );
}
