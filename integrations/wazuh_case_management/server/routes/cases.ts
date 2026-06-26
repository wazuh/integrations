/*
 * Wazuh Case Management Plugin
 * Case Routes — CRUD operations for cases
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';
import { getCurrentUsername } from './users';

export function registerCaseRoutes(router: IRouter, logger: Logger): void {
  // ─── LIST CASES ─────────────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/cases',
      validate: {
        query: schema.object({
          page: schema.maybe(schema.number({ min: 1, defaultValue: 1 })),
          per_page: schema.maybe(schema.number({ min: 1, max: 100, defaultValue: 20 })),
          sort_field: schema.maybe(schema.string({ defaultValue: 'created_at' })),
          sort_order: schema.maybe(schema.oneOf([schema.literal('asc'), schema.literal('desc')], { defaultValue: 'desc' })),
          status: schema.maybe(schema.string()),
          severity: schema.maybe(schema.string()),
          priority: schema.maybe(schema.string()),
          category: schema.maybe(schema.string()),
          assignee: schema.maybe(schema.string()),
          search: schema.maybe(schema.string()),
          tags: schema.maybe(schema.string()),
          created_from: schema.maybe(schema.string()),
          created_to: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result = await CaseService.listCases(client, request.query);
        return response.ok({ body: result });
      } catch (error: any) {
        logger.error(`Error listing cases: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to list cases' },
        });
      }
    },
  );

  // ─── GET CASE BY ID ─────────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/cases/{id}',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const caseDoc = await CaseService.getCase(client, request.params.id);
        if (!caseDoc) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: caseDoc });
      } catch (error: any) {
        logger.error(`Error getting case: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to get case' },
        });
      }
    },
  );

  // ─── CREATE CASE ────────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases',
      validate: {
        body: schema.object({
          title: schema.string({ minLength: 1, maxLength: 500 }),
          description: schema.maybe(schema.string()),
          severity: schema.string(),
          priority: schema.string(),
          category: schema.string(),
          tlp: schema.maybe(schema.string()),
          tags: schema.maybe(schema.arrayOf(schema.string())),
          assignee: schema.maybe(schema.nullable(schema.string())),
        }, { unknowns: 'allow' }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const newCase = await CaseService.createCase(client, request.body, user);
        return response.ok({ body: newCase });
      } catch (error: any) {
        const status = error.statusCode ?? error.meta?.statusCode ?? 500;
        const detail = error.meta?.body ? JSON.stringify(error.meta.body) : '';
        logger.error(`Error creating case [${status}]: ${error.message} ${detail}`);
        return response.customError({
          statusCode: status >= 400 && status < 600 ? status : 500,
          body: { message: `${error.message}${detail ? ` — ${detail}` : ''}` },
        });
      }
    },
  );

  // ─── UPDATE CASE ────────────────────────────────────────────
  router.put(
    {
      path: '/api/wazuh-case-management/cases/{id}',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          title: schema.maybe(schema.string({ minLength: 1, maxLength: 500 })),
          description: schema.maybe(schema.string()),
          severity: schema.maybe(schema.string()),
          priority: schema.maybe(schema.string()),
          category: schema.maybe(schema.string()),
          tlp: schema.maybe(schema.string()),
          tags: schema.maybe(schema.arrayOf(schema.string())),
          assignee: schema.maybe(schema.nullable(schema.string())),
          resolution_summary: schema.maybe(schema.nullable(schema.string())),
        }, { unknowns: 'allow' }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.updateCase(client, request.params.id, request.body, user);
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error updating case: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to update case' },
        });
      }
    },
  );

  // ─── DELETE CASE ────────────────────────────────────────────
  router.delete(
    {
      path: '/api/wazuh-case-management/cases/{id}',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        if (user !== 'admin') {
          return response.forbidden({ body: { message: 'Only admin users can delete cases' } });
        }
        const deleted = await CaseService.deleteCase(client, request.params.id);
        if (!deleted) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: { message: 'Case deleted successfully' } });
      } catch (error: any) {
        logger.error(`Error deleting case: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to delete case' },
        });
      }
    },
  );

  // ─── CHANGE STATUS ──────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/status',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          status: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const result = await CaseService.changeStatus(
          client,
          request.params.id,
          request.body.status,
          user,
        );
        if (!result.success) {
          return response.badRequest({ body: { message: result.error } });
        }
        return response.ok({ body: result.case });
      } catch (error: any) {
        logger.error(`Error changing case status: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to change status' },
        });
      }
    },
  );

  // ─── ASSIGN CASE ────────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/assign',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          assignee: schema.nullable(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.assignCase(
          client,
          request.params.id,
          request.body.assignee,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error assigning case: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to assign case' },
        });
      }
    },
  );

  // ─── ADD TASK ────────────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/tasks',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          title: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.addTask(client, request.params.id, request.body.title, user);
        return response.ok({ body: updated });
      } catch (error: any) {
        return response.customError({ statusCode: 500, body: { message: error.message } });
      }
    }
  );

  // ─── TOGGLE TASK ─────────────────────────────────────────────
  router.patch(
    {
      path: '/api/wazuh-case-management/cases/{id}/tasks/{taskId}',
      validate: {
        params: schema.object({
          id: schema.string(),
          taskId: schema.string(),
        }),
        body: schema.object({
          completed: schema.boolean(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.toggleTask(client, request.params.id, request.params.taskId, request.body.completed, user);
        return response.ok({ body: updated });
      } catch (error: any) {
        return response.customError({ statusCode: 500, body: { message: error.message } });
      }
    }
  );

  // ─── REMOVE TASK ─────────────────────────────────────────────
  router.delete(
    {
      path: '/api/wazuh-case-management/cases/{id}/tasks/{taskId}',
      validate: {
        params: schema.object({
          id: schema.string(),
          taskId: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.removeTask(client, request.params.id, request.params.taskId, user);
        return response.ok({ body: updated });
      } catch (error: any) {
        return response.customError({ statusCode: 500, body: { message: error.message } });
      }
    }
  );

  // ─── SAVE NOTES ──────────────────────────────────────────────
  router.patch(
    {
      path: '/api/wazuh-case-management/cases/{id}/notes',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          notes: schema.string({ defaultValue: '' }),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.updateNotes(client, request.params.id, request.body.notes, user);
        return response.ok({ body: updated });
      } catch (error: any) {
        return response.customError({ statusCode: 500, body: { message: error.message } });
      }
    }
  );
}
