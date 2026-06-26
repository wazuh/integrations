/*
 * Wazuh Case Management Plugin
 * Comment Routes — Add and delete comments on cases
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';
import { getCurrentUsername } from './users';

export function registerCommentRoutes(router: IRouter, logger: Logger): void {
  // ─── ADD COMMENT ────────────────────────────────────────────
  router.post(
    {
      path: '/api/wazuh-case-management/cases/{id}/comments',
      validate: {
        params: schema.object({
          id: schema.string(),
        }),
        body: schema.object({
          content: schema.string({ minLength: 1, maxLength: 10000 }),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.addComment(
          client,
          request.params.id,
          request.body.content,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error adding comment: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to add comment' },
        });
      }
    },
  );

  // ─── DELETE COMMENT ─────────────────────────────────────────
  router.delete(
    {
      path: '/api/wazuh-case-management/cases/{id}/comments/{commentId}',
      validate: {
        params: schema.object({
          id: schema.string(),
          commentId: schema.string(),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const user = await getCurrentUsername(client);
        const updated = await CaseService.deleteComment(
          client,
          request.params.id,
          request.params.commentId,
          user,
        );
        if (!updated) {
          return response.notFound({ body: { message: 'Case not found' } });
        }
        return response.ok({ body: updated });
      } catch (error: any) {
        logger.error(`Error deleting comment: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to delete comment' },
        });
      }
    },
  );
}
