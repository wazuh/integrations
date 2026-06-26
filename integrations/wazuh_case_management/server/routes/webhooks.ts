/*
 * Wazuh Case Management Plugin
 * Webhook Routes — Handles incoming alerts from Wazuh Manager
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';

export function registerWebhookRoutes(router: IRouter, logger: Logger): void {
  router.post(
    {
      path: '/api/wazuh-case-management/webhook/alert',
      validate: {
        body: schema.object({}, { unknowns: 'allow' }),
      },
    },
    async (context, request, response) => {
      try {
        // Use asCurrentUser because the webhook will send Basic Auth credentials
        const client = context.core.opensearch.client.asCurrentUser;
        const alertJson = request.body;
        
        const result = await CaseService.handleAutomatedAlert(client, alertJson, 'wazuh-automation');
        return response.ok({ body: { success: true, case: result } });
      } catch (error: any) {
        logger.error(`Error processing webhook alert: ${error.message}`);
        return response.customError({
          statusCode: error.statusCode || 500,
          body: { message: error.message || 'Failed to process webhook alert' },
        });
      }
    },
  );
}
