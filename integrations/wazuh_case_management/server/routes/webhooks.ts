/*
 * Wazuh Case Management Plugin
 * Webhook Routes — Handles incoming alerts from Wazuh Manager
 */

import { timingSafeEqual } from 'crypto';
import { IRouter, Logger } from '../../../../src/core/server';
import { schema } from '@osd/config-schema';
import { CaseService } from '../services/case_service';

// Shared secret the Wazuh Manager (or whatever forwards alerts) must send back
// via the X-Wazuh-Webhook-Secret header. Configure it as an environment
// variable on the Dashboard process — see the plugin README for setup.
const WEBHOOK_SHARED_SECRET_ENV = 'WAZUH_CASE_MANAGEMENT_WEBHOOK_SECRET';

function secretsMatch(provided: string, expected: string): boolean {
  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);
  // timingSafeEqual throws on length mismatch, so compare lengths first —
  // this leaks length via timing but not the secret's content.
  if (providedBuf.length !== expectedBuf.length) {
    return false;
  }
  return timingSafeEqual(providedBuf, expectedBuf);
}

export function registerWebhookRoutes(router: IRouter, logger: Logger): void {
  const sharedSecret = process.env[WEBHOOK_SHARED_SECRET_ENV];
  if (!sharedSecret) {
    logger.warn(
      `${WEBHOOK_SHARED_SECRET_ENV} is not set — the alert webhook endpoint is accepting ` +
        'unauthenticated requests from anyone who can reach the Dashboard. Set this ' +
        'environment variable to require a shared secret (see README).',
    );
  }

  router.post(
    {
      path: '/api/wazuh-case-management/webhook/alert',
      validate: {
        body: schema.object(
          {
            id: schema.string(),
            _index: schema.maybe(schema.string()),
            timestamp: schema.maybe(schema.string()),
            full_log: schema.maybe(schema.string()),
            rule: schema.object(
              {
                id: schema.oneOf([schema.string(), schema.number()]),
                description: schema.maybe(schema.string()),
                level: schema.maybe(schema.number()),
                groups: schema.maybe(schema.arrayOf(schema.string())),
              },
              { unknowns: 'allow' },
            ),
            agent: schema.object(
              {
                id: schema.string(),
                name: schema.maybe(schema.string()),
              },
              { unknowns: 'allow' },
            ),
          },
          // Real Wazuh alerts carry many more fields than we act on — allow
          // the rest through untouched instead of hand-modeling every one.
          { unknowns: 'allow' },
        ),
      },
    },
    async (context, request, response) => {
      if (sharedSecret) {
        const provided = request.headers['x-wazuh-webhook-secret'];
        if (typeof provided !== 'string' || !secretsMatch(provided, sharedSecret)) {
          logger.warn('Rejected webhook alert: missing or invalid X-Wazuh-Webhook-Secret header');
          return response.forbidden({ body: { message: 'Invalid or missing webhook secret' } });
        }
      }

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
