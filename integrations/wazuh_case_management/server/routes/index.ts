/*
 * Wazuh Case Management Plugin
 * Route Registration Hub
 *
 * Registers all API route groups with the OpenSearch Dashboards HTTP router.
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { registerCaseRoutes } from './cases';
import { registerCommentRoutes } from './comments';
import { registerAlertRoutes } from './alerts';
import { registerAnalyticsRoutes } from './analytics';
import { registerWebhookRoutes } from './webhooks';
import { registerUserRoutes } from './users';
import { registerDebugRoutes } from './debug';
import { registerMonitorRoutes } from './monitor';

/**
 * Define all plugin routes.
 * Called from the server-side plugin setup().
 */
export function defineRoutes(router: IRouter, logger: Logger): void {
  registerCaseRoutes(router, logger);
  registerCommentRoutes(router, logger);
  registerAlertRoutes(router, logger);
  registerAnalyticsRoutes(router, logger);
  registerWebhookRoutes(router, logger);
  registerUserRoutes(router, logger);
  registerDebugRoutes(router, logger);
  registerMonitorRoutes(router, logger);

  logger.info('All API routes registered');
}
