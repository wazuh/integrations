/*
 * Wazuh Case Management Plugin
 * Server-side entry point
 *
 * This file exports the plugin class that OpenSearch Dashboards
 * discovers and instantiates during startup.
 */

import { PluginInitializerContext } from '../../../src/core/server';
import { WazuhCaseManagementPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhCaseManagementPlugin(initializerContext);
}

export { WazuhCaseManagementPlugin as Plugin };
