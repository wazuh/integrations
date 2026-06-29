/*
 * Wazuh Case Management Plugin
 * Client-side entry point
 */

import { PluginInitializerContext } from 'opensearch-dashboards/public';
import { WazuhCaseManagementPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhCaseManagementPlugin();
}

export { WazuhCaseManagementPlugin as Plugin };
