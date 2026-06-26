/*
 * Wazuh Case Management Plugin
 * Client plugin class — registers the application with OSD
 */

import {
  CoreSetup,
  CoreStart,
  Plugin,
  AppMountParameters,
} from 'opensearch-dashboards/public';
import { PLUGIN_ID, PLUGIN_NAME } from '../common/constants';
import {
  WazuhCaseManagementPluginSetup,
  WazuhCaseManagementPluginStart,
} from './types';

export class WazuhCaseManagementPlugin
  implements Plugin<WazuhCaseManagementPluginSetup, WazuhCaseManagementPluginStart>
{
  public setup(core: CoreSetup): WazuhCaseManagementPluginSetup {
    // Register the application
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      category: {
        id: 'wazuh_case_manager',
        label: 'Wazuh case manager',
        euiIconType: 'securityApp',
        order: 1000,
      },
      order: 5000,
      async mount(params: AppMountParameters) {
        // Lazy-load application bundle
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });

    return {};
  }

  public start(_core: CoreStart): WazuhCaseManagementPluginStart {
    return {};
  }

  public stop() {}
}
