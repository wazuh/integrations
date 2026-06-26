/*
 * Wazuh Case Management Plugin
 * Server-side plugin class
 *
 * Handles plugin lifecycle: registers routes, ensures OpenSearch indices exist.
 */

import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../src/core/server';
import { CASE_INDEX, CASE_COUNTER_INDEX } from '../common/constants';
import { caseMappings, counterMappings } from './saved_objects/case_mappings';
import { OpenSearchService } from './services/opensearch_service';
import { MonitorService } from './services/monitor_service';
import { defineRoutes } from './routes';

export class WazuhCaseManagementPlugin implements Plugin {
  private readonly logger: Logger;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public setup(core: CoreSetup) {
    this.logger.info('Wazuh Case Management plugin: Setting up');

    // Register all API routes
    const router = core.http.createRouter();
    defineRoutes(router, this.logger);

    return {};
  }

  public async start(core: CoreStart) {
    this.logger.info('Wazuh Case Management plugin: Starting');

    // Ensure required indices exist on startup
    try {
      const client = core.opensearch.client.asInternalUser;
      await this.ensureIndices(client);
      await MonitorService.ensureConfigIndex(client);
      MonitorService.start(client, this.logger);
    } catch (error) {
      this.logger.error(`Failed to initialize indices: ${error}`);
    }

    return {};
  }

  public stop() {
    MonitorService.stop();
    this.logger.info('Wazuh Case Management plugin: Stopped');
  }

  /**
   * Ensure that the cases index and counter index exist.
   * Called on startup and safe to call multiple times (idempotent).
   */
  private async ensureIndices(client: any): Promise<void> {
    // Create the main cases index
    const casesExist = await OpenSearchService.indexExists(client, CASE_INDEX);
    if (!casesExist) {
      this.logger.info(`Creating index: ${CASE_INDEX}`);
      await OpenSearchService.createIndex(client, CASE_INDEX, caseMappings);
      this.logger.info(`Index created: ${CASE_INDEX}`);
    } else {
      // Update mappings on existing index to add new fields (tlp, notes)
      try {
        await client.indices.putMapping({
          index: CASE_INDEX,
          body: { properties: { tlp: { type: 'keyword' }, notes: { type: 'text' } } },
        });
      } catch (e) {
        // Non-fatal — dynamic mapping will handle it if putMapping fails
        this.logger.warn(`Could not update mappings: ${e}`);
      }
    }

    // Create the counter index for auto-incrementing case IDs
    const counterExist = await OpenSearchService.indexExists(client, CASE_COUNTER_INDEX);
    if (!counterExist) {
      this.logger.info(`Creating index: ${CASE_COUNTER_INDEX}`);
      await OpenSearchService.createIndex(client, CASE_COUNTER_INDEX, counterMappings);
      this.logger.info(`Index created: ${CASE_COUNTER_INDEX}`);
    }
  }
}
