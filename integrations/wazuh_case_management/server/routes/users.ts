/*
 * Wazuh Case Management Plugin
 * User Routes — current user info and user list for assignee selection
 */

import { IRouter, Logger } from '../../../../src/core/server';

/** Extract the authenticated username from the OpenSearch Security API */
export async function getCurrentUsername(client: any): Promise<string> {
  try {
    const result = await client.transport.request({
      method: 'GET',
      path: '/_plugins/_security/api/account',
    });
    return result.body?.user_name || 'unknown';
  } catch (_e1) {
    try {
      const result = await client.transport.request({
        method: 'GET',
        path: '/_opendistro/_security/api/account',
      });
      return result.body?.user_name || 'unknown';
    } catch (_e2) {
      return 'unknown';
    }
  }
}

// Built-in system accounts that should never appear as case assignees
const SYSTEM_USERS = new Set([
  'logstash',
  'snapshotrestore',
  'kibanaserver',
  'kibanaro',
  'kibana',
  'readall',
  'anomalyadmin',
  'anomaly_ad_plugin',
  'cross_cluster_replication',
  'wazuh',
  'wazuh-wui',
  'filebeat',
  'metricbeat',
  'beats',
  'alerting',
  'reports',
  'asynchronous_search',
  'ml',
  'opensearch',
]);

function isSystemUser(username: string): boolean {
  const lower = username.toLowerCase();
  return (
    SYSTEM_USERS.has(lower) ||
    lower.startsWith('_') ||
    lower.startsWith('kibana') ||
    lower.startsWith('wazuh-') ||
    lower.startsWith('opensearch-') ||
    lower.endsWith('server') ||
    lower.endsWith('admin') && lower !== 'admin'
  );
}

/** Fetch all internal users from the OpenSearch Security API, excluding system accounts */
async function getInternalUsers(client: any): Promise<string[]> {
  try {
    const result = await client.transport.request({
      method: 'GET',
      path: '/_plugins/_security/api/internalusers',
    });
    return Object.keys(result.body || {}).filter((u) => !isSystemUser(u));
  } catch (_e1) {
    try {
      const result = await client.transport.request({
        method: 'GET',
        path: '/_opendistro/_security/api/internalusers',
      });
      return Object.keys(result.body || {}).filter((u) => !isSystemUser(u));
    } catch (_e2) {
      return [];
    }
  }
}

export function registerUserRoutes(router: IRouter, logger: Logger): void {
  // ─── GET CURRENT USER ───────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/me',
      validate: false,
    },
    async (context, _request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const username = await getCurrentUsername(client);
        return response.ok({ body: { username } });
      } catch (error: any) {
        logger.error(`Error getting current user: ${error.message}`);
        return response.ok({ body: { username: 'unknown' } });
      }
    },
  );

  // ─── LIST USERS ─────────────────────────────────────────────
  router.get(
    {
      path: '/api/wazuh-case-management/users',
      validate: false,
    },
    async (context, _request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const users = await getInternalUsers(client);
        return response.ok({ body: { users } });
      } catch (error: any) {
        logger.error(`Error listing users: ${error.message}`);
        return response.ok({ body: { users: [] } });
      }
    },
  );
}
