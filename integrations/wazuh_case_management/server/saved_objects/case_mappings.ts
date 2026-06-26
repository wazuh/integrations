/*
 * Wazuh Case Management Plugin
 * OpenSearch index mappings for case management indices
 *
 * Defines the index settings and field mappings for:
 * - The main cases index (wazuh-case-management-cases)
 * - The counter index (wazuh-case-management-counter) for auto-incrementing IDs
 */

/**
 * Mappings for the main cases index.
 * Every field from the Case interface is mapped with an appropriate OpenSearch type.
 * Nested objects (linked_alerts, observables, comments, activity_log) use the
 * "nested" type so they can be queried independently.
 */
export const caseMappings = {
  settings: {
    number_of_shards: 1,
    number_of_replicas: 1,
    'index.mapping.total_fields.limit': 2000,
  },
  mappings: {
    properties: {
      // ─── Core fields ──────────────────────────────────
      case_id: { type: 'keyword' },
      title: { type: 'text', fields: { keyword: { type: 'keyword' } } },
      description: { type: 'text' },
      status: { type: 'keyword' },
      severity: { type: 'keyword' },
      priority: { type: 'keyword' },
      category: { type: 'keyword' },
      tags: { type: 'keyword' },
      assignee: { type: 'keyword' },
      tlp: { type: 'keyword' },
      notes: { type: 'text' },

      // ─── Audit fields ────────────────────────────────
      created_by: { type: 'keyword' },
      created_at: { type: 'date' },
      updated_at: { type: 'date' },
      closed_at: { type: 'date' },

      // ─── Resolution ───────────────────────────────────
      resolution_summary: { type: 'text' },
      time_to_resolve_ms: { type: 'long' },

      // ─── Related cases ────────────────────────────────
      related_cases: { type: 'keyword' },

      // ─── Custom fields ────────────────────────────────
      custom_fields: { type: 'object', enabled: false },

      // ─── Linked Alerts (nested for independent queries) ─
      linked_alerts: {
        type: 'nested',
        properties: {
          alert_id: { type: 'keyword' },
          index: { type: 'keyword' },
          rule_id: { type: 'integer' },
          rule_description: { type: 'text', fields: { keyword: { type: 'keyword' } } },
          rule_level: { type: 'integer' },
          rule_groups: { type: 'keyword' },
          agent_id: { type: 'keyword' },
          agent_name: { type: 'keyword' },
          timestamp: { type: 'date' },
          manager_name: { type: 'keyword' },
          full_log: { type: 'text' },
        },
      },

      // ─── Observables (nested) ─────────────────────────
      observables: {
        type: 'nested',
        properties: {
          id: { type: 'keyword' },
          type: { type: 'keyword' },
          value: { type: 'keyword' },
          description: { type: 'text' },
          is_ioc: { type: 'boolean' },
          added_at: { type: 'date' },
          added_by: { type: 'keyword' },
        },
      },

      // ─── Comments (nested) ────────────────────────────
      comments: {
        type: 'nested',
        properties: {
          comment_id: { type: 'keyword' },
          author: { type: 'keyword' },
          content: { type: 'text' },
          created_at: { type: 'date' },
          updated_at: { type: 'date' },
        },
      },

      // ─── Activity Log (nested) ────────────────────────
      activity_log: {
        type: 'nested',
        properties: {
          id: { type: 'keyword' },
          action: { type: 'keyword' },
          user: { type: 'keyword' },
          timestamp: { type: 'date' },
          details: { type: 'object', enabled: false },
        },
      },
    },
  },
};

/**
 * Mappings for the counter index.
 * Stores a single document with the current counter value,
 * used to generate monotonically increasing case IDs.
 */
export const counterMappings = {
  settings: {
    number_of_shards: 1,
    number_of_replicas: 1,
  },
  mappings: {
    properties: {
      counter_name: { type: 'keyword' },
      current_value: { type: 'long' },
    },
  },
};
