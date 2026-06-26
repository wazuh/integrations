/*
 * Wazuh Case Management Plugin
 * OpenSearch Service — Low-level OpenSearch client operations
 *
 * Provides reusable CRUD helpers, search, aggregation, and counter management
 * that wrap the OpenSearch client obtained from the request context.
 * This service is stateless — every method receives the client explicitly.
 */

import { CASE_COUNTER_INDEX } from '../../common/constants';

/** A minimal interface representing the scoped OpenSearch client */
type OpenSearchClient = {
  indices: {
    exists: (params: any) => Promise<{ body: boolean }>;
    create: (params: any) => Promise<any>;
  };
  index: (params: any) => Promise<any>;
  get: (params: any) => Promise<any>;
  update: (params: any) => Promise<any>;
  delete: (params: any) => Promise<any>;
  search: (params: any) => Promise<any>;
  count: (params: any) => Promise<any>;
};

/**
 * OpenSearchService — thin wrapper around the scoped OpenSearch client.
 *
 * Design notes:
 *  - Every public method is static so callers don't need to manage instances.
 *  - The `client` parameter must be `context.core.opensearch.client.asCurrentUser`.
 */
export class OpenSearchService {
  // ──────────────────────────────────────────────────────────────
  // Index operations
  // ──────────────────────────────────────────────────────────────

  /** Check whether an index already exists */
  static async indexExists(client: any, index: string): Promise<boolean> {
    try {
      const { body } = await client.indices.exists({ index });
      return body as boolean;
    } catch (error) {
      // 404 means it does not exist — not an error
      return false;
    }
  }

  /** Create an index with the given body (settings + mappings) */
  static async createIndex(client: any, index: string, body: any): Promise<void> {
    await client.indices.create({ index, body });
  }

  // ──────────────────────────────────────────────────────────────
  // Document CRUD
  // ──────────────────────────────────────────────────────────────

  /**
   * Index (create/overwrite) a document.
   * If `id` is provided the document is stored under that _id, otherwise
   * OpenSearch auto-generates one.
   */
  static async createDocument(
    client: any,
    index: string,
    body: any,
    id?: string,
  ): Promise<{ _id: string }> {
    const params: any = { index, body, refresh: 'wait_for' };
    if (id) params.id = id;
    const { body: result } = await client.index(params);
    return { _id: result._id };
  }

  /** Retrieve a single document by _id */
  static async getDocument(client: any, index: string, id: string): Promise<any> {
    try {
      const { body } = await client.get({ index, id });
      return { _id: body._id, _source: body._source };
    } catch (error: any) {
      if (error?.statusCode === 404 || error?.meta?.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  /** Partially update a document (merge fields) */
  static async updateDocument(
    client: any,
    index: string,
    id: string,
    doc: any,
  ): Promise<void> {
    await client.update({
      index,
      id,
      body: { doc },
      refresh: 'wait_for',
      retry_on_conflict: 3,
    });
  }

  /** Delete a document by _id */
  static async deleteDocument(client: any, index: string, id: string): Promise<boolean> {
    try {
      await client.delete({ index, id, refresh: 'wait_for' });
      return true;
    } catch (error: any) {
      if (error?.statusCode === 404 || error?.meta?.statusCode === 404) {
        return false;
      }
      throw error;
    }
  }

  // ──────────────────────────────────────────────────────────────
  // Search & Aggregation
  // ──────────────────────────────────────────────────────────────

  /**
   * Perform a search query against an index.
   * Returns the raw hits array together with the total count.
   */
  static async searchDocuments(
    client: any,
    index: string,
    body: any,
  ): Promise<{ hits: any[]; total: number }> {
    const { body: result } = await client.search({ index, body });
    const total =
      typeof result.hits.total === 'number'
        ? result.hits.total
        : result.hits.total?.value ?? 0;
    return {
      hits: result.hits.hits,
      total,
    };
  }

  /**
   * Run an aggregation-only query (size=0).
   * Returns the raw aggregations object.
   */
  static async aggregateDocuments(
    client: any,
    index: string,
    body: any,
  ): Promise<any> {
    const { body: result } = await client.search({ index, body: { size: 0, ...body } });
    return result.aggregations ?? {};
  }

  // ──────────────────────────────────────────────────────────────
  // Counter management for case ID generation
  // ──────────────────────────────────────────────────────────────

  /** The well-known document ID that holds the case counter */
  private static readonly COUNTER_DOC_ID = 'case_id_counter';

  /**
   * Atomically increment-and-return the case counter.
   * Uses optimistic concurrency control (seq_no + primary_term) instead of
   * Painless scripts, which may be disabled in Wazuh's OpenSearch deployment.
   */
  static async getNextCounterValue(client: any): Promise<number> {
    const MAX_RETRIES = 10;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      let seqNo: number | undefined;
      let primaryTerm: number | undefined;
      let currentValue = 0;

      // Try to read the existing counter document
      try {
        const { body } = await client.get({
          index: CASE_COUNTER_INDEX,
          id: OpenSearchService.COUNTER_DOC_ID,
        });
        seqNo = body._seq_no;
        primaryTerm = body._primary_term;
        currentValue = body._source?.current_value ?? 0;
      } catch (err: any) {
        // 404 — counter doesn't exist yet, we'll create it below
        if (err?.statusCode !== 404 && err?.meta?.statusCode !== 404) {
          throw err;
        }
      }

      const nextValue = currentValue + 1;

      try {
        if (seqNo === undefined) {
          // Create the counter document for the first time
          await client.index({
            index: CASE_COUNTER_INDEX,
            id: OpenSearchService.COUNTER_DOC_ID,
            body: { counter_name: 'case_id', current_value: nextValue },
            op_type: 'create',
            refresh: 'wait_for',
          });
        } else {
          // Update with optimistic concurrency check
          await client.index({
            index: CASE_COUNTER_INDEX,
            id: OpenSearchService.COUNTER_DOC_ID,
            body: { counter_name: 'case_id', current_value: nextValue },
            if_seq_no: seqNo,
            if_primary_term: primaryTerm,
            refresh: 'wait_for',
          });
        }
        return nextValue;
      } catch (err: any) {
        const status = err?.statusCode ?? err?.meta?.statusCode;
        // 409 conflict means another request updated the counter first — retry
        if (status === 409) {
          continue;
        }
        throw err;
      }
    }

    // Fallback: use timestamp-based value if all retries exhausted
    return Date.now();
  }
}
