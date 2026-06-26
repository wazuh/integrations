/*
 * Debug route — tests each step of case creation and returns detailed errors.
 * Remove this file after the issue is resolved.
 */

import { IRouter, Logger } from '../../../../src/core/server';
import { CASE_INDEX, CASE_COUNTER_INDEX } from '../../common/constants';
import { getCurrentUsername } from './users';

export function registerDebugRoutes(router: IRouter, logger: Logger): void {
  // POST /api/wazuh-case-management/debug/create
  // Accepts any body, runs each step, returns a detailed report
  router.post(
    {
      path: '/api/wazuh-case-management/debug/create',
      validate: false,
    },
    async (context, request, response) => {
      const report: Record<string, any> = {};
      const client = context.core.opensearch.client.asCurrentUser;

      // Step 1: current user
      try {
        report.step1_user = await getCurrentUsername(client);
      } catch (e: any) {
        report.step1_user_error = e.message;
      }

      // Step 2: check indices exist
      try {
        const ci = await client.indices.exists({ index: CASE_INDEX });
        report.step2_case_index_exists = ci.body;
      } catch (e: any) {
        report.step2_case_index_error = e.message;
      }
      try {
        const ci2 = await client.indices.exists({ index: CASE_COUNTER_INDEX });
        report.step2_counter_index_exists = ci2.body;
      } catch (e: any) {
        report.step2_counter_index_error = e.message;
      }

      // Step 3: read counter document
      try {
        const doc = await client.get({ index: CASE_COUNTER_INDEX, id: 'case_id_counter' });
        report.step3_counter_doc = doc.body._source;
        report.step3_counter_seq_no = doc.body._seq_no;
      } catch (e: any) {
        report.step3_counter_error = `${e.statusCode || e.meta?.statusCode} — ${e.message}`;
      }

      // Step 4: attempt counter increment (no script)
      try {
        const now = Date.now();
        await client.index({
          index: CASE_COUNTER_INDEX,
          id: `debug_test_${now}`,
          body: { counter_name: 'debug', current_value: 1 },
          refresh: 'wait_for',
        });
        // clean up
        await client.delete({ index: CASE_COUNTER_INDEX, id: `debug_test_${now}` }).catch(() => {});
        report.step4_index_write = 'OK';
      } catch (e: any) {
        report.step4_index_write_error = `${e.statusCode || e.meta?.statusCode} — ${e.message}`;
      }

      // Step 5: write a minimal case document
      try {
        const testDoc = {
          case_id: 'DEBUG-TEST',
          title: 'Debug test',
          description: '',
          status: 'open',
          severity: 'low',
          priority: 'P4',
          category: 'other',
          tlp: 'WHITE',
          tags: [],
          assignee: null,
          created_by: 'debug',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          closed_at: null,
          linked_alerts: [],
          observables: [],
          comments: [],
          tasks: [],
          notes: '',
          activity_log: [],
          resolution_summary: null,
          time_to_resolve_ms: null,
          related_cases: [],
          custom_fields: {},
        };
        const result = await client.index({ index: CASE_INDEX, body: testDoc, refresh: 'wait_for' });
        report.step5_case_write = 'OK';
        // clean up
        await client.delete({ index: CASE_INDEX, id: result.body._id }).catch(() => {});
      } catch (e: any) {
        report.step5_case_write_error = `${e.statusCode || e.meta?.statusCode} — ${e.message}`;
        try { report.step5_full_error = JSON.stringify(e.meta?.body); } catch {}
      }

      // Step 6: echo request body
      try {
        report.step6_received_body = request.body;
      } catch (e: any) {
        report.step6_body_error = e.message;
      }

      logger.info(`DEBUG REPORT: ${JSON.stringify(report)}`);
      return response.ok({ body: report });
    },
  );
}
