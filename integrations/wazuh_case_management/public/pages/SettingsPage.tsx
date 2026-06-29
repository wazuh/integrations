/*
 * SettingsPage — Plugin settings and about information
 */
import React from 'react';
import {
  EuiTitle,
  EuiSpacer,
  EuiDescribedFormGroup,
  EuiFormRow,
  EuiFieldText,
  EuiText,
  EuiHorizontalRule,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
} from '@elastic/eui';
import { PLUGIN_NAME, CASE_ID_PREFIX } from '../../common/constants';

export const SettingsPage: React.FC = () => {
  return (
    <div className="caseManagement__fadeIn" style={{ maxWidth: 800 }}>
      <div className="caseManagement__header">
        <div className="caseManagement__headerTitle">
          <span>Settings</span>
        </div>
      </div>

      {/* About Section */}
      <div className="caseManagement__card caseManagement__card--no-hover">
        <EuiFlexGroup alignItems="center" gutterSize="m">
          <EuiFlexItem grow={false}>
            <div style={{
              width: 48, height: 48, borderRadius: 12,
              background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 4px 16px rgba(99, 102, 241, 0.3)',
            }}>
              <EuiIcon type="securityApp" size="xl" color="#fff" />
            </div>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiTitle size="s">
              <h2>Wazuh {PLUGIN_NAME}</h2>
            </EuiTitle>
            <EuiText size="s" color="subdued">
              <p>Security incident case management for Wazuh Dashboard</p>
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size="l" />

        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 24px', fontSize: 13 }}>
          <span style={{ color: '#64748b', fontWeight: 600 }}>Version</span>
          <span>1.0.0</span>
          <span style={{ color: '#64748b', fontWeight: 600 }}>Target</span>
          <span>Wazuh 4.14.5 / OpenSearch Dashboards 2.19.5</span>
          <span style={{ color: '#64748b', fontWeight: 600 }}>Case Index</span>
          <span style={{ fontFamily: 'monospace' }}>wazuh-case-management-cases</span>
          <span style={{ color: '#64748b', fontWeight: 600 }}>Alert Source</span>
          <span style={{ fontFamily: 'monospace' }}>wazuh-alerts-*</span>
          <span style={{ color: '#64748b', fontWeight: 600 }}>Case ID Prefix</span>
          <span style={{ fontFamily: 'monospace' }}>{CASE_ID_PREFIX}</span>
        </div>
      </div>

      <EuiSpacer size="l" />

      {/* Configuration Section */}
      <div className="caseManagement__card caseManagement__card--no-hover caseManagement__form">
        <div className="caseManagement__detail__sectionTitle">Configuration</div>

        <EuiDescribedFormGroup
          title={<h3>Case ID Prefix</h3>}
          description="The prefix used for auto-generated case IDs (e.g., CASE-2026-0001)"
        >
          <EuiFormRow>
            <EuiFieldText
              id="setting-case-prefix"
              value={CASE_ID_PREFIX}
              readOnly
              compressed
            />
          </EuiFormRow>
        </EuiDescribedFormGroup>

        <EuiHorizontalRule />

        <EuiDescribedFormGroup
          title={<h3>Data Retention</h3>}
          description="Case data is stored in OpenSearch and follows your cluster's retention policies."
        >
          <EuiFormRow>
            <EuiText size="s" color="subdued">
              <p>Managed by OpenSearch Index Lifecycle Management (ILM)</p>
            </EuiText>
          </EuiFormRow>
        </EuiDescribedFormGroup>
      </div>

      <EuiSpacer size="l" />

      {/* Help */}
      <div className="caseManagement__card caseManagement__card--no-hover">
        <div className="caseManagement__detail__sectionTitle">Quick Start Guide</div>
        <EuiText size="s">
          <ol style={{ color: '#94a3b8', lineHeight: 2 }}>
            <li>Navigate to the <strong>Cases</strong> tab to view all cases</li>
            <li>Click <strong>Create Case</strong> to create a new security incident case</li>
            <li>Use <strong>Link Alert</strong> to associate Wazuh alerts with a case</li>
            <li>Add <strong>comments</strong> and <strong>observables</strong> to track investigation progress</li>
            <li>Change case <strong>status</strong> as you work through the incident lifecycle</li>
            <li>View the <strong>Dashboard</strong> for analytics and metrics</li>
          </ol>
        </EuiText>
      </div>
    </div>
  );
};
