/*
 * AlertLinker — Modal to search and link Wazuh alerts to a case
 */
import React, { useState, useCallback } from 'react';
import {
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiButton,
  EuiButtonEmpty,
  EuiFieldSearch,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiSpacer,
  EuiCallOut,
} from '@elastic/eui';
import { useServices } from '../app';
import { searchAlerts } from '../services/case_api';
import { WazuhAlertHit } from '../../common/types';

interface Props {
  onLink: (alerts: WazuhAlertHit[]) => Promise<void>;
  onClose: () => void;
}

export const AlertLinker: React.FC<Props> = ({ onLink, onClose }) => {
  const { http } = useServices();
  const [searchTerm, setSearchTerm] = useState('');
  const [alerts, setAlerts] = useState<WazuhAlertHit[]>([]);
  const [selectedAlerts, setSelectedAlerts] = useState<WazuhAlertHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [linking, setLinking] = useState(false);

  const handleSearch = useCallback(async () => {
    if (!searchTerm.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result = await searchAlerts(http, { search: searchTerm, size: 50 });
      setAlerts(result.alerts || result.hits || []);
    } catch (e: any) {
      setError(e.message || 'Failed to search alerts');
    } finally {
      setLoading(false);
    }
  }, [http, searchTerm]);

  const handleLink = useCallback(async () => {
    if (selectedAlerts.length === 0) return;
    setLinking(true);
    try {
      await onLink(selectedAlerts);
      onClose();
    } catch (e: any) {
      setError(e.message || 'Failed to link alerts');
    } finally {
      setLinking(false);
    }
  }, [selectedAlerts, onLink, onClose]);

  const columns: EuiBasicTableColumn<WazuhAlertHit>[] = [
    {
      field: '_source.rule.description',
      name: 'Rule',
      truncateText: true,
    },
    {
      field: '_source.agent.name',
      name: 'Agent',
      width: '120px',
    },
    {
      field: '_source.rule.level',
      name: 'Level',
      width: '70px',
      render: (level: number) => (
        <span style={{ fontWeight: 700, color: level >= 10 ? '#ef4444' : level >= 5 ? '#f59e0b' : '#22d3ee' }}>
          {level}
        </span>
      ),
    },
    {
      field: '_source.timestamp',
      name: 'Time',
      width: '140px',
      render: (ts: string) => new Date(ts).toLocaleString(),
    },
  ];

  const selection = {
    onSelectionChange: (selected: WazuhAlertHit[]) => setSelectedAlerts(selected),
  };

  return (
    <EuiModal onClose={onClose} style={{ width: 800, maxWidth: '90vw' }}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Link Wazuh Alerts</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiFieldSearch
          id="alert-search-input"
          placeholder="Search alerts by rule, agent, log content..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onSearch={handleSearch}
          isLoading={loading}
          fullWidth
        />
        <EuiSpacer size="m" />

        {error && (
          <>
            <EuiCallOut title={error} color="danger" iconType="alert" size="s" />
            <EuiSpacer size="m" />
          </>
        )}

        <EuiBasicTable
          items={alerts}
          columns={columns}
          selection={selection}
          loading={loading}
          itemId="_id"
          noItemsMessage={
            searchTerm
              ? 'No alerts found. Try a different search.'
              : 'Search for Wazuh alerts to link to this case.'
          }
        />
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton
          id="link-alerts-btn"
          fill
          onClick={handleLink}
          isLoading={linking}
          disabled={selectedAlerts.length === 0}
          className="caseManagement__button--primary"
        >
          Link {selectedAlerts.length > 0 ? `(${selectedAlerts.length})` : ''} Alerts
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
