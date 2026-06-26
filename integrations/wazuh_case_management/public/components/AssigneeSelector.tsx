/*
 * AssigneeSelector — Combo box for selecting/assigning users
 * Fetches real users from Wazuh and provides an "Assign to me" shortcut.
 */
import React, { useState, useCallback, useEffect } from 'react';
import { EuiComboBox, EuiComboBoxOptionOption, EuiButtonEmpty, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { useServices } from '../app';
import { getUsers } from '../services/case_api';

interface Props {
  value: string | null;
  onChange: (value: string | null) => void;
  placeholder?: string;
  id?: string;
  showAssignToMe?: boolean;
}

export const AssigneeSelector: React.FC<Props> = ({
  value,
  onChange,
  placeholder = 'Assign to...',
  id = 'assignee-selector',
  showAssignToMe = true,
}) => {
  const { http, currentUser } = useServices();
  const [options, setOptions] = useState<EuiComboBoxOptionOption[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    setIsLoading(true);
    getUsers(http)
      .then((users) => {
        const userOpts = users.length > 0
          ? users.map((u) => ({ label: u }))
          : [{ label: 'admin' }, { label: 'analyst' }, { label: 'soc-lead' }];
        setOptions(userOpts);
      })
      .catch(() => {
        setOptions([{ label: 'admin' }, { label: 'analyst' }, { label: 'soc-lead' }]);
      })
      .finally(() => setIsLoading(false));
  }, [http]);

  const selectedOptions = value ? [{ label: value }] : [];

  const handleChange = useCallback(
    (selected: EuiComboBoxOptionOption[]) => {
      onChange(selected.length === 0 ? null : selected[0].label);
    },
    [onChange],
  );

  const handleCreate = useCallback(
    (searchValue: string) => {
      const newOption: EuiComboBoxOptionOption = { label: searchValue };
      setOptions((prev) => [...prev, newOption]);
      onChange(searchValue);
    },
    [onChange],
  );

  const handleAssignToMe = useCallback(() => {
    if (currentUser && currentUser !== 'unknown') {
      if (!options.find((o) => o.label === currentUser)) {
        setOptions((prev) => [{ label: currentUser }, ...prev]);
      }
      onChange(currentUser);
    }
  }, [currentUser, options, onChange]);

  const isAlreadyMe = value === currentUser;

  return (
    <div>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem>
          <EuiComboBox
            id={id}
            placeholder={placeholder}
            singleSelection={{ asPlainText: true }}
            options={options}
            selectedOptions={selectedOptions}
            onChange={handleChange}
            onCreateOption={handleCreate}
            customOptionText="Assign to {searchValue}"
            isClearable
            compressed
            isLoading={isLoading}
          />
        </EuiFlexItem>
        {showAssignToMe && currentUser && currentUser !== 'unknown' && !isAlreadyMe && (
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              size="xs"
              iconType="user"
              onClick={handleAssignToMe}
              style={{ whiteSpace: 'nowrap', color: 'var(--cm-primary)' }}
            >
              Assign to me
            </EuiButtonEmpty>
          </EuiFlexItem>
        )}
        {isAlreadyMe && (
          <EuiFlexItem grow={false}>
            <span style={{ fontSize: 11, color: 'var(--cm-success)', whiteSpace: 'nowrap' }}>
              ✓ Assigned to you
            </span>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
    </div>
  );
};
