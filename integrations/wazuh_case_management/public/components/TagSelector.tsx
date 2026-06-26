/*
 * TagSelector — Combo box for managing case tags with create option
 */
import React, { useState, useCallback } from 'react';
import { EuiComboBox, EuiComboBoxOptionOption } from '@elastic/eui';

interface Props {
  tags: string[];
  onChange: (tags: string[]) => void;
  id?: string;
}

const DEFAULT_TAGS = [
  'ssh', 'brute-force', 'malware', 'phishing', 'ransomware',
  'exfiltration', 'lateral-movement', 'privilege-escalation',
  'linux', 'windows', 'firewall', 'web-attack', 'dns',
  'insider-threat', 'iot', 'cloud', 'active-directory',
];

export const TagSelector: React.FC<Props> = ({ tags, onChange, id = 'tag-selector' }) => {
  const [options, setOptions] = useState<EuiComboBoxOptionOption[]>(
    DEFAULT_TAGS.map((t) => ({ label: t })),
  );

  const selectedOptions = tags.map((t) => ({ label: t }));

  const handleChange = useCallback(
    (selected: EuiComboBoxOptionOption[]) => {
      onChange(selected.map((o) => o.label));
    },
    [onChange],
  );

  const handleCreate = useCallback(
    (searchValue: string) => {
      const normalized = searchValue.toLowerCase().trim().replace(/\s+/g, '-');
      const newOption: EuiComboBoxOptionOption = { label: normalized };
      setOptions((prev) => [...prev, newOption]);
      onChange([...tags, normalized]);
    },
    [onChange, tags],
  );

  return (
    <EuiComboBox
      id={id}
      placeholder="Add tags..."
      options={options}
      selectedOptions={selectedOptions}
      onChange={handleChange}
      onCreateOption={handleCreate}
      customOptionText='Add "{searchValue}" as a tag'
      isClearable
      compressed
    />
  );
};
