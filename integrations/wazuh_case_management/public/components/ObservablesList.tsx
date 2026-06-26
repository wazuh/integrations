/*
 * ObservablesList — IOC/observable display and management
 */
import React, { useState, useCallback } from 'react';
import {
  EuiButtonIcon,
  EuiButton,
  EuiFieldText,
  EuiSelect,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSwitch,
  EuiSpacer,
} from '@elastic/eui';
import { Observable, ObservableType } from '../../common/types';
import { OBSERVABLE_TYPES } from '../../common/constants';

interface Props {
  observables: Observable[];
  onAdd: (obs: { type: ObservableType; value: string; description?: string; is_ioc: boolean }) => Promise<void>;
  onRemove: (id: string) => Promise<void>;
}

export const ObservablesList: React.FC<Props> = ({ observables, onAdd, onRemove }) => {
  const [showForm, setShowForm] = useState(false);
  const [type, setType] = useState<ObservableType>('ip');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [isIoc, setIsIoc] = useState(false);
  const [adding, setAdding] = useState(false);

  const handleAdd = useCallback(async () => {
    if (!value.trim()) return;
    setAdding(true);
    try {
      await onAdd({ type, value: value.trim(), description: description.trim() || undefined, is_ioc: isIoc });
      setValue('');
      setDescription('');
      setIsIoc(false);
      setShowForm(false);
    } finally {
      setAdding(false);
    }
  }, [type, value, description, isIoc, onAdd]);

  return (
    <div className="caseManagement__observables">
      {observables.length === 0 && !showForm && (
        <div style={{ textAlign: 'center', padding: 16, color: '#64748b', fontSize: 13 }}>
          No observables tracked.
        </div>
      )}

      {observables.map((obs) => (
        <div key={obs.id} className="caseManagement__observables__item">
          <span className="caseManagement__observables__item__type">{obs.type}</span>
          <span className="caseManagement__observables__item__value">{obs.value}</span>
          {obs.is_ioc && <span className="caseManagement__observables__item__ioc">IOC</span>}
          <EuiButtonIcon
            id={`remove-obs-${obs.id}`}
            iconType="cross"
            color="danger"
            size="s"
            aria-label="Remove observable"
            onClick={() => onRemove(obs.id)}
          />
        </div>
      ))}

      {showForm ? (
        <div style={{ marginTop: 12 }}>
          <EuiFlexGroup gutterSize="s">
            <EuiFlexItem grow={false} style={{ width: 140 }}>
              <EuiSelect
                id="obs-type-select"
                options={OBSERVABLE_TYPES.map((t) => ({ value: t.value, text: t.label }))}
                value={type}
                onChange={(e) => setType(e.target.value as ObservableType)}
                compressed
              />
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFieldText
                id="obs-value-input"
                placeholder="Value (e.g., 192.168.1.1)"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                compressed
              />
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="s" alignItems="center">
            <EuiFlexItem>
              <EuiFieldText
                id="obs-desc-input"
                placeholder="Description (optional)"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                compressed
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiSwitch
                id="obs-ioc-toggle"
                label="IOC"
                checked={isIoc}
                onChange={(e) => setIsIoc(e.target.checked)}
                compressed
              />
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="s" justifyContent="flexEnd">
            <EuiFlexItem grow={false}>
              <EuiButton size="s" onClick={() => setShowForm(false)}>Cancel</EuiButton>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton id="add-obs-btn" size="s" fill onClick={handleAdd} isLoading={adding} disabled={!value.trim()}>
                Add
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </div>
      ) : (
        <EuiButton
          id="show-add-obs-btn"
          size="s"
          iconType="plusInCircle"
          onClick={() => setShowForm(true)}
          style={{ marginTop: 8 }}
        >
          Add Observable
        </EuiButton>
      )}
    </div>
  );
};
