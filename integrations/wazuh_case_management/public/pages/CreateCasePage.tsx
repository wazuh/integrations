/*
 * CreateCasePage — Form for creating a new case
 */
import React, { useState, useCallback } from 'react';
import {
  EuiForm,
  EuiFormRow,
  EuiFieldText,
  EuiTextArea,
  EuiSelect,
  EuiButton,
  EuiButtonEmpty,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiCallOut,
  EuiTitle,
} from '@elastic/eui';
import { useHistory } from 'react-router-dom';
import { useServices } from '../app';
import { createCase } from '../services/case_api';
import { CreateCasePayload, CaseSeverity, CasePriority, CaseCategory, TlpLevel } from '../../common/types';
import { CASE_SEVERITIES, CASE_PRIORITIES, CASE_CATEGORIES, TLP_LEVELS } from '../../common/constants';
import { TagSelector } from '../components/TagSelector';
import { AssigneeSelector } from '../components/AssigneeSelector';

export const CreateCasePage: React.FC = () => {
  const { http, notifications, currentUser } = useServices();
  const history = useHistory();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [priority, setPriority] = useState<CasePriority>('P3');
  const [tlp, setTlp] = useState<TlpLevel>('WHITE');
  const [category, setCategory] = useState<CaseCategory>('other');
  const [tags, setTags] = useState<string[]>([]);
  const [assignee, setAssignee] = useState<string | null>(currentUser !== 'unknown' ? currentUser : null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async () => {
    if (!title.trim()) {
      setError('Title is required');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const payload: CreateCasePayload = {
        title: title.trim(),
        description: description.trim(),
        severity,
        priority,
        tlp,
        category,
        tags,
        assignee,
      };

      const newCase = await createCase(http, payload);
      notifications.toasts.addSuccess(`Case ${newCase.case_id} created successfully`);
      history.push(`/cases/${newCase.id}`);
    } catch (e: any) {
      setError(e.message || 'Failed to create case');
    } finally {
      setSubmitting(false);
    }
  }, [title, description, severity, priority, category, tags, assignee, http, notifications, history]);

  return (
    <div className="caseManagement__fadeIn" style={{ maxWidth: 800 }}>
      <EuiTitle size="l">
        <h1>Create New Case</h1>
      </EuiTitle>
      <EuiSpacer size="l" />

      {error && (
        <>
          <EuiCallOut title={error} color="danger" iconType="alert" size="s" />
          <EuiSpacer size="m" />
        </>
      )}

      <div className="caseManagement__card caseManagement__card--no-hover caseManagement__form">
        <EuiForm component="form">
          <EuiFormRow label="Title" fullWidth>
            <EuiFieldText
              id="case-title-input"
              placeholder="Brief description of the incident"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              fullWidth
            />
          </EuiFormRow>

          <EuiFormRow label="Description" fullWidth>
            <EuiTextArea
              id="case-description-input"
              placeholder="Detailed description of the security incident, affected systems, initial findings..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={6}
              fullWidth
            />
          </EuiFormRow>

          <EuiFlexGroup gutterSize="m">
            <EuiFlexItem>
              <EuiFormRow label="Severity">
                <EuiSelect
                  id="case-severity-select"
                  options={CASE_SEVERITIES.map((s) => ({ value: s.value, text: s.label }))}
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as CaseSeverity)}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label="Priority">
                <EuiSelect
                  id="case-priority-select"
                  options={CASE_PRIORITIES.map((p) => ({ value: p.value, text: p.label }))}
                  value={priority}
                  onChange={(e) => setPriority(e.target.value as CasePriority)}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label="TLP">
                <EuiSelect
                  id="case-tlp-select"
                  options={TLP_LEVELS.map((t) => ({ value: t.value, text: t.label }))}
                  value={tlp}
                  onChange={(e) => setTlp(e.target.value as TlpLevel)}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label="Category">
                <EuiSelect
                  id="case-category-select"
                  options={CASE_CATEGORIES.map((c) => ({ value: c.value, text: c.label }))}
                  value={category}
                  onChange={(e) => setCategory(e.target.value as CaseCategory)}
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiFormRow label="Assignee">
            <AssigneeSelector
              value={assignee}
              onChange={setAssignee}
              id="case-assignee-selector"
            />
          </EuiFormRow>

          <EuiFormRow label="Tags">
            <TagSelector tags={tags} onChange={setTags} id="case-tags-selector" />
          </EuiFormRow>

          <EuiSpacer size="xl" />

          <EuiFlexGroup justifyContent="flexEnd">
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty id="cancel-create-btn" onClick={() => history.push('/')}>
                Cancel
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                id="submit-create-btn"
                fill
                onClick={handleSubmit}
                isLoading={submitting}
                className="caseManagement__button--primary"
              >
                Create Case
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiForm>
      </div>
    </div>
  );
};
