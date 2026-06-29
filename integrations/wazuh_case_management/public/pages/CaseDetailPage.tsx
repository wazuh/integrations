/*
 * CaseDetailPage — DFIR-IRIS inspired left-tab sidebar layout
 * Tabs: Summary | Tasks | Alerts | Observables | Timeline
 * Features: inline field editing, assign-to-me, resolution dialog
 */
import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiLoadingSpinner,
  EuiCallOut,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiTitle,
  EuiBreadcrumbs,
  EuiPopover,
  EuiContextMenuPanel,
  EuiContextMenuItem,
  EuiConfirmModal,
  EuiFieldText,
  EuiTextArea,
  EuiSelect,
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiFormRow,
  EuiToolTip,
} from '@elastic/eui';
import { useHistory, useParams } from 'react-router-dom';
import { useServices } from '../app';
import * as api from '../services/case_api';
import { Case, CaseStatus, CaseSeverity, CasePriority, CaseCategory, TlpLevel, CaseTask, WazuhAlertHit } from '../../common/types';
import { CASE_STATUSES, STATUS_TRANSITIONS, CASE_SEVERITIES, CASE_PRIORITIES, CASE_CATEGORIES, TLP_LEVELS } from '../../common/constants';
import { CaseStatusBadge } from '../components/CaseStatusBadge';
import { CaseSeverityBadge } from '../components/CaseSeverityBadge';
import { TlpBadge } from '../components/TlpBadge';
import { CaseTimeline } from '../components/CaseTimeline';
import { CommentSection } from '../components/CommentSection';
import { LinkedAlertsList } from '../components/LinkedAlertsList';
import { ObservablesList } from '../components/ObservablesList';
import { AlertLinker } from '../components/AlertLinker';
import { CaseTaskList } from '../components/CaseTaskList';
import { InvestigationNotes } from '../components/InvestigationNotes';
import { AssigneeSelector } from '../components/AssigneeSelector';
import { TagSelector } from '../components/TagSelector';
import { IocSection } from '../components/IocSection';
import { MarkdownRenderer } from '../components/MarkdownRenderer';

type TabId = 'summary' | 'tasks' | 'alerts' | 'observables' | 'timeline';

const SEVERITY_COLORS: Record<string, string> = {
  informational: 'var(--cm-text-secondary)',
  low: '#00BB7A',
  medium: '#F5A623',
  high: '#EE3434',
  critical: '#9333EA',
};

const TABS: { id: TabId; label: string; icon: string }[] = [
  { id: 'summary', label: 'Summary', icon: '📋' },
  { id: 'tasks', label: 'Tasks', icon: '✅' },
  { id: 'alerts', label: 'Alerts', icon: '🚨' },
  { id: 'observables', label: 'Observables', icon: '🔍' },
  { id: 'timeline', label: 'Timeline', icon: '📅' },
];

export const CaseDetailPage: React.FC = () => {
  const { http, notifications, currentUser } = useServices();
  const { id } = useParams<{ id: string }>();
  const history = useHistory();

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  const [statusPopover, setStatusPopover] = useState(false);
  const [showAlertLinker, setShowAlertLinker] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Inline editing state
  const [editingTitle, setEditingTitle] = useState(false);
  const [editingDescription, setEditingDescription] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [savingField, setSavingField] = useState<string | null>(null);

  // Resolution dialog
  const [pendingStatus, setPendingStatus] = useState<CaseStatus | null>(null);
  const [resolutionSummary, setResolutionSummary] = useState('');

  const fetchCase = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getCase(http, id);
      setCaseData(result);
    } catch (e: any) {
      setError(e.message || 'Failed to load case');
    } finally {
      setLoading(false);
    }
  }, [http, id]);

  useEffect(() => { fetchCase(); }, [fetchCase]);

  const handleStatusChange = useCallback(async (newStatus: CaseStatus) => {
    setStatusPopover(false);
    if (newStatus === 'resolved' || newStatus === 'closed') {
      setPendingStatus(newStatus);
      setResolutionSummary('');
      return;
    }
    try {
      const updated = await api.updateCaseStatus(http, id, newStatus);
      setCaseData(updated);
      notifications.toasts.addSuccess(`Status updated to ${newStatus.replace(/_/g, ' ')}`);
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to change status');
    }
  }, [http, id, notifications]);

  const handleConfirmResolution = useCallback(async () => {
    if (!pendingStatus) return;
    try {
      const updated = await api.updateCaseStatus(http, id, pendingStatus);
      if (resolutionSummary.trim()) {
        await api.updateCase(http, id, { resolution_summary: resolutionSummary.trim() });
      }
      setCaseData(updated);
      await fetchCase();
      notifications.toasts.addSuccess(`Case ${pendingStatus === 'resolved' ? 'resolved' : 'closed'}`);
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to update status');
    } finally {
      setPendingStatus(null);
    }
  }, [http, id, pendingStatus, resolutionSummary, fetchCase, notifications]);

  const handleSaveField = useCallback(async (field: string, value: any) => {
    setSavingField(field);
    try {
      const updated = await api.updateCase(http, id, { [field]: value });
      setCaseData(updated);
      notifications.toasts.addSuccess('Case updated');
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to update');
    } finally {
      setSavingField(null);
    }
  }, [http, id, notifications]);

  const handleSaveTitle = useCallback(async () => {
    if (editTitle.trim() && editTitle.trim() !== caseData?.title) {
      await handleSaveField('title', editTitle.trim());
    }
    setEditingTitle(false);
  }, [editTitle, caseData, handleSaveField]);

  const handleSaveDescription = useCallback(async () => {
    await handleSaveField('description', editDescription);
    setEditingDescription(false);
  }, [editDescription, handleSaveField]);

  const handleAssignCase = useCallback(async (assignee: string | null) => {
    await handleSaveField('assignee', assignee);
  }, [handleSaveField]);

  const handleAssignToMe = useCallback(async () => {
    await handleSaveField('assignee', currentUser);
  }, [currentUser, handleSaveField]);

  const handleAddComment = useCallback(async (content: string) => {
    const updated = await api.addComment(http, id, content);
    setCaseData(updated as any);
  }, [http, id]);

  const handleDeleteComment = useCallback(async (commentId: string) => {
    await api.deleteComment(http, id, commentId);
    fetchCase();
  }, [http, id, fetchCase]);

  const handleUnlinkAlert = useCallback(async (alertId: string) => {
    await api.unlinkAlert(http, id, alertId);
    fetchCase();
  }, [http, id, fetchCase]);

  const handleLinkAlerts = useCallback(async (alerts: WazuhAlertHit[]) => {
    for (const alert of alerts) {
      await api.linkAlert(http, id, {
        alert_id: alert._id,
        index: alert._index,
        rule_id: Number(alert._source.rule.id),
        rule_description: alert._source.rule.description,
        rule_level: alert._source.rule.level,
        rule_groups: alert._source.rule.groups || [],
        agent_id: alert._source.agent.id,
        agent_name: alert._source.agent.name,
        timestamp: alert._source.timestamp,
      });
    }
    fetchCase();
  }, [http, id, fetchCase]);

  const handleAddObservable = useCallback(async (obs: any) => {
    await api.addObservable(http, id, obs);
    fetchCase();
  }, [http, id, fetchCase]);

  const handleRemoveObservable = useCallback(async (obsId: string) => {
    await api.removeObservable(http, id, obsId);
    fetchCase();
  }, [http, id, fetchCase]);

  const handleAddTask = useCallback(async (title: string) => {
    try {
      await http.post(`/api/wazuh-case-management/cases/${id}/tasks`, { body: JSON.stringify({ title }) });
      fetchCase();
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to add task');
    }
  }, [http, id, fetchCase, notifications]);

  const handleToggleTask = useCallback(async (taskId: string, completed: boolean) => {
    try {
      await http.patch(`/api/wazuh-case-management/cases/${id}/tasks/${taskId}`, { body: JSON.stringify({ completed }) });
      fetchCase();
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to update task');
    }
  }, [http, id, fetchCase, notifications]);

  const handleRemoveTask = useCallback(async (taskId: string) => {
    try {
      await http.delete(`/api/wazuh-case-management/cases/${id}/tasks/${taskId}`);
      fetchCase();
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to remove task');
    }
  }, [http, id, fetchCase, notifications]);

  const handleSaveNotes = useCallback(async (notes: string) => {
    try {
      await http.patch(`/api/wazuh-case-management/cases/${id}/notes`, { body: JSON.stringify({ notes }) });
      fetchCase();
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to save notes');
    }
  }, [http, id, fetchCase, notifications]);

  const handleDelete = useCallback(async () => {
    try {
      await api.deleteCase(http, id);
      notifications.toasts.addSuccess('Case deleted');
      history.push('/');
    } catch (e: any) {
      notifications.toasts.addDanger(e.message || 'Failed to delete case');
    }
  }, [http, id, notifications, history]);

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 80 }}><EuiLoadingSpinner size="xl" /></div>;
  }
  if (error || !caseData) {
    return <EuiCallOut title={error || 'Case not found'} color="danger" iconType="alert" />;
  }

  const allowedTransitions = STATUS_TRANSITIONS[caseData.status] || [];
  const severityColor = SEVERITY_COLORS[caseData.severity] || 'var(--cm-text-secondary)';
  const tasks = caseData.tasks || [];
  const completedTasks = tasks.filter((t) => t.completed).length;
  const isAssignedToMe = caseData.assignee === currentUser;

  return (
    <div style={{ minHeight: '100vh', background: 'var(--cm-bg)' }}>
      {/* Severity-colored top banner strip */}
      <div style={{ height: 4, background: `linear-gradient(to right, ${severityColor}, ${severityColor}66)`, marginBottom: 0 }} />

      {/* Case Header */}
      <div style={{ background: 'var(--cm-surface)', borderBottom: '1px solid var(--cm-border)', padding: '16px 24px' }}>
        <EuiBreadcrumbs
          breadcrumbs={[
            { text: '← Cases', onClick: () => history.push('/') },
            { text: caseData.case_id },
          ]}
          truncate={false}
        />
        <EuiSpacer size="s" />

        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1 }}>
            {/* Inline title editing */}
            {editingTitle ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                <EuiFieldText
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleSaveTitle(); if (e.key === 'Escape') setEditingTitle(false); }}
                  autoFocus
                  compressed
                  style={{ fontSize: 18, fontWeight: 700, maxWidth: 600 }}
                />
                <EuiButtonEmpty size="xs" onClick={handleSaveTitle} isLoading={savingField === 'title'} style={{ color: 'var(--cm-success)' }}>Save</EuiButtonEmpty>
                <EuiButtonEmpty size="xs" onClick={() => setEditingTitle(false)} style={{ color: 'var(--cm-text-secondary)' }}>Cancel</EuiButtonEmpty>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <h1 style={{ color: 'var(--cm-text)', fontSize: 22, fontWeight: 700, margin: 0 }}>
                  {caseData.title}
                </h1>
                <EuiToolTip content="Edit title">
                  <EuiButtonIcon
                    iconType="pencil"
                    size="xs"
                    aria-label="Edit title"
                    color="text"
                    onClick={() => { setEditTitle(caseData.title); setEditingTitle(true); }}
                    style={{ color: 'var(--cm-text-muted)', opacity: 0.6 }}
                  />
                </EuiToolTip>
              </div>
            )}

            {/* Badge Row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#6B7280', background: 'var(--cm-bg)', padding: '2px 8px', borderRadius: 4, border: '1px solid var(--cm-border)' }}>
                {caseData.case_id}
              </span>
              <CaseStatusBadge status={caseData.status} />
              <CaseSeverityBadge severity={caseData.severity} />
              <span style={{ background: 'rgba(169,174,196,0.1)', color: 'var(--cm-text-secondary)', border: '1px solid rgba(169,174,196,0.2)', padding: '3px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600 }}>
                {caseData.priority}
              </span>
              {caseData.tlp && <TlpBadge tlp={caseData.tlp} size="small" />}
              {tasks.length > 0 && (
                <span style={{ fontSize: 12, color: completedTasks === tasks.length ? '#00BB7A' : 'var(--cm-text-secondary)' }}>
                  {completedTasks}/{tasks.length} tasks
                </span>
              )}
              {caseData.assignee && (
                <span style={{
                  fontSize: 12, color: isAssignedToMe ? '#00BB7A' : 'var(--cm-text-secondary)',
                  background: isAssignedToMe ? 'rgba(0,187,122,0.1)' : 'rgba(169,174,196,0.1)',
                  border: `1px solid ${isAssignedToMe ? 'rgba(0,187,122,0.3)' : 'rgba(169,174,196,0.2)'}`,
                  padding: '3px 10px', borderRadius: 20,
                }}>
                  👤 {caseData.assignee}{isAssignedToMe ? ' (you)' : ''}
                </span>
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {!isAssignedToMe && currentUser !== 'unknown' && (
              <EuiButton
                size="s"
                iconType="user"
                onClick={handleAssignToMe}
                isLoading={savingField === 'assignee'}
                style={{ background: 'rgba(0,187,122,0.1)', borderColor: 'rgba(0,187,122,0.3)', color: '#00BB7A' }}
              >
                Assign to me
              </EuiButton>
            )}
            <EuiPopover
              id="status-change-popover"
              button={
                <EuiButton
                  id="change-status-btn"
                  size="s"
                  iconType="arrowDown"
                  iconSide="right"
                  onClick={() => setStatusPopover(!statusPopover)}
                  style={{ background: '#1D76EE', border: 'none', color: '#fff' }}
                >
                  Change Status
                </EuiButton>
              }
              isOpen={statusPopover}
              closePopover={() => setStatusPopover(false)}
            >
              <EuiContextMenuPanel
                items={allowedTransitions.map((s) => (
                  <EuiContextMenuItem key={s} id={`status-option-${s}`} onClick={() => handleStatusChange(s as CaseStatus)}>
                    <CaseStatusBadge status={s as CaseStatus} />
                  </EuiContextMenuItem>
                ))}
              />
            </EuiPopover>
            <EuiButton
              id="link-alert-btn"
              size="s"
              iconType="link"
              onClick={() => setShowAlertLinker(true)}
              style={{ background: 'var(--cm-surface)', borderColor: 'var(--cm-border)', color: 'var(--cm-text-secondary)' }}
            >
              Link Alert
            </EuiButton>
            {currentUser === 'admin' && (
              <EuiButtonIcon id="delete-case-btn" iconType="trash" color="danger" aria-label="Delete case" onClick={() => setShowDeleteConfirm(true)} />
            )}
          </div>
        </div>
      </div>

      {/* Main Body: Left Tab Sidebar + Content */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 140px)' }}>
        {/* Left Sidebar Tabs */}
        <div style={{ width: 180, background: 'var(--cm-surface)', borderRight: '1px solid var(--cm-border)', padding: '16px 0', flexShrink: 0 }}>
          {TABS.map((tab) => {
            const isActive = activeTab === tab.id;
            let badge: string | null = null;
            if (tab.id === 'alerts') badge = String(caseData.linked_alerts?.length || 0);
            if (tab.id === 'observables') badge = String(caseData.observables?.length || 0);
            if (tab.id === 'tasks') badge = tasks.length > 0 ? `${completedTasks}/${tasks.length}` : null;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10, width: '100%',
                  padding: '10px 16px',
                  background: isActive ? 'rgba(29,118,238,0.15)' : 'transparent',
                  border: 'none', borderLeft: isActive ? '3px solid #1D76EE' : '3px solid transparent',
                  color: isActive ? 'var(--cm-primary)' : 'var(--cm-text-secondary)',
                  fontSize: 13, fontWeight: isActive ? 600 : 400,
                  cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.color = 'var(--cm-text)'; }}
                onMouseLeave={(e) => { if (!isActive) (e.currentTarget as HTMLElement).style.color = 'var(--cm-text-secondary)'; }}
              >
                <span style={{ fontSize: 14 }}>{tab.icon}</span>
                <span style={{ flex: 1 }}>{tab.label}</span>
                {badge !== null && (
                  <span style={{ fontSize: 10, padding: '1px 6px', background: isActive ? '#1D76EE' : 'var(--cm-border)', color: 'var(--cm-text)', borderRadius: 10, fontWeight: 700 }}>
                    {badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>

          {/* SUMMARY TAB */}
          {activeTab === 'summary' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 24 }}>
              {/* Left: Description + Notes + Comments */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Description */}
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Description</div>
                    {!editingDescription && (
                      <EuiButtonIcon iconType="pencil" size="xs" aria-label="Edit description" color="text"
                        onClick={() => { setEditDescription(caseData.description || ''); setEditingDescription(true); }}
                        style={{ color: 'var(--cm-text-muted)', opacity: 0.6 }}
                      />
                    )}
                  </div>
                  {editingDescription ? (
                    <div>
                      <EuiTextArea
                        value={editDescription}
                        onChange={(e) => setEditDescription(e.target.value)}
                        rows={6}
                        fullWidth
                        autoFocus
                      />
                      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                        <EuiButtonEmpty size="xs" onClick={handleSaveDescription} isLoading={savingField === 'description'} style={{ color: 'var(--cm-success)' }}>Save</EuiButtonEmpty>
                        <EuiButtonEmpty size="xs" onClick={() => setEditingDescription(false)} style={{ color: 'var(--cm-text-secondary)' }}>Cancel</EuiButtonEmpty>
                      </div>
                    </div>
                  ) : (
                    caseData.description
                      ? <MarkdownRenderer content={caseData.description} />
                      : <span style={{ color: 'var(--cm-text-muted)', fontStyle: 'italic', fontSize: 13 }}>No description provided. Click edit to add one.</span>
                  )}
                </div>

                {/* Investigation Notes */}
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                    Investigation Notes
                  </div>
                  <InvestigationNotes notes={caseData.notes || ''} onSave={handleSaveNotes} lastUpdated={caseData.updated_at} />
                </div>

                {/* Comments */}
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                    Comments ({caseData.comments?.length || 0})
                  </div>
                  <CommentSection comments={caseData.comments || []} onAddComment={handleAddComment} onDeleteComment={handleDeleteComment} />
                </div>
              </div>

              {/* Right: Editable Case Details Sidebar */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>Case Details</div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13 }}>
                    {/* Assignee — always editable */}
                    <div>
                      <div style={{ color: '#6B7280', marginBottom: 4 }}>Assignee</div>
                      <AssigneeSelector
                        value={caseData.assignee}
                        onChange={handleAssignCase}
                        showAssignToMe={true}
                      />
                    </div>

                    {/* Severity */}
                    <EditableSelectRow
                      label="Severity"
                      value={caseData.severity}
                      options={CASE_SEVERITIES.map((s) => ({ value: s.value, text: s.label }))}
                      onSave={(v) => handleSaveField('severity', v)}
                      saving={savingField === 'severity'}
                      renderValue={<CaseSeverityBadge severity={caseData.severity} />}
                    />

                    {/* Priority */}
                    <EditableSelectRow
                      label="Priority"
                      value={caseData.priority}
                      options={CASE_PRIORITIES.map((p) => ({ value: p.value, text: p.label }))}
                      onSave={(v) => handleSaveField('priority', v)}
                      saving={savingField === 'priority'}
                      renderValue={
                        <span style={{ background: 'rgba(169,174,196,0.1)', color: 'var(--cm-text-secondary)', border: '1px solid rgba(169,174,196,0.2)', padding: '3px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600 }}>
                          {caseData.priority}
                        </span>
                      }
                    />

                    {/* Category */}
                    <EditableSelectRow
                      label="Category"
                      value={caseData.category}
                      options={CASE_CATEGORIES.map((c) => ({ value: c.value, text: c.label }))}
                      onSave={(v) => handleSaveField('category', v)}
                      saving={savingField === 'category'}
                      renderValue={<span style={{ color: 'var(--cm-text)', fontWeight: 500 }}>{caseData.category?.replace(/_/g, ' ')}</span>}
                    />

                    {/* TLP */}
                    <EditableSelectRow
                      label="TLP"
                      value={caseData.tlp || 'WHITE'}
                      options={TLP_LEVELS.map((t) => ({ value: t.value, text: t.label }))}
                      onSave={(v) => handleSaveField('tlp', v)}
                      saving={savingField === 'tlp'}
                      renderValue={<TlpBadge tlp={caseData.tlp || 'WHITE'} size="small" />}
                    />

                    <div style={{ height: 1, background: 'var(--cm-border)', margin: '2px 0' }} />

                    <DetailRow label="Created by" value={caseData.created_by} />
                    <DetailRow label="Created" value={new Date(caseData.created_at).toLocaleString()} />
                    <DetailRow label="Updated" value={new Date(caseData.updated_at).toLocaleString()} />
                    {caseData.closed_at && <DetailRow label="Closed" value={new Date(caseData.closed_at).toLocaleString()} />}
                    {caseData.time_to_resolve_ms && (
                      <DetailRow label="Resolution Time" value={formatDuration(caseData.time_to_resolve_ms)} />
                    )}
                  </div>
                </div>

                {/* Editable Tags */}
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Tags</div>
                  <TagSelector
                    tags={caseData.tags || []}
                    onChange={(newTags) => handleSaveField('tags', newTags)}
                    id="case-detail-tags"
                  />
                </div>

                {/* IOC Panel */}
                <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      IOCs
                    </div>
                    {caseData.observables?.filter((o) => o.is_ioc).length > 0 && (
                      <span style={{ fontSize: 10, background: 'rgba(238,52,52,0.12)', color: '#EE3434', border: '1px solid rgba(238,52,52,0.25)', padding: '2px 7px', borderRadius: 10, fontWeight: 700 }}>
                        {caseData.observables.filter((o) => o.is_ioc).length}
                      </span>
                    )}
                  </div>
                  <IocSection
                    observables={caseData.observables || []}
                    onAdd={handleAddObservable}
                    onRemove={handleRemoveObservable}
                  />
                </div>

                {/* Resolution Summary */}
                {caseData.resolution_summary && (
                  <div style={{ background: 'rgba(0,187,122,0.05)', borderRadius: 10, border: '1px solid rgba(0,187,122,0.2)', padding: 20 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#00BB7A', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Resolution Summary</div>
                    <div style={{ color: 'var(--cm-text)', fontSize: 13, lineHeight: 1.6 }}>{caseData.resolution_summary}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TASKS TAB */}
          {activeTab === 'tasks' && (
            <div style={{ maxWidth: 700 }}>
              <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 24 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
                  Investigation Tasks
                </div>
                <CaseTaskList tasks={tasks} onAdd={handleAddTask} onToggle={handleToggleTask} onRemove={handleRemoveTask} />
              </div>
            </div>
          )}

          {/* ALERTS TAB */}
          {activeTab === 'alerts' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Linked Wazuh Alerts ({caseData.linked_alerts?.length || 0})
                </div>
                <EuiButton size="s" iconType="link" onClick={() => setShowAlertLinker(true)} style={{ background: '#1D76EE', border: 'none', color: '#fff' }}>
                  Link Alert
                </EuiButton>
              </div>
              <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                <LinkedAlertsList alerts={caseData.linked_alerts || []} onUnlink={handleUnlinkAlert} />
              </div>
            </div>
          )}

          {/* OBSERVABLES TAB */}
          {activeTab === 'observables' && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
                Observables / IOCs ({caseData.observables?.length || 0})
              </div>
              <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                <ObservablesList observables={caseData.observables || []} onAdd={handleAddObservable} onRemove={handleRemoveObservable} />
              </div>
            </div>
          )}

          {/* TIMELINE TAB */}
          {activeTab === 'timeline' && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
                Activity Timeline
              </div>
              <div style={{ background: 'var(--cm-surface)', borderRadius: 10, border: '1px solid var(--cm-border)', padding: 20 }}>
                <CaseTimeline activities={caseData.activity_log || []} />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Resolution / Close Dialog */}
      {pendingStatus && (
        <EuiModal onClose={() => setPendingStatus(null)} style={{ maxWidth: 520 }}>
          <EuiModalHeader>
            <EuiModalHeaderTitle>
              {pendingStatus === 'resolved' ? 'Resolve Case' : 'Close Case'}
            </EuiModalHeaderTitle>
          </EuiModalHeader>
          <EuiModalBody>
            <p style={{ color: 'var(--cm-text-secondary)', marginBottom: 16, fontSize: 13 }}>
              {pendingStatus === 'resolved'
                ? 'Provide a resolution summary describing how this incident was handled.'
                : 'Optionally add a closing note before archiving this case.'}
            </p>
            <EuiFormRow label="Resolution Summary" fullWidth>
              <EuiTextArea
                value={resolutionSummary}
                onChange={(e) => setResolutionSummary(e.target.value)}
                placeholder="Describe how the incident was resolved, actions taken, lessons learned..."
                rows={5}
                fullWidth
                autoFocus
              />
            </EuiFormRow>
          </EuiModalBody>
          <EuiModalFooter>
            <EuiButtonEmpty onClick={() => setPendingStatus(null)}>Cancel</EuiButtonEmpty>
            <EuiButton
              fill
              onClick={handleConfirmResolution}
              style={{ background: pendingStatus === 'resolved' ? '#00BB7A' : '#6b7280', border: 'none', color: '#fff' }}
            >
              {pendingStatus === 'resolved' ? 'Mark as Resolved' : 'Close Case'}
            </EuiButton>
          </EuiModalFooter>
        </EuiModal>
      )}

      {/* Alert Linker Modal */}
      {showAlertLinker && (
        <AlertLinker onLink={handleLinkAlerts} onClose={() => setShowAlertLinker(false)} />
      )}

      {/* Delete Confirm */}
      {showDeleteConfirm && (
        <EuiConfirmModal
          title="Delete Case"
          onCancel={() => setShowDeleteConfirm(false)}
          onConfirm={handleDelete}
          cancelButtonText="Cancel"
          confirmButtonText="Delete"
          buttonColor="danger"
        >
          <p>Are you sure you want to delete <strong>{caseData.case_id}</strong>? This cannot be undone.</p>
        </EuiConfirmModal>
      )}
    </div>
  );
};

// ─── Helper Components ────────────────────────────────────────

const DetailRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
    <span style={{ color: '#6B7280', flexShrink: 0 }}>{label}</span>
    <span style={{ color: 'var(--cm-text)', fontWeight: 500, textAlign: 'right' }}>{value}</span>
  </div>
);

interface EditableSelectRowProps {
  label: string;
  value: string;
  options: Array<{ value: string; text: string }>;
  onSave: (value: string) => void;
  saving: boolean;
  renderValue: React.ReactNode;
}

const EditableSelectRow: React.FC<EditableSelectRowProps> = ({ label, value, options, onSave, saving, renderValue }) => {
  const [editing, setEditing] = useState(false);
  const [local, setLocal] = useState(value);

  const handleSave = () => {
    onSave(local);
    setEditing(false);
  };

  if (editing) {
    return (
      <div>
        <div style={{ color: '#6B7280', marginBottom: 4, fontSize: 12 }}>{label}</div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <EuiSelect
            options={options}
            value={local}
            onChange={(e) => setLocal(e.target.value)}
            compressed
          />
          <EuiButtonEmpty size="xs" onClick={handleSave} isLoading={saving} style={{ color: 'var(--cm-success)' }}>Save</EuiButtonEmpty>
          <EuiButtonEmpty size="xs" onClick={() => { setLocal(value); setEditing(false); }} style={{ color: 'var(--cm-text-secondary)' }}>✕</EuiButtonEmpty>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
      <span style={{ color: '#6B7280', flexShrink: 0 }}>{label}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {renderValue}
        <EuiButtonIcon
          iconType="pencil" size="xs" aria-label={`Edit ${label}`} color="text"
          onClick={() => { setLocal(value); setEditing(true); }}
          style={{ color: 'var(--cm-text-muted)', opacity: 0.5 }}
        />
      </div>
    </div>
  );
};

function formatDuration(ms: number): string {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}
