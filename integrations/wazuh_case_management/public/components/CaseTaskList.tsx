/*
 * CaseTaskList — Investigation task checklist (DFIR-IRIS inspired)
 */
import React, { useState } from 'react';
import {
  EuiFieldText,
  EuiButton,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
} from '@elastic/eui';
import { CaseTask } from '../../common/types';

interface Props {
  tasks: CaseTask[];
  onAdd: (title: string) => Promise<void>;
  onToggle: (taskId: string, completed: boolean) => Promise<void>;
  onRemove: (taskId: string) => Promise<void>;
}

export const CaseTaskList: React.FC<Props> = ({ tasks, onAdd, onToggle, onRemove }) => {
  const [newTask, setNewTask] = useState('');
  const [adding, setAdding] = useState(false);

  const handleAdd = async () => {
    const trimmed = newTask.trim();
    if (!trimmed) return;
    setAdding(true);
    try {
      await onAdd(trimmed);
      setNewTask('');
    } finally {
      setAdding(false);
    }
  };

  const completed = tasks.filter((t) => t.completed).length;
  const total = tasks.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Progress Header */}
      {total > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
          <div
            style={{
              flex: 1,
              height: 4,
              background: '#3D3E5A',
              borderRadius: 2,
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${total === 0 ? 0 : (completed / total) * 100}%`,
                background: '#00BB7A',
                borderRadius: 2,
                transition: 'width 0.4s ease',
              }}
            />
          </div>
          <span style={{ fontSize: 12, color: '#A9AEC4', whiteSpace: 'nowrap' }}>
            {completed}/{total} done
          </span>
        </div>
      )}

      {/* Empty State */}
      {tasks.length === 0 && (
        <div style={{ color: '#6B7280', fontSize: 13, padding: '12px 0', textAlign: 'center' }}>
          No investigation tasks yet. Add one below.
        </div>
      )}

      {/* Task List */}
      {tasks.map((task) => (
        <div
          key={task.task_id}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '8px 12px',
            background: task.completed ? 'rgba(0,187,122,0.06)' : 'rgba(61,62,90,0.4)',
            border: `1px solid ${task.completed ? 'rgba(0,187,122,0.2)' : '#3D3E5A'}`,
            borderRadius: 8,
            transition: 'all 0.2s ease',
          }}
        >
          <input
            type="checkbox"
            checked={task.completed}
            onChange={(e) => onToggle(task.task_id, e.target.checked)}
            style={{
              width: 16,
              height: 16,
              accentColor: '#00BB7A',
              cursor: 'pointer',
              flexShrink: 0,
            }}
          />
          <span
            style={{
              flex: 1,
              fontSize: 13,
              color: task.completed ? 'var(--cm-text-muted)' : 'var(--cm-text)',
              textDecoration: task.completed ? 'line-through' : 'none',
              transition: 'color 0.2s ease',
            }}
          >
            {task.title}
          </span>
          {task.assigned_to && (
            <span
              style={{
                fontSize: 11,
                color: '#4D9FF5',
                background: 'rgba(29,118,238,0.1)',
                padding: '2px 8px',
                borderRadius: 12,
                border: '1px solid rgba(29,118,238,0.2)',
              }}
            >
              {task.assigned_to}
            </span>
          )}
          <EuiButtonIcon
            iconType="trash"
            color="danger"
            size="xs"
            aria-label="Remove task"
            onClick={() => onRemove(task.task_id)}
          />
        </div>
      ))}

      {/* Add Task Row */}
      <EuiFlexGroup gutterSize="s" responsive={false}>
        <EuiFlexItem>
          <EuiFieldText
            placeholder="Add a new investigation task..."
            value={newTask}
            onChange={(e) => setNewTask(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); }}
            compressed
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            onClick={handleAdd}
            isLoading={adding}
            isDisabled={!newTask.trim()}
            style={{ background: '#1D76EE', border: 'none', color: '#fff' }}
          >
            Add
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
    </div>
  );
};
