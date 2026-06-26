/*
 * Lightweight markdown renderer — no external dependencies.
 * Supports: ## headings, **bold**, `inline code`, fenced code blocks, bullet lists.
 */

import React from 'react';

interface Props {
  content: string;
  style?: React.CSSProperties;
}

export const MarkdownRenderer: React.FC<Props> = ({ content, style }) => {
  if (!content) return null;

  // Split into blocks separated by blank lines
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // ── Fenced code block ───────────────────────────
    if (line.trim() === '```') {
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && lines[i].trim() !== '```') {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={key++} style={{
          background: 'var(--cm-surface)',
          border: '1px solid var(--cm-border)',
          borderRadius: 6,
          padding: '12px 14px',
          overflowX: 'auto',
          fontSize: 12,
          lineHeight: 1.6,
          color: 'var(--cm-text)',
          fontFamily: "'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace",
          margin: '10px 0',
          whiteSpace: 'pre',
        }}>
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
      i++;
      continue;
    }

    // ── h2 heading (##) ─────────────────────────────
    if (line.startsWith('## ')) {
      elements.push(
        <div key={key++} style={{
          fontSize: 13,
          fontWeight: 700,
          color: 'var(--cm-text)',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
          borderBottom: '1px solid var(--cm-border)',
          paddingBottom: 6,
          marginTop: 16,
          marginBottom: 10,
        }}>
          {line.slice(3)}
        </div>
      );
      i++;
      continue;
    }

    // ── Bullet list block ────────────────────────────
    if (line.startsWith('- ')) {
      const listItems: string[] = [];
      while (i < lines.length && lines[i].startsWith('- ')) {
        listItems.push(lines[i].slice(2));
        i++;
      }
      elements.push(
        <ul key={key++} style={{
          margin: '6px 0',
          paddingLeft: 18,
          listStyle: 'none',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}>
          {listItems.map((item, idx) => (
            <li key={idx} style={{ display: 'flex', gap: 8, fontSize: 13, lineHeight: 1.6 }}>
              <span style={{ color: 'var(--cm-primary-light)', marginTop: 1, flexShrink: 0 }}>›</span>
              <span style={{ color: 'var(--cm-text)' }}>{renderInline(item)}</span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // ── Blank line ───────────────────────────────────
    if (line.trim() === '') {
      i++;
      continue;
    }

    // ── Normal paragraph ─────────────────────────────
    elements.push(
      <p key={key++} style={{
        margin: '4px 0',
        fontSize: 13,
        lineHeight: 1.7,
        color: 'var(--cm-text-secondary)',
      }}>
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return (
    <div style={{ ...style }}>
      {elements}
    </div>
  );
};

/** Render inline markdown: **bold**, `code` */
function renderInline(text: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  // Match **bold** and `code`
  const regex = /(\*\*(.+?)\*\*|`([^`]+)`)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(text.slice(last, match.index));
    }
    if (match[0].startsWith('**')) {
      parts.push(<strong key={key++} style={{ color: 'var(--cm-text)', fontWeight: 600 }}>{match[2]}</strong>);
    } else {
      parts.push(
        <code key={key++} style={{
          background: 'var(--cm-surface)',
          border: '1px solid var(--cm-border)',
          borderRadius: 3,
          padding: '1px 5px',
          fontSize: 12,
          fontFamily: "'SF Mono', 'Monaco', monospace",
          color: 'var(--cm-primary-light)',
        }}>{match[3]}</code>
      );
    }
    last = match.index + match[0].length;
  }

  if (last < text.length) {
    parts.push(text.slice(last));
  }

  return parts.length === 1 ? parts[0] : <>{parts}</>;
}
