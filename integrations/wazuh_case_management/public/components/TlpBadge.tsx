/*
 * TlpBadge — Traffic Light Protocol classification badge (DFIR-IRIS inspired)
 */
import React from 'react';
import { TlpLevel } from '../../common/types';
import { TLP_LEVELS } from '../../common/constants';

interface Props {
  tlp: TlpLevel;
  size?: 'small' | 'medium';
}

export const TlpBadge: React.FC<Props> = ({ tlp, size = 'medium' }) => {
  const config = TLP_LEVELS.find((t) => t.value === tlp) || TLP_LEVELS[0];
  const fontSize = size === 'small' ? 10 : 12;
  const padding = size === 'small' ? '2px 6px' : '3px 10px';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding,
        fontSize,
        fontWeight: 700,
        fontFamily: 'monospace',
        letterSpacing: '0.5px',
        borderRadius: 4,
        background: config.bg,
        color: config.color,
        border: `1px solid ${config.color}40`,
        whiteSpace: 'nowrap',
      }}
    >
      {config.label}
    </span>
  );
};
