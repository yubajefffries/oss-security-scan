import type { ReactNode } from 'react';

interface Props {
  type: 'info' | 'warning' | 'success' | 'danger';
  title: string;
  children: ReactNode;
}

export default function InsightCard({ type, title, children }: Props) {
  return (
    <div className={`insight-card insight-card--${type}`}>
      <p className="insight-card__title">{title}</p>
      <div className="insight-card__body">{children}</div>
    </div>
  );
}
