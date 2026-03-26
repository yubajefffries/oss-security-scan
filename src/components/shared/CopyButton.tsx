import { useState } from 'react';
import { copyToClipboard } from '../../lib/copy-results';

interface Props {
  text: string;
  label?: string;
}

export default function CopyButton({ text, label = 'Copy results' }: Props) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <button
      type="button"
      className={`copy-btn${copied ? ' copy-btn--copied' : ''}`}
      onClick={handleCopy}
      aria-label={copied ? 'Copied!' : label}
    >
      {copied ? '✓ Copied' : label}
    </button>
  );
}
