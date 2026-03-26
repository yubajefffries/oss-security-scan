import { useState } from 'react';
import { isValidDomain } from '../../lib/dns-over-https';

interface Props {
  onSubmit: (domain: string) => void;
  loading?: boolean;
  placeholder?: string;
}

export default function DomainInput({ onSubmit, loading = false, placeholder = 'example.com' }: Props) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setError('Enter a domain name');
      return;
    }
    if (!isValidDomain(trimmed)) {
      setError('Enter a valid domain (e.g. example.com)');
      return;
    }
    setError('');
    onSubmit(trimmed);
  }

  return (
    <div>
      <form className="domain-form" onSubmit={handleSubmit}>
        <input
          type="text"
          className="domain-form__input"
          value={value}
          onChange={(e) => { setValue(e.target.value); setError(''); }}
          placeholder={placeholder}
          disabled={loading}
          aria-label="Domain name"
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="submit"
          className="domain-form__btn"
          disabled={loading}
        >
          {loading ? 'Scanning…' : 'Scan'}
        </button>
      </form>
      {error && <p className="error-msg" role="alert" style={{ marginTop: '-16px', marginBottom: '24px', maxWidth: '480px' }}>{error}</p>}
    </div>
  );
}
