export type ScanStatus = 'pass' | 'warning' | 'critical' | 'error' | 'pending' | 'scanning';

export interface ScanResults {
  emailAuth?: import('./scanners/email-auth').EmailAuthResult;
  ssl?: import('./scanners/ssl').SSLResult;
  headers?: import('./scanners/headers').HeadersResult;
  blacklist?: import('./scanners/blacklist').BlacklistResult;
  dnsSecurity?: import('./scanners/dns-security').DnsSecurityResult;
}

export type ScanKey = keyof ScanResults;

export interface ScanState {
  domain: string;
  status: 'idle' | 'scanning' | 'complete' | 'error';
  progress: Partial<Record<ScanKey, 'pending' | 'scanning' | 'done' | 'error'>>;
  results: ScanResults;
}
