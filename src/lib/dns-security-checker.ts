/** DNS security checker - DNSSEC, CAA, BIMI, MTA-STS via DNS-over-HTTPS */

import {
  lookupBimi,
  lookupCaa,
  lookupDnssec,
  lookupMtaSts,
  type DnsRecord,
  type DnssecLookupResult,
} from './dns-over-https';

export interface MtaStsPolicy {
  fetched: boolean;
  mode?: string;
  issues: string[];
}

export interface DnsSecurityReport {
  dnssec: DnssecLookupResult;
  caa: { found: boolean; records: string[]; error?: string };
  bimi: { found: boolean; record: DnsRecord | null };
  mtaSts: {
    txtFound: boolean;
    record: DnsRecord | null;
    /**
     * Result of fetching https://mta-sts.<domain>/.well-known/mta-sts.txt.
     * Filled in from the server API - the policy file fetch needs the
     * server-side SSRF validation and IP pinning, so it never runs in the
     * browser. Undefined when the server API was unreachable.
     */
    policy?: MtaStsPolicy;
  };
}

export async function checkDnsSecurity(domain: string): Promise<DnsSecurityReport> {
  const [dnssec, caaResult, bimiRecord, mtaStsRecord] = await Promise.all([
    lookupDnssec(domain),
    lookupCaa(domain),
    lookupBimi(domain),
    lookupMtaSts(domain),
  ]);

  return {
    dnssec,
    caa: {
      found: caaResult.records.length > 0,
      records: caaResult.records.map((r) => r.value),
      error: caaResult.error,
    },
    bimi: { found: !!bimiRecord, record: bimiRecord },
    mtaSts: { txtFound: !!mtaStsRecord, record: mtaStsRecord },
  };
}
