/** Email authentication grading - SPF, DMARC, DKIM → A–F grade */

import type { DnsRecord } from './dns-over-https';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface EmailAuthResult {
  grade: Grade;
  spf: { found: boolean; record: DnsRecord | null; strict: boolean; recommendation: string };
  dmarc: { found: boolean; record: DnsRecord | null; policy: string; recommendation: string };
  dkim: { found: boolean; selector: string | null; record: DnsRecord | null; recommendation: string };
  summary: string;
}

// Common DKIM selectors to check
export const DKIM_SELECTORS = ['google', 'default', 'selector1', 'selector2', 's1', 's2', 'k1', 'dkim', 'mail'];

export function computeGrade(
  spf: EmailAuthResult['spf'],
  dmarc: EmailAuthResult['dmarc'],
  dkim: EmailAuthResult['dkim'],
): { grade: Grade; summary: string } {
  let score = 0;

  // SPF scoring (0-3)
  if (spf.found) score += spf.strict ? 3 : 2;

  // DMARC scoring (0-4)
  if (dmarc.found) {
    if (dmarc.policy === 'reject') score += 4;
    else if (dmarc.policy === 'quarantine') score += 3;
    else score += 1; // none
  }

  // DKIM scoring (0-3)
  if (dkim.found) score += 3;

  // Grade thresholds: max 10
  let grade: Grade;
  let summary: string;

  if (score >= 9) {
    grade = 'A';
    summary = 'Well done! Your domain has valid DMARC, SPF, and DKIM records that provide full protection against phishing and spoofing. Based on your strict DMARC policy, mailbox providers like Google, Yahoo, and Microsoft can reliably identify and block unauthorized use of your domain.';
  } else if (score >= 7) {
    grade = 'B';
    summary = 'Good work! Your domain has email authentication in place and helps ensure you meet email sending best practices. However, your domain is not fully protected against abuse - review the recommendations below to close the remaining gaps.';
  } else if (score >= 5) {
    grade = 'C';
    summary = 'Your domain has basic email authentication, but significant gaps leave it vulnerable. Mailbox providers cannot reliably block fraudulent emails that mimic your domain. Address the issues below to improve your protection.';
  } else if (score >= 2) {
    grade = 'D';
    summary = 'Your domain has weak email authentication. It is not protected against abuse and likely does not meet the current Google and Yahoo sender requirements. Phishers and spammers can easily send email pretending to be your domain.';
  } else {
    grade = 'F';
    summary = 'We were unable to find email authentication records for your domain. As a result, this domain is not protected against abuse and anyone can send email pretending to be you. This also means you likely do not meet Google and Yahoo\'s sender requirements.';
  }

  return { grade, summary };
}

export interface BestPractices {
  spfStrict: boolean;   // SPF with -all
  dmarcReject: boolean;  // DMARC with p=reject
  dkimFound: boolean;    // DKIM record found
  allMet: boolean;
}

export function computeBestPractices(
  spf: EmailAuthResult['spf'],
  dmarc: EmailAuthResult['dmarc'],
  dkim: EmailAuthResult['dkim'],
): BestPractices {
  const spfStrict = spf.found && spf.strict;
  const dmarcReject = dmarc.found && dmarc.policy === 'reject';
  const dkimFound = dkim.found;
  return {
    spfStrict,
    dmarcReject,
    dkimFound,
    allMet: spfStrict && dmarcReject && dkimFound,
  };
}
