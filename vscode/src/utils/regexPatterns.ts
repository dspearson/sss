/**
 * Shared regex patterns used across the extension
 */

import { buildMarkerRegex } from './delimiters';

/**
 * Matches sss interpolation markers (`⊲`/`<` prefix) across every supported
 * delimiter pair. The key lands in one of many capture groups — read it via
 * `extractMarkerContent` from `./delimiters`.
 */
export const INTERPOLATION_MARKER_REGEX = buildMarkerRegex(['⊲', '<']);

/** Matches single-line secret format: key: value */
export const SINGLE_LINE_SECRET_REGEX = /^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|(.*))\s*$/;

/** Matches multiline secret format: key: | */
export const MULTILINE_SECRET_REGEX = /^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*\|\s*$/;

/** Extracts the secret key from regex match groups */
export function extractSecretKey(match: RegExpMatchArray): string {
    return (match[1] || match[2] || match[3]).trim();
}

/** Extracts the secret value from single-line regex match groups */
export function extractSecretValue(match: RegExpMatchArray): string {
    return (match[4] || match[5] || match[6] || '').trim();
}

/** Checks if a line is a comment or empty */
export function isCommentOrEmpty(line: string): boolean {
    const trimmed = line.trim();
    return trimmed === '' || trimmed.startsWith('#');
}
