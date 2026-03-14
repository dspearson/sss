/**
 * SSS marker delimiter helpers — TypeScript mirror of the Rust
 * `src/marker_inference/marker_syntax.rs` and `src/processor/core.rs`
 * delimiter tables.
 *
 * When a value to be wrapped contains an unbalanced `}` (or any char that
 * would otherwise clash with the default `{}` pair), `pickDelimiter` walks
 * this ladder to find a non-colliding pair. The Rust scanner and the
 * VS Code marker regexes share the same table, so every pair accepted
 * here parses correctly on the CLI side.
 */

export const DELIMITER_PAIRS: ReadonlyArray<readonly [string, string]> = [
    ['{', '}'],
    ['[', ']'],
    ['\u{27E6}', '\u{27E7}'],   // ⟦ ⟧
    ['\u{27E8}', '\u{27E9}'],   // ⟨ ⟩
    ['\u{27EA}', '\u{27EB}'],   // ⟪ ⟫
    ['\u{27EC}', '\u{27ED}'],   // ⟬ ⟭
    ['\u{27EE}', '\u{27EF}'],   // ⟮ ⟯
    ['\u{2983}', '\u{2984}'],   // ⦃ ⦄
    ['\u{2985}', '\u{2986}'],   // ⦅ ⦆
    ['\u{2987}', '\u{2988}'],   // ⦇ ⦈
    ['\u{2989}', '\u{298A}'],   // ⦉ ⦊
    ['\u{298B}', '\u{298C}'],   // ⦋ ⦌
    ['\u{300C}', '\u{300D}'],   // 「 」
    ['\u{300E}', '\u{300F}'],   // 『 』
] as const;

/** Look up the closing delimiter for an opening char from the supported set. */
export function closeForOpen(open: string): string | undefined {
    const pair = DELIMITER_PAIRS.find(([o]) => o === open);
    return pair?.[1];
}

/** Whether `{` / `}` in `value` balance — every `}` has a matching `{` before it. */
function bracesBalance(value: string): boolean {
    let depth = 0;
    for (const ch of value) {
        if (ch === '{') {
            depth++;
        } else if (ch === '}') {
            depth--;
            if (depth < 0) {
                return false;
            }
        }
    }
    return depth === 0;
}

/**
 * Pick a delimiter pair whose chars don't collide with `value`.
 *
 * `{}` is preferred when braces balance (keeps existing files byte-identical),
 * otherwise we walk the ladder. Falls back to `{}` when nothing fits —
 * unreachable in practice given the table's breadth.
 */
export function pickDelimiter(value: string): readonly [string, string] {
    if (bracesBalance(value)) {
        return ['{', '}'];
    }
    for (let i = 1; i < DELIMITER_PAIRS.length; i++) {
        const [open, close] = DELIMITER_PAIRS[i];
        if (!value.includes(open) && !value.includes(close)) {
            return [open, close];
        }
    }
    return ['{', '}'];
}

/**
 * Emit a marker with a content-determined delimiter pair. Mirrors the Rust
 * `format_marker(prefix, value)` helper. Use this everywhere the extension
 * synthesises a new marker (wrap selection, insert interpolation, etc.).
 */
export function formatMarker(prefix: string, value: string): string {
    const [open, close] = pickDelimiter(value);
    return `${prefix}${open}${value}${close}`;
}

const CHAR_CLASS_META = new Set([']', '\\', '^', '-']);
const REGEX_META = new Set(['.', '*', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\']);

function escapeForCharClass(ch: string): string {
    return CHAR_CLASS_META.has(ch) ? `\\${ch}` : ch;
}

function escapeLiteral(s: string): string {
    let out = '';
    for (const ch of s) {
        out += REGEX_META.has(ch) ? `\\${ch}` : ch;
    }
    return out;
}

/**
 * Build a global regex that matches any marker with one of `prefixes`
 * (e.g. `'⊕'`, `'o+'`) across every supported delimiter pair. The content
 * is captured in one of many groups — use `extractMarkerContent` to read it.
 */
export function buildMarkerRegex(prefixes: readonly string[]): RegExp {
    const prefixAlt = prefixes.map(escapeLiteral).join('|');
    const pairAlt = DELIMITER_PAIRS.map(([open, close]) =>
        `${escapeLiteral(open)}([^${escapeForCharClass(close)}]*)${escapeLiteral(close)}`
    ).join('|');
    return new RegExp(`(?:${prefixAlt})(?:${pairAlt})`, 'gu');
}

/**
 * Extract the captured content from a marker match. A `buildMarkerRegex`
 * regex has one capture group per delimiter pair, so only one slot is
 * populated per match; return the first non-undefined group.
 */
export function extractMarkerContent(match: RegExpMatchArray): string {
    for (let i = 1; i < match.length; i++) {
        if (match[i] !== undefined) {
            return match[i];
        }
    }
    return '';
}

/** Lookahead alternation matching any supported opening delimiter char. */
function openersLookahead(): string {
    const openers = DELIMITER_PAIRS.map(p => escapeForCharClass(p[0])).join('');
    return `(?=[${openers}])`;
}

/**
 * Regex matching an unnormalised ASCII prefix (`o+` or `<`) immediately
 * followed by any supported opener — used by the auto-normalise pipeline.
 * Stateful (/g); reset `lastIndex` before reuse.
 */
export function asciiPrefixScanRegex(): RegExp {
    const look = openersLookahead();
    return new RegExp(`(o\\+|<)${look}`, 'gu');
}

/**
 * Replace every ASCII prefix (`o+`/`<`) that precedes a supported opener
 * with its Unicode canonical form (`⊕`/`⊲`). Leaves the delimiter untouched.
 */
export function normaliseAsciiPrefixes(text: string): string {
    const look = openersLookahead();
    const oplus = new RegExp(`o\\+${look}`, 'gu');
    const lt = new RegExp(`<${look}`, 'gu');
    return text.replace(oplus, '⊕').replace(lt, '⊲');
}

/** Whether `text` contains at least one ASCII-prefix marker. */
export function hasAsciiMarker(text: string): boolean {
    return asciiPrefixScanRegex().test(text);
}
