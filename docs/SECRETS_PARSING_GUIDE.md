# Secrets File Parsing Guide for VSCode Extension

This guide explains how to parse `.secrets` files for displaying secret values in tooltips when hovering over interpolation markers (`⊲{key}` or `<{key}`).

## Format Overview

Secrets files support two formats that can be mixed in the same file:

1. **Single-line format**: `key: value`
2. **Multi-line format**: `key: |` followed by indented lines

## Regex Patterns

### Single-Line Pattern

```regex
^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|(.*))\s*$
```

**Captures:**
- Group 1, 2, or 3: The key (double-quoted, single-quoted, or unquoted)
- Group 4, 5, or 6: The value (double-quoted, single-quoted, or unquoted)

**Examples:**
```
api_key: secret123           → key="api_key", value="secret123"
"my key": value              → key="my key", value="value"
username: "john doe"         → key="username", value="john doe"
```

### Multi-Line Indicator Pattern

```regex
^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*\|\s*$
```

**Captures:**
- Group 1, 2, or 3: The key (double-quoted, single-quoted, or unquoted)

**What it matches:**
- `key: |` (pipe indicator at end of line)
- `"my key": |`
- `'my_key': |`

## Parsing Algorithm

### High-Level Flow

```
For each line in the file:
  1. Skip if empty or starts with '#' (comment)
  2. Check if it matches multi-line indicator pattern
     - If yes: collect multi-line value
     - If no: try single-line pattern
  3. Store key-value pair
```

### Single-Line Parsing

```javascript
function parseSingleLine(line) {
  // Skip comments and empty lines
  if (line.trim() === '' || line.trim().startsWith('#')) {
    return null;
  }

  const singleLineRegex = /^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|(.*))\s*$/;
  const match = line.match(singleLineRegex);

  if (!match) {
    return null;
  }

  // Extract key (from first non-null capture group 1-3)
  const key = match[1] || match[2] || match[3];

  // Extract value (from first non-null capture group 4-6)
  const value = match[4] || match[5] || match[6];

  return { key: key.trim(), value: value.trim() };
}
```

### Multi-Line Parsing

This is the tricky part. Here's the step-by-step algorithm:

```javascript
function parseMultiLine(lines, startIndex) {
  // startIndex points to the line AFTER "key: |"

  const valueLines = [];
  let baseIndent = null;
  let currentIndex = startIndex;

  while (currentIndex < lines.length) {
    const line = lines[currentIndex];

    // Handle empty lines - preserve them
    if (line.trim() === '') {
      valueLines.push('');
      currentIndex++;
      continue;
    }

    // Calculate indentation
    const indent = line.length - line.trimStart().length;

    // First non-empty line sets base indentation
    if (baseIndent === null) {
      if (indent === 0) {
        // No indentation = end of multi-line value
        break;
      }
      baseIndent = indent;
    }

    // Line dedented below base = end of multi-line value
    if (indent < baseIndent) {
      break;
    }

    // Calculate relative indentation and dedent
    const relativeIndent = indent - baseIndent;
    const dedentedLine = ' '.repeat(relativeIndent) + line.trimStart();

    valueLines.push(dedentedLine);
    currentIndex++;
  }

  // Join lines with newlines
  const value = valueLines.join('\n');
  const linesConsumed = currentIndex - startIndex;

  return { value, linesConsumed };
}
```

### Complete Parsing Example

```javascript
function parseSecretsFile(content) {
  const lines = content.split('\n');
  const secrets = {};
  let i = 0;

  const multiLineRegex = /^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*\|\s*$/;

  while (i < lines.length) {
    const line = lines[i];

    // Skip empty lines and comments
    if (line.trim() === '' || line.trim().startsWith('#')) {
      i++;
      continue;
    }

    // Check for multi-line indicator
    const multiLineMatch = line.match(multiLineRegex);
    if (multiLineMatch) {
      // Extract key
      const key = multiLineMatch[1] || multiLineMatch[2] || multiLineMatch[3];

      // Parse multi-line value starting from next line
      i++; // Move to first line after "key: |"
      const { value, linesConsumed } = parseMultiLine(lines, i);

      secrets[key.trim()] = value;
      i += linesConsumed;
      continue;
    }

    // Try single-line format
    const singleLine = parseSingleLine(line);
    if (singleLine) {
      secrets[singleLine.key] = singleLine.value;
    }

    i++;
  }

  return secrets;
}
```

## Indentation Handling Details

### Key Rules

1. **Base indentation** is set by the first non-empty line after `key: |`
2. **Relative indentation** is preserved (important for nested structures)
3. **Empty lines** are preserved as empty strings
4. **Dedentation** stops collection when a line has less indentation than base

### Example 1: Simple Multi-Line

```
ssh_key: |
  -----BEGIN KEY-----
  abc123
  -----END KEY-----
```

**Parsing:**
- Line 1: `  -----BEGIN KEY-----` → base_indent = 2
- Line 2: `  abc123` → relative_indent = 0, keep
- Line 3: `  -----END KEY-----` → relative_indent = 0, keep

**Result:**
```
"-----BEGIN KEY-----\nabc123\n-----END KEY-----"
```

### Example 2: Nested JSON

```
config: |
  {
    "nested": {
      "value": "test"
    }
  }
```

**Parsing:**
- Line 1: `  {` → base_indent = 2, relative_indent = 0
- Line 2: `    "nested": {` → indent = 4, relative_indent = 2
- Line 3: `      "value": "test"` → indent = 6, relative_indent = 4
- Line 4: `    }` → indent = 4, relative_indent = 2
- Line 5: `  }` → indent = 2, relative_indent = 0

**Result:**
```json
{
  "nested": {
    "value": "test"
  }
}
```

Notice the relative indentation is preserved!

### Example 3: Empty Lines

```
text: |
  First paragraph

  Second paragraph
```

**Parsing:**
- Line 1: `  First paragraph` → base_indent = 2
- Line 2: `` (empty) → preserve as empty string
- Line 3: `  Second paragraph`

**Result:**
```
"First paragraph\n\nSecond paragraph"
```

### Example 4: Stopping at Dedented Line

```
value1: |
  line1
  line2
value2: simple
```

**Parsing `value1`:**
- Line 1: `  line1` → base_indent = 2
- Line 2: `  line2` → continue
- Line 3: `value2: simple` → indent = 0, dedented below base, STOP

**Result for `value1`:** `"line1\nline2"`

## VSCode Extension Tooltip Implementation

### Detecting Interpolation Markers

When the user hovers over text, check if they're hovering over an interpolation marker:

```typescript
// Regex to find interpolation markers
const markerRegex = /[⊲<]\{([^}]+)\}/g;

function getSecretKeyAtPosition(document: vscode.TextDocument, position: vscode.Position): string | null {
  const line = document.lineAt(position.line);
  const matches = line.text.matchAll(markerRegex);

  for (const match of matches) {
    const startPos = match.index!;
    const endPos = startPos + match[0].length;
    const charPos = position.character;

    if (charPos >= startPos && charPos <= endPos) {
      return match[1]; // Return the key name
    }
  }

  return null;
}
```

### Finding the Secrets File

Based on the configured `secrets_filename` and `secrets_suffix`:

```typescript
async function findSecretsFile(
  currentFile: vscode.Uri,
  projectRoot: vscode.Uri,
  config: { filename: string, suffix: string }
): Promise<vscode.Uri | null> {
  // Strategy 1: Check for file-specific secrets (currentFile + suffix)
  const fileSpecific = vscode.Uri.file(currentFile.fsPath + config.suffix);
  if (await fileExists(fileSpecific)) {
    return fileSpecific;
  }

  // Strategy 2: Search upward for centralized secrets file
  let dir = path.dirname(currentFile.fsPath);
  const rootPath = projectRoot.fsPath;

  while (true) {
    const secretsPath = vscode.Uri.file(path.join(dir, config.filename));
    if (await fileExists(secretsPath)) {
      return secretsPath;
    }

    if (dir === rootPath) {
      break;
    }

    const parent = path.dirname(dir);
    if (parent === dir) {
      break; // Reached filesystem root
    }
    dir = parent;
  }

  return null;
}
```

### Displaying in Tooltip

```typescript
async function provideHover(
  document: vscode.TextDocument,
  position: vscode.Position
): Promise<vscode.Hover | null> {
  const secretKey = getSecretKeyAtPosition(document, position);
  if (!secretKey) {
    return null;
  }

  // Find and parse secrets file
  const secretsFile = await findSecretsFile(document.uri, projectRoot, config);
  if (!secretsFile) {
    return new vscode.Hover(`Secret '${secretKey}' - No secrets file found`);
  }

  const secrets = await parseSecretsFile(secretsFile);
  const value = secrets[secretKey];

  if (!value) {
    return new vscode.Hover(`Secret '${secretKey}' - Not found in ${secretsFile.fsPath}`);
  }

  // Format the hover content
  const markdown = new vscode.MarkdownString();
  markdown.appendMarkdown(`**Secret:** \`${secretKey}\`\n\n`);

  // Render multi-line values in a code block
  if (value.includes('\n')) {
    markdown.appendMarkdown('```\n');
    markdown.appendText(value);
    markdown.appendMarkdown('\n```');
  } else {
    markdown.appendCodeblock(value, '');
  }

  markdown.appendMarkdown(`\n\n*From: ${path.basename(secretsFile.fsPath)}*`);

  return new vscode.Hover(markdown);
}
```

## Example Tooltip Rendering

### For Single-Line Secret

**Secrets file:**
```
api_key: sk-1234567890abcdef
```

**Hover over:** `⊲{api_key}`

**Tooltip shows:**
```
Secret: api_key

sk-1234567890abcdef

From: secrets
```

### For Multi-Line Secret (SSH Key)

**Secrets file:**
```
ssh_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
  -----END OPENSSH PRIVATE KEY-----
```

**Hover over:** `⊲{ssh_key}`

**Tooltip shows:**
```
Secret: ssh_key

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
-----END OPENSSH PRIVATE KEY-----

From: secrets
```

### For Multi-Line Secret (JSON)

**Secrets file:**
```
config: |
  {
    "region": "us-west-2",
    "credentials": {
      "key": "AKIAIOSFODNN7EXAMPLE"
    }
  }
```

**Hover over:** `⊲{config}`

**Tooltip shows:**
```
Secret: config

{
  "region": "us-west-2",
  "credentials": {
    "key": "AKIAIOSFODNN7EXAMPLE"
  }
}

From: config.yaml.secrets
```

## Edge Cases to Handle

### 1. Trailing Newlines

YAML `|` indicator preserves trailing newlines. You may want to `.trimEnd()` for display:

```typescript
const displayValue = value.trimEnd();
```

### 2. Very Long Values

Truncate very long secrets in tooltips:

```typescript
const MAX_DISPLAY_LENGTH = 500;
let displayValue = value;

if (displayValue.length > MAX_DISPLAY_LENGTH) {
  displayValue = displayValue.substring(0, MAX_DISPLAY_LENGTH) + '\n\n... (truncated)';
}
```

### 3. Encrypted Secrets Files

If the secrets file starts with `⊠{`, it's encrypted. Show a message:

```typescript
const content = await fs.readFile(secretsFile.fsPath, 'utf8');
if (content.trim().startsWith('⊠{')) {
  return new vscode.Hover(`Secret '${secretKey}' - Secrets file is encrypted. Run 'sss open' to decrypt.`);
}
```

### 4. Syntax Highlighting

For known formats, apply syntax highlighting in the code block:

```typescript
// Try to detect format
let language = '';
if (value.trim().startsWith('{') || value.trim().startsWith('[')) {
  language = 'json';
} else if (value.includes('-----BEGIN')) {
  language = 'pem';
} else if (value.includes('host=') || value.includes('port=')) {
  language = 'properties';
}

markdown.appendCodeblock(value, language);
```

## Configuration Reading

Read from `.sss.toml` (project config):

```toml
secrets_filename = "passwords"
secrets_suffix = ".sealed"
```

And from `~/.config/sss/settings.toml` (user config):

```toml
secrets_filename = ".secrets"
secrets_suffix = ".passwords"
```

**Precedence:** Project config > User config > Defaults (`"secrets"`, `".secrets"`)

## Summary

**Key points for the extension:**

1. **Two formats**: Single-line (`key: value`) and multi-line (`key: |` + indented lines)
2. **Indentation matters**: Base indent set by first non-empty line, relative indent preserved
3. **Empty lines preserved**: Don't skip them in multi-line values
4. **Stopping condition**: Collection stops when line dedents below base
5. **File discovery**: Check suffix-based file first, then search upward for filename-based
6. **Tooltip rendering**: Use code blocks for multi-line, truncate if needed
7. **Handle encryption**: Check if file starts with `⊠{`

The parsing logic is deterministic and well-defined, so implementing this in TypeScript for VSCode should be straightforward!
