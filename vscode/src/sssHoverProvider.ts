import * as vscode from 'vscode';
import * as path from 'path';
import { SSSWrapper } from './sssWrapper';
import { SecretsFileLocator, SecretsFileParser, INTERPOLATION_MARKER_REGEX, extractMarkerContent } from './utils';
import { DISPLAY } from './constants';

/**
 * Provides hover information for sss interpolated references
 * Shows the actual secret value when hovering over ⊲{key} or <{key} markers
 */
export class SSSHoverProvider implements vscode.HoverProvider {
    private locator: SecretsFileLocator;
    private parser: SecretsFileParser;

    constructor(private sssWrapper: SSSWrapper, private outputChannel: vscode.OutputChannel) {
        this.locator = new SecretsFileLocator(sssWrapper, outputChannel);
        this.parser = new SecretsFileParser(sssWrapper, outputChannel);
    }

    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | undefined> {
        this.outputChannel.appendLine(`[provideHover] Called for document: ${document.uri.toString()}`);

        // Get the word range at the position
        const line = document.lineAt(position.line);
        const text = line.text;

        // Find if we're inside an interpolated reference marker
        const reference = this.findReferenceAtPosition(text, position.character);
        if (!reference) {
            this.outputChannel.appendLine(`[provideHover] No reference found at position`);
            return undefined;
        }

        this.outputChannel.appendLine(`[provideHover] Found reference: ${reference.key}`);

        // Get the actual file path (handle both file:// and sss-fs:// schemes)
        const actualPath = document.uri.scheme === 'sss-fs' ? document.uri.path : document.uri.fsPath;
        this.outputChannel.appendLine(`[provideHover] Actual path: ${actualPath}`);

        // Find the secrets file
        const secretsFile = await this.locator.findSecretsFile(actualPath);
        this.outputChannel.appendLine(`[provideHover] findSecretsFile returned: ${secretsFile}`);

        if (!secretsFile) {
            this.outputChannel.appendLine(`[provideHover] No secrets file found, returning error hover`);
            return new vscode.Hover(
                new vscode.MarkdownString(`**Secret Reference:** \`${reference.key}\`\n\n⚠️ No secrets file found`)
            );
        }

        // Look up the secret value
        let secretValue = await this.parser.lookupSecret(secretsFile, reference.key);

        if (secretValue === null) {
            return new vscode.Hover(
                new vscode.MarkdownString(`**Secret Reference:** \`${reference.key}\`\n\n⚠️ Key not found in secrets file`)
            );
        }

        // Create hover content
        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;
        markdown.appendMarkdown(`**Secret:** \`${reference.key}\`\n\n`);

        // Truncate very long values
        let isTruncated = false;
        if (secretValue.length > DISPLAY.SECRET_MAX_LENGTH) {
            secretValue = secretValue.substring(0, DISPLAY.SECRET_MAX_LENGTH);
            isTruncated = true;
        }

        // Format based on single-line vs multiline
        const formattedValue = this.formatSecretValueMarkdown(secretValue, isTruncated);
        markdown.appendMarkdown(formattedValue);
        markdown.appendMarkdown(`*From: ${path.basename(secretsFile)}*`);

        return new vscode.Hover(markdown, reference.range);
    }

    /**
     * Find interpolated reference at the given position
     * Returns the key and range if found
     */
    private findReferenceAtPosition(text: string, character: number): { key: string; range: vscode.Range } | null {
        // Rebuild from source so we own `lastIndex` — the shared constant is /g.
        const interpolationRegex = new RegExp(INTERPOLATION_MARKER_REGEX.source, 'gu');
        let match;

        while ((match = interpolationRegex.exec(text))) {
            const start = match.index;
            const end = match.index + match[0].length;

            // Check if cursor is within this match
            if (character >= start && character <= end) {
                const key = extractMarkerContent(match);
                return {
                    key,
                    range: new vscode.Range(
                        new vscode.Position(0, start),
                        new vscode.Position(0, end)
                    )
                };
            }
        }

        return null;
    }

    private formatSecretValueMarkdown(secretValue: string, isTruncated: boolean): string {
        if (secretValue.includes('\n')) {
            return this.formatMultilineValue(secretValue, isTruncated);
        }
        return this.formatSingleLineValue(secretValue, isTruncated);
    }

    private formatMultilineValue(secretValue: string, isTruncated: boolean): string {
        let language = this.detectLanguage(secretValue);
        let markdown = '```' + language + '\n';
        markdown += secretValue.trimEnd();
        if (isTruncated) {
            markdown += '\n\n... (truncated)';
        }
        markdown += '\n```\n\n';
        return markdown;
    }

    private formatSingleLineValue(secretValue: string, isTruncated: boolean): string {
        let markdown = `\`${secretValue}\``;
        if (isTruncated) {
            markdown += ` *(truncated)*`;
        }
        markdown += '\n\n';
        return markdown;
    }

    private detectLanguage(value: string): string {
        const trimmedValue = value.trim();
        if (trimmedValue.startsWith('{') || trimmedValue.startsWith('[')) {
            return 'json';
        } else if (value.includes('-----BEGIN')) {
            return 'pem';
        }
        return '';
    }
}
