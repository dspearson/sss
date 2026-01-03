import { SSSWrapper } from '../sssWrapper';
import * as vscode from 'vscode';
import {
    SINGLE_LINE_SECRET_REGEX,
    MULTILINE_SECRET_REGEX,
    extractSecretKey,
    extractSecretValue,
    isCommentOrEmpty
} from './regexPatterns';

export interface SecretKey {
    key: string;
    hasValue: boolean;
}

/**
 * Handles parsing of secrets files to extract keys and values
 */
export class SecretsFileParser {
    constructor(
        private sssWrapper: SSSWrapper,
        private outputChannel?: vscode.OutputChannel
    ) {}

    /**
     * Parse a secrets file to extract all key names
     */
    async parseSecretsFile(secretsFilePath: string): Promise<SecretKey[]> {
        try {
            const content = await this.sssWrapper.openAndRead(secretsFilePath);
            return this.parseSecretsContent(content);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to parse secrets file: ${error}`);
            return [];
        }
    }

    /**
     * Parse secrets file content to extract keys
     */
    parseSecretsContent(content: string): SecretKey[] {
        const keys: SecretKey[] = [];
        const lines = content.split('\n');

        for (const line of lines) {
            if (isCommentOrEmpty(line)) {
                continue;
            }

            const match = line.match(/^(.+?):\s*(.*)$/);
            if (match) {
                const key = match[1].trim();
                const value = match[2].trim();
                keys.push({
                    key,
                    hasValue: value.length > 0
                });
            }
        }

        return keys;
    }

    /**
     * Find the line number where a secret key is defined
     * Returns 0-indexed line number, or null if not found
     */
    async findSecretDefinitionLine(
        secretsFilePath: string,
        key: string
    ): Promise<number | null> {
        try {
            const content = await this.sssWrapper.openAndRead(secretsFilePath);
            return this.findKeyInContent(content, key);
        } catch (error) {
            this.log(`Error finding secret definition: ${error}`);
            return null;
        }
    }

    /**
     * Find a key's line number in the content
     */
    private findKeyInContent(content: string, key: string): number | null {
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            if (isCommentOrEmpty(line)) {
                continue;
            }

            // Check multiline format first
            const multiLineMatch = line.match(MULTILINE_SECRET_REGEX);
            if (multiLineMatch) {
                const secretKey = extractSecretKey(multiLineMatch);
                if (secretKey === key) {
                    return i;
                }
                continue;
            }

            // Check single-line format
            const singleLineMatch = line.match(SINGLE_LINE_SECRET_REGEX);
            if (singleLineMatch) {
                const secretKey = extractSecretKey(singleLineMatch);
                if (secretKey === key) {
                    return i;
                }
            }
        }

        return null;
    }

    /**
     * Look up a secret value by key
     * Returns null if not found
     */
    async lookupSecret(secretsFilePath: string, key: string): Promise<string | null> {
        try {
            const content = await this.sssWrapper.openAndRead(secretsFilePath);
            return this.lookupSecretInContent(content, key);
        } catch (error) {
            this.log(`Error looking up secret: ${error}`);
            return null;
        }
    }

    /**
     * Look up a secret value in content
     */
    private lookupSecretInContent(content: string, key: string): string | null {
        const lines = content.split('\n');
        let inMultilineValue = false;
        let multilineBuffer: string[] = [];
        let currentKey: string | null = null;

        for (const line of lines) {
            if (isCommentOrEmpty(line) && !inMultilineValue) {
                continue;
            }

            // Handle multiline continuation
            if (inMultilineValue) {
                if (this.isIndented(line)) {
                    multilineBuffer.push(line);
                    continue;
                } else {
                    // End of multiline value
                    inMultilineValue = false;
                    if (currentKey === key) {
                        return this.parseMultiLineValue(multilineBuffer);
                    }
                    multilineBuffer = [];
                    currentKey = null;
                }
            }

            // Check for multiline start
            const multiLineMatch = line.match(MULTILINE_SECRET_REGEX);
            if (multiLineMatch) {
                const secretKey = extractSecretKey(multiLineMatch);
                if (secretKey === key) {
                    currentKey = key;
                    inMultilineValue = true;
                }
                continue;
            }

            // Check for single-line format
            const singleLineMatch = line.match(SINGLE_LINE_SECRET_REGEX);
            if (singleLineMatch) {
                const secretKey = extractSecretKey(singleLineMatch);
                if (secretKey === key) {
                    return extractSecretValue(singleLineMatch);
                }
            }
        }

        // Handle case where file ends while in multiline value
        if (inMultilineValue && currentKey === key) {
            return this.parseMultiLineValue(multilineBuffer);
        }

        return null;
    }

    /**
     * Parse multiline value by finding common indentation and removing it
     */
    private parseMultiLineValue(lines: string[]): string {
        if (lines.length === 0) {
            return '';
        }

        // Find minimum indentation (ignoring empty lines)
        const nonEmptyLines = lines.filter(line => line.trim().length > 0);
        if (nonEmptyLines.length === 0) {
            return '';
        }

        const minIndent = Math.min(
            ...nonEmptyLines.map(line => line.length - line.trimStart().length)
        );

        // Remove common indentation from all lines
        return lines
            .map(line => (line.length >= minIndent ? line.substring(minIndent) : line))
            .join('\n')
            .trimEnd();
    }

    /**
     * Check if a line is indented (starts with whitespace)
     */
    private isIndented(line: string): boolean {
        return line.length > 0 && /^\s/.test(line);
    }

    private log(message: string): void {
        if (this.outputChannel) {
            this.outputChannel.appendLine(`[SecretsFileParser] ${message}`);
        }
    }
}
