import * as vscode from 'vscode';
import * as fs from 'fs';
import { promptForNonEmptyInput, showInfo } from './uiHelpers';

/**
 * Operations for managing secrets in secrets files
 */

/**
 * Add a new secret to a secrets file
 * Prompts for secret name and value, then appends to file
 * Returns the secret name if successful, null if cancelled
 */
export async function addSecretToFile(secretsFilePath: string): Promise<string | null> {
    const secretName = await promptForNonEmptyInput(
        'Enter secret name (e.g., "database password", "api key")',
        'database password',
        'Secret name'
    );

    if (!secretName) {
        return null;
    }

    const secretValue = await promptForNonEmptyInput(
        `Enter value for "${secretName}"`,
        'secret-value-here',
        'Secret value'
    );

    if (!secretValue) {
        return null;
    }

    // Append to secrets file
    const secretLine = `${secretName}: ${secretValue}\n`;
    fs.appendFileSync(secretsFilePath, secretLine);

    showInfo(`Added secret "${secretName}" to secrets file`);
    return secretName;
}
