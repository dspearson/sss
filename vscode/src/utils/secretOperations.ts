import * as vscode from 'vscode';
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

    // Append to secrets file via the document-edit API (routes through the
    // VS Code dirty-buffer lifecycle and fires onWillSaveTextDocument).
    const secretLine = `${secretName}: ${secretValue}\n`;
    const uri = vscode.Uri.file(secretsFilePath);

    const doc = await vscode.workspace.openTextDocument(uri);

    const edit = new vscode.WorkspaceEdit();
    const endPos = doc.lineAt(doc.lineCount - 1).range.end;
    edit.insert(uri, endPos, secretLine);
    const applied = await vscode.workspace.applyEdit(edit);
    if (!applied) {
        vscode.window.showErrorMessage(`Failed to add secret "${secretName}"`);
        return null;
    }

    await doc.save();

    showInfo(`Added secret "${secretName}" to secrets file`);
    return secretName;
}
