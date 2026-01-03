import * as vscode from 'vscode';
import * as path from 'path';
import { SSSWrapper } from '../sssWrapper';
import { SSSRenderProvider } from '../types';
import { URI_SCHEMES, MARKER_SEQUENCES } from '../constants';

/**
 * File operation commands (seal, open, render, etc.)
 */
export class FileCommands {
    constructor(
        private sssWrapper: SSSWrapper,
        private renderProvider: SSSRenderProvider,
        private outputChannel: vscode.OutputChannel
    ) {}

    async sealFile(uri?: vscode.Uri): Promise<void> {
        const targetUri = this.getTargetFileUri(uri);
        const filePath = targetUri?.fsPath;

        if (!filePath) {
            vscode.window.showErrorMessage('No file selected');
            return;
        }

        try {
            await this.sssWrapper.seal(filePath);

            const doc = await vscode.workspace.openTextDocument(filePath);
            await vscode.window.showTextDocument(doc);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to seal file: ${error.message}`);
        }
    }

    async openFile(uri?: vscode.Uri): Promise<void> {
        const targetUri = this.getTargetFileUri(uri);

        if (!targetUri) {
            vscode.window.showErrorMessage('No file selected');
            return;
        }

        try {
            await this.sssWrapper.ensureAuthenticated();

            const filePath = targetUri.scheme === URI_SCHEMES.SSS_FS ? targetUri.path : targetUri.fsPath;
            const sssUri = vscode.Uri.parse(`${URI_SCHEMES.SSS_FS}://${filePath}`);

            // Close current editor if same file
            const currentEditor = vscode.window.activeTextEditor;
            if (currentEditor && currentEditor.document.uri.toString() === targetUri.toString()) {
                await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            }

            const doc = await vscode.workspace.openTextDocument(sssUri);
            await vscode.window.showTextDocument(doc);

            this.outputChannel.appendLine(`[Open File] Opened with sss-fs://: ${filePath}`);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to open file: ${error.message}`);
        }
    }

    async renderFile(uri?: vscode.Uri): Promise<void> {
        const targetUri = this.getTargetFileUri(uri);
        const filePath = targetUri?.fsPath;

        if (!filePath) {
            vscode.window.showErrorMessage('No file selected');
            return;
        }

        try {
            const rendered = await this.sssWrapper.render(filePath);

            const fileName = path.basename(filePath);
            const virtualUri = vscode.Uri.parse(`${URI_SCHEMES.SSS_RENDER}:${fileName} (Rendered)`);

            this.renderProvider.setContent(virtualUri, rendered);

            const doc = await vscode.workspace.openTextDocument(virtualUri);
            await vscode.window.showTextDocument(doc, { preview: true });
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to render file: ${error.message}`);
        }
    }

    async wrapSelection(): Promise<void> {
        const editor = vscode.window.activeTextEditor;

        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selection = editor.selection;
        if (selection.isEmpty) {
            vscode.window.showErrorMessage('No text selected');
            return;
        }

        const selectedText = editor.document.getText(selection);
        const wrappedText = `${MARKER_SEQUENCES.PLAINTEXT_OPEN}${selectedText}}`;

        await editor.edit(editBuilder => {
            editBuilder.replace(selection, wrappedText);
        });

        vscode.window.showInformationMessage(`Text wrapped with ${MARKER_SEQUENCES.PLAINTEXT_OPEN}...} marker`);
    }

    async normaliseMarkers(): Promise<void> {
        const editor = vscode.window.activeTextEditor;

        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const document = editor.document;
        let text = document.getText();
        let changesMade = false;

        // o+{...} → ⊕{...}
        if (text.includes(MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN)) {
            text = text.replaceAll(MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN, MARKER_SEQUENCES.PLAINTEXT_OPEN);
            changesMade = true;
        }

        // <{...} → ⊲{...}
        if (text.includes(MARKER_SEQUENCES.INTERPOLATION_ALT_OPEN)) {
            text = text.replaceAll(MARKER_SEQUENCES.INTERPOLATION_ALT_OPEN, MARKER_SEQUENCES.INTERPOLATION_OPEN);
            changesMade = true;
        }

        if (changesMade) {
            const fullRange = new vscode.Range(
                document.positionAt(0),
                document.positionAt(document.getText().length)
            );

            await editor.edit(editBuilder => {
                editBuilder.replace(fullRange, text);
            });

            vscode.window.showInformationMessage('Markers normalised to UTF-8 format');
        } else {
            vscode.window.showInformationMessage('No markers to normalise');
        }
    }

    async sealWorkspace(): Promise<void> {
        if (!vscode.workspace.workspaceFolders) {
            vscode.window.showErrorMessage('No workspace open');
            return;
        }

        try {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Sealing workspace files...',
                cancellable: false
            }, async () => {
                await this.sssWrapper.sealAll();
            });

            vscode.window.showInformationMessage('Workspace files sealed successfully');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to seal workspace: ${error.message}`);
        }
    }

    async openWorkspace(): Promise<void> {
        if (!vscode.workspace.workspaceFolders) {
            vscode.window.showErrorMessage('No workspace open');
            return;
        }

        try {
            await this.sssWrapper.ensureAuthenticated();

            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Opening workspace files...',
                cancellable: false
            }, async () => {
                const result = await this.sssWrapper.openAll();
                this.outputChannel.appendLine(`[Open Workspace] Result: ${result}`);
            });

            // Refresh all open editors to show decrypted content
            await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');

            // Reload window to refresh all file decorations
            const choice = await vscode.window.showInformationMessage(
                'Workspace files opened. Reload window to see changes?',
                'Reload',
                'Later'
            );

            if (choice === 'Reload') {
                await vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to open workspace: ${error.message}`);
        }
    }

    private getTargetFileUri(uri?: vscode.Uri): vscode.Uri | undefined {
        if (uri) {
            return uri;
        }

        const explorer = vscode.window.activeTextEditor?.document.uri;
        if (explorer && explorer.scheme === URI_SCHEMES.FILE) {
            return explorer;
        }

        return vscode.window.activeTextEditor?.document.uri;
    }
}
