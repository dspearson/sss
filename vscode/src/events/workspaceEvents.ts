import * as vscode from 'vscode';
import { SSSStatusBar } from '../statusBar';
import { MESSAGES, BUTTONS } from '../constants';

/**
 * Workspace and UI-related event handlers
 */
export class WorkspaceEventHandlers {
    constructor(
        private statusBar: SSSStatusBar,
        private updateProjectContext: () => Promise<void>
    ) {}

    /**
     * Update status bar when active editor changes
     */
    handleDidChangeActiveTextEditor(): void {
        this.statusBar.update();
    }

    /**
     * Update context when workspace folders change
     */
    async handleDidChangeWorkspaceFolders(): Promise<void> {
        await this.updateProjectContext();
        await this.statusBar.update();
    }

    /**
     * Protect .sss.toml from accidental deletion
     */
    async handleWillDeleteFiles(event: vscode.FileWillDeleteEvent): Promise<void> {
        const sssTomlFiles = event.files.filter(uri => uri.fsPath.endsWith('.sss.toml'));

        if (sssTomlFiles.length === 0) {
            return;
        }

        event.waitUntil(this.confirmSssTomlDeletion());
    }

    private async confirmSssTomlDeletion(): Promise<void> {
        const result = await vscode.window.showWarningMessage(
            MESSAGES.DELETE_SSS_TOML_WARNING,
            { modal: true },
            BUTTONS.DELETE,
            BUTTONS.CANCEL
        );

        if (result !== BUTTONS.DELETE) {
            throw vscode.FileSystemError.NoPermissions('Deletion of .sss.toml cancelled by user');
        }
    }
}
