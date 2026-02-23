import * as vscode from 'vscode';
import { SSSWrapper } from '../sssWrapper';
import { BinaryDownloader } from '../binaryDownloader';
import { TreeViewProviders } from './types';

/**
 * Configuration and settings commands
 */
export class ConfigCommands {
    constructor(
        private sssWrapper: SSSWrapper,
        private binaryDownloader: BinaryDownloader,
        private treeProviders: TreeViewProviders
    ) {}

    async toggleAutoSeal(): Promise<void> {
        if (!this.hasWorkspace()) {
            return;
        }

        try {
            const config = vscode.workspace.getConfiguration('secrets');
            const current = config.get<boolean>('autoSealOnSave', true);
            await config.update('autoSealOnSave', !current, vscode.ConfigurationTarget.Workspace);
            vscode.window.showInformationMessage(
                `Auto-seal & write: ${!current ? 'enabled' : 'disabled'}`
            );
            this.treeProviders.actions.refresh();
        } catch (error: any) {
            vscode.window.showErrorMessage(
                `Failed to toggle auto-seal setting: ${error.message || error}`
            );
        }
    }

    async toggleAutoOpen(): Promise<void> {
        if (!this.hasWorkspace()) {
            return;
        }

        try {
            const config = vscode.workspace.getConfiguration('secrets');
            const current = config.get<boolean>('autoOpenOnLoad', false);
            await config.update('autoOpenOnLoad', !current, vscode.ConfigurationTarget.Workspace);
            vscode.window.showInformationMessage(
                `Auto-open & write: ${!current ? 'enabled' : 'disabled'}`
            );
            this.treeProviders.actions.refresh();
        } catch (error: any) {
            vscode.window.showErrorMessage(
                `Failed to toggle auto-open setting: ${error.message || error}`
            );
        }
    }

    openSettings(): void {
        vscode.commands.executeCommand('workbench.action.openSettings', 'secrets');
    }

    clearPassword(): void {
        this.sssWrapper.clearCachedPassword();
        vscode.window.showInformationMessage('Cached password cleared');
    }

    async updateBinary(): Promise<void> {
        try {
            await this.binaryDownloader.updateBinary();
            vscode.window.showInformationMessage(
                'sss binary updated. Please reload the window for changes to take effect.'
            );
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to update sss binary: ${error.message}`);
        }
    }

    private hasWorkspace(): boolean {
        if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
            vscode.window.showErrorMessage('Cannot toggle setting: No workspace folder is open');
            return false;
        }
        return true;
    }
}
