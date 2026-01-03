import * as vscode from 'vscode';
import { SSSWrapper } from '../sssWrapper';
import { ProjectManager } from '../projectManager';
import { GitIntegration } from '../gitIntegration';
import { TreeViewProviders } from './types';

/**
 * Project management commands
 */
export class ProjectCommands {
    constructor(
        private sssWrapper: SSSWrapper,
        private projectManager: ProjectManager,
        private gitIntegration: GitIntegration | null,
        private treeProviders: TreeViewProviders,
        private updateProjectContext: () => Promise<void>
    ) {}

    async renderProject(): Promise<void> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const confirmed = await this.confirmDestructiveOperation();
        if (!confirmed) {
            return;
        }

        try {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Rendering project to plaintext...',
                    cancellable: false
                },
                async () => {
                    await this.sssWrapper.renderProject(workspaceFolder.uri.fsPath);
                }
            );

            vscode.window.showInformationMessage('Project rendered to plaintext successfully');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to render project: ${error.message}`);
        }
    }

    async initProject(): Promise<void> {
        await this.projectManager.initProject();
        await this.updateProjectContext();
        this.refreshAllViews();
    }

    showProjectInfo(): void {
        this.projectManager.showProjectInfo();
    }

    async installHooks(): Promise<void> {
        if (!this.gitIntegration) {
            vscode.window.showErrorMessage('Git integration not initialised');
            return;
        }
        await this.gitIntegration.installHooks();
    }

    private async confirmDestructiveOperation(): Promise<boolean> {
        const confirmation = await vscode.window.showWarningMessage(
            'WARNING: This will permanently convert all encrypted secrets to plaintext. ' +
            'This is ONE-WAY and DESTRUCTIVE. You CANNOT undo this operation. ' +
            'Are you absolutely sure?',
            'Render to Plaintext'
        );

        return confirmation === 'Render to Plaintext';
    }

    private refreshAllViews(): void {
        this.treeProviders.project.refresh();
        this.treeProviders.users.refresh();
        this.treeProviders.keys.refresh();
        this.treeProviders.actions.refresh();
    }
}
