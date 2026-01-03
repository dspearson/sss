import * as vscode from 'vscode';
import { SSSWrapper } from './sssWrapper';
import { activationComplete } from './extension';
import { DISPLAY } from './constants';

// Base tree item class
class SSSTreeItem extends vscode.TreeItem {
    public keyUuid?: string;  // Store full key UUID for context commands

    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue?: string
    ) {
        super(label, collapsibleState);
    }
}

// Base tree data provider with common functionality
abstract class BaseTreeProvider implements vscode.TreeDataProvider<SSSTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<SSSTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(protected sssWrapper: SSSWrapper) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: SSSTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: SSSTreeItem): Promise<SSSTreeItem[]> {
        // Wait for activation and authentication to complete
        if (activationComplete) {
            await activationComplete;
        }

        if (!element) {
            return await this.getRootChildren();
        }
        return [];
    }

    protected abstract getRootChildren(): Promise<SSSTreeItem[]>;
}

// Helper functions for creating common tree item patterns
function createTreeItem(
    label: string,
    icon: string,
    options?: {
        tooltip?: string;
        description?: string;
        contextValue?: string;
        command?: vscode.Command;
        keyUuid?: string;
    }
): SSSTreeItem {
    const item = new SSSTreeItem(
        label,
        vscode.TreeItemCollapsibleState.None,
        options?.contextValue
    );
    item.iconPath = new vscode.ThemeIcon(icon);
    if (options?.tooltip) item.tooltip = options.tooltip;
    if (options?.description) item.description = options.description;
    if (options?.command) item.command = options.command;
    if (options?.keyUuid) item.keyUuid = options.keyUuid;
    return item;
}

function createErrorItem(message: string): SSSTreeItem {
    return createTreeItem(message, 'error');
}

function createEmptyItem(message: string): SSSTreeItem {
    return createTreeItem(message, 'info');
}

function createActionItem(label: string, icon: string, command: string): SSSTreeItem {
    return createTreeItem(label, icon, {
        command: { command, title: label }
    });
}

// Project View - Shows project information
export class ProjectViewProvider extends BaseTreeProvider {
    protected async getRootChildren(): Promise<SSSTreeItem[]> {
        try {
            const [projectInfo, currentKey] = await Promise.all([
                this.sssWrapper.checkProjectStatus(),
                this.sssWrapper.getCurrentKey()
            ]);

            const items: SSSTreeItem[] = [];

            if (projectInfo.projectRoot) {
                items.push(createTreeItem(
                    `Root: ${projectInfo.projectRoot}`,
                    'root-folder'
                ));
            }

            if (currentKey) {
                items.push(createTreeItem(
                    `Current Key: ${currentKey.substring(0, DISPLAY.UUID_LENGTH)}...`,
                    'key',
                    { tooltip: currentKey }
                ));
            }

            return items;
        } catch (error) {
            return [createErrorItem('Not a Secret String Substitution project')];
        }
    }
}

// Users View - Shows project users
export class UsersViewProvider extends BaseTreeProvider {
    protected async getRootChildren(): Promise<SSSTreeItem[]> {
        try {
            const users = await this.sssWrapper.listUsers();

            if (users.length === 0) {
                return [createEmptyItem('No users found')];
            }

            const currentPublicKey = await this.getCurrentPublicKey();
            const isLastUser = users.length === 1;

            return users.map(user => this.createUserItem(user, currentPublicKey, isLastUser));
        } catch (error) {
            return [createErrorItem('Error loading users')];
        }
    }

    private async getCurrentPublicKey(): Promise<string | null> {
        try {
            return await this.sssWrapper.getPublicKey();
        } catch (error) {
            return null;
        }
    }

    private createUserItem(
        user: any,
        currentPublicKey: string | null,
        isLastUser: boolean
    ): SSSTreeItem {
        const isCurrentUser = currentPublicKey && user.publicKey === currentPublicKey;
        const contextValue = (isCurrentUser || isLastUser) ? 'user-protected' : 'user';

        return createTreeItem(
            user.username,
            isCurrentUser ? 'account' : 'person',
            {
                contextValue,
                tooltip: `Public key: ${user.publicKey}${isCurrentUser ? '\n(Current user)' : ''}`,
                description: isCurrentUser ? '(current)' : user.publicKey.substring(0, DISPLAY.PUBLIC_KEY_LENGTH) + '...'
            }
        );
    }
}

// Keys View - Shows keypairs
export class KeysViewProvider extends BaseTreeProvider {
    protected async getRootChildren(): Promise<SSSTreeItem[]> {
        try {
            const keys = await this.sssWrapper.listKeys();

            if (keys.length === 0) {
                return [createEmptyItem('No keypairs found')];
            }

            return keys.map(key => this.createKeyItem(key));
        } catch (error) {
            return [createErrorItem('Error loading keys')];
        }
    }

    private createKeyItem(key: any): SSSTreeItem {
        const passwordInfo = key.isPasswordProtected ? '\nPassword protected' : '';
        return createTreeItem(
            key.uuid.substring(0, DISPLAY.UUID_LENGTH) + '...',
            key.isCurrent ? 'key' : 'circle-outline',
            {
                contextValue: 'key',
                keyUuid: key.uuid,
                tooltip: `UUID: ${key.uuid}\nCreated: ${key.created}${passwordInfo}`,
                description: key.isCurrent ? '(current)' : key.created
            }
        );
    }
}

// Actions View - Shows common actions
export class ActionsViewProvider extends BaseTreeProvider {
    protected async getRootChildren(): Promise<SSSTreeItem[]> {
        const isProject = await this.checkIfProject();
        const config = vscode.workspace.getConfiguration('secrets');

        return [
            ...this.getProjectActions(isProject),
            ...this.getCommonActions(),
            ...this.getSettingsActions(config)
        ];
    }

    private async checkIfProject(): Promise<boolean> {
        try {
            const projectInfo = await this.sssWrapper.checkProjectStatus();
            return projectInfo.isProject;
        } catch (error) {
            return false;
        }
    }

    private getProjectActions(isProject: boolean): SSSTreeItem[] {
        if (!isProject) {
            return [createActionItem('Initialise Project', 'add', 'sss.initProject')];
        }

        return [
            createActionItem('Seal All Files', 'lock', 'sss.sealWorkspace'),
            createActionItem('Open All Files', 'unlock', 'sss.openWorkspace'),
            createActionItem('Render to Plaintext (Destructive)', 'warning', 'sss.renderProject')
        ];
    }

    private getCommonActions(): SSSTreeItem[] {
        return [
            createActionItem('Copy Public Key to Clipboard', 'clippy', 'sss.showPublicKey'),
            createActionItem('Install Git Hooks', 'git-commit', 'sss.installHooks')
        ];
    }

    private getSettingsActions(config: vscode.WorkspaceConfiguration): SSSTreeItem[] {
        const autoSealEnabled = config.get<boolean>('autoSealOnSave', true);
        const autoOpenEnabled = config.get<boolean>('autoOpenOnLoad', false);

        return [
            this.createToggleItem('Auto-Seal & Write', autoSealEnabled, 'sss.toggleAutoSeal'),
            this.createToggleItem('Auto-Open & Write', autoOpenEnabled, 'sss.toggleAutoOpen'),
            createActionItem('Clear Cached Password', 'trash', 'sss.clearPassword'),
            createActionItem('Update sss Binary', 'cloud-download', 'sss.updateBinary'),
            createActionItem('Open Settings', 'settings', 'sss.openSettings')
        ];
    }

    private createToggleItem(label: string, enabled: boolean, command: string): SSSTreeItem {
        return createActionItem(
            `${label}: ${enabled ? 'Enabled' : 'Disabled'}`,
            enabled ? 'check' : 'circle-slash',
            command
        );
    }
}
