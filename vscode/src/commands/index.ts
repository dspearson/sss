/**
 * Centralized command registration
 */

import * as vscode from 'vscode';
import { FileCommands } from './fileCommands';
import { SecretCommands } from './secretCommands';
import { ProjectCommands } from './projectCommands';
import { ConfigCommands } from './configCommands';
import { UserKeyManager } from '../userKeyManager';
import { TreeViewProviders } from './types';

export * from './fileCommands';
export * from './secretCommands';
export * from './projectCommands';
export * from './configCommands';
export * from './types';

/**
 * Register all commands with VS Code
 */
export function registerAllCommands(
    context: vscode.ExtensionContext,
    fileCommands: FileCommands,
    secretCommands: SecretCommands,
    projectCommands: ProjectCommands,
    configCommands: ConfigCommands,
    userKeyManager: UserKeyManager,
    treeProviders: TreeViewProviders
): void {
    const register = (command: string, handler: (...args: any[]) => any) => {
        context.subscriptions.push(vscode.commands.registerCommand(command, handler));
    };

    // File operations
    register('sss.sealFile', (uri) => fileCommands.sealFile(uri));
    register('sss.openFile', (uri) => fileCommands.openFile(uri));
    register('sss.renderFile', (uri) => fileCommands.renderFile(uri));
    register('sss.wrapSelection', () => fileCommands.wrapSelection());
    register('sss.normaliseMarkers', () => fileCommands.normaliseMarkers());
    register('sss.sealWorkspace', () => fileCommands.sealWorkspace());
    register('sss.openWorkspace', () => fileCommands.openWorkspace());

    // Secret operations
    register('sss.insertInterpolatedSecret', () => secretCommands.insertInterpolatedSecret());
    register('sss.goToSecretDefinition', () => secretCommands.goToSecretDefinition());

    // Project management
    register('sss.renderProject', () => projectCommands.renderProject());
    register('sss.initProject', () => projectCommands.initProject());
    register('sss.showProjectInfo', () => projectCommands.showProjectInfo());
    register('sss.installHooks', () => projectCommands.installHooks());
    register('sss.migrateToHybrid', async () => {
        await projectCommands.migrateToHybrid();
        treeProviders.project.refresh();
        treeProviders.actions.refresh();
    });

    // User management
    register('sss.addUser', async () => {
        await userKeyManager.addUser();
        treeProviders.users.refresh();
    });
    register('sss.removeUser', async (item?: any) => {
        await userKeyManager.removeUser(item?.label);
        treeProviders.users.refresh();
    });
    register('sss.listUsers', () => userKeyManager.listUsers());

    // Key management
    register('sss.generateKey', async () => {
        await userKeyManager.generateKey();
        treeProviders.keys.refresh();
        treeProviders.project.refresh();
    });
    register('sss.listKeys', () => userKeyManager.listKeys());
    register('sss.setCurrentKey', async (item?: any) => {
        await userKeyManager.setCurrentKey(item?.keyUuid);
        treeProviders.keys.refresh();
        treeProviders.project.refresh();
    });
    register('sss.showPublicKey', () => userKeyManager.showPublicKey());

    // View refresh
    register('sss.refreshProjectView', () => treeProviders.project.refresh());
    register('sss.refreshUsersView', () => treeProviders.users.refresh());
    register('sss.refreshKeysView', () => treeProviders.keys.refresh());

    // Configuration
    register('sss.toggleAutoSeal', () => configCommands.toggleAutoSeal());
    register('sss.toggleAutoOpen', () => configCommands.toggleAutoOpen());
    register('sss.openSettings', () => configCommands.openSettings());
    register('sss.clearPassword', () => configCommands.clearPassword());
    register('sss.updateBinary', () => configCommands.updateBinary());
}
