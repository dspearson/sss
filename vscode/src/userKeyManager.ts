import * as vscode from 'vscode';
import { SSSWrapper } from './sssWrapper';

export class UserKeyManager {
    private sssWrapper: SSSWrapper;

    constructor(sssWrapper: SSSWrapper) {
        this.sssWrapper = sssWrapper;
    }

    async addUser(): Promise<void> {
        // Get existing users first to check for duplicates
        const existingUsers = await this.sssWrapper.listUsers();
        const existingUsernames = existingUsers.map(u => u.username.toLowerCase());

        // Prompt for username
        const username = await vscode.window.showInputBox({
            prompt: 'Enter username to add',
            placeHolder: 'username',
            validateInput: (value) => {
                if (!value || value.trim().length === 0) {
                    return 'Username cannot be empty';
                }
                if (existingUsernames.includes(value.toLowerCase())) {
                    return `User '${value}' already exists in the project`;
                }
                return null;
            }
        });

        if (!username) {
            return;
        }

        // Prompt for public key
        const publicKey = await vscode.window.showInputBox({
            prompt: 'Enter user\'s public key (base64)',
            placeHolder: 'base64-encoded-public-key',
            validateInput: (value) => {
                if (!value || value.trim().length === 0) {
                    return 'Public key cannot be empty';
                }
                return null;
            }
        });

        if (!publicKey) {
            return;
        }

        try {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Adding user ${username}...`,
                cancellable: false
            }, async () => {
                await this.sssWrapper.addUser(username, publicKey);
            });

            vscode.window.showInformationMessage(`User ${username} added successfully`);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to add user: ${error.message}`);
        }
    }

    async removeUser(username?: string): Promise<void> {
        let selectedUser = username;

        // Get all users to validate removal
        const users = await this.sssWrapper.listUsers();

        if (users.length === 0) {
            vscode.window.showInformationMessage('No users found in project');
            return;
        }

        // Check if this is the last user
        if (users.length === 1) {
            vscode.window.showErrorMessage('Cannot remove the last user from the project');
            return;
        }

        // If no username provided (called from command palette), show quick pick
        if (!selectedUser) {
            selectedUser = await vscode.window.showQuickPick(
                users.map(u => u.username),
                {
                    placeHolder: 'Select user to remove'
                }
            );

            if (!selectedUser) {
                return;
            }
        }

        // Check if trying to remove current user
        try {
            const currentPublicKey = await this.sssWrapper.getPublicKey();
            const userToRemove = users.find(u => u.username === selectedUser);

            if (userToRemove && userToRemove.publicKey === currentPublicKey) {
                vscode.window.showErrorMessage('Cannot remove yourself from the project. You are currently using this key.');
                return;
            }
        } catch (error: any) {
            // If we can't get the current key, allow removal (might not be in project yet)
        }

        // Confirm removal
        const confirm = await vscode.window.showWarningMessage(
            `Are you sure you want to remove user ${selectedUser}?`,
            'Yes', 'No'
        );

        if (confirm !== 'Yes') {
            return;
        }

        try {
            await this.sssWrapper.removeUser(selectedUser);
            vscode.window.showInformationMessage(`User ${selectedUser} removed successfully`);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to remove user: ${error.message}`);
        }
    }

    async listUsers(): Promise<void> {
        try {
            const users = await this.sssWrapper.listUsers();

            if (users.length === 0) {
                vscode.window.showInformationMessage('No users found in project');
                return;
            }

            // Format user list with public keys
            const userList = users.map(u => `  ${u.username}\n    Public key: ${u.publicKey}`).join('\n\n');

            // Show in new document
            const doc = await vscode.workspace.openTextDocument({
                content: `Secret String Substitution Project Users (${users.length}):\n\n${userList}`,
                language: 'plaintext'
            });

            await vscode.window.showTextDocument(doc, { preview: true });
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to list users: ${error.message}`);
        }
    }

    async generateKey(): Promise<void> {
        const passwordProtected = await vscode.window.showQuickPick(
            ['No password', 'Password protected'],
            {
                placeHolder: 'Select key protection type'
            }
        );

        if (!passwordProtected) {
            return;
        }

        const isPasswordProtected = passwordProtected === 'Password protected';
        let password: string | undefined;

        if (isPasswordProtected) {
            // Prompt for password
            password = await vscode.window.showInputBox({
                prompt: 'Enter password for keypair',
                password: true,
                placeHolder: 'password',
                validateInput: (value) => {
                    if (!value || value.length === 0) {
                        return 'Password cannot be empty';
                    }
                    return null;
                }
            });

            if (!password) {
                return;
            }

            // Confirm password
            const confirmPassword = await vscode.window.showInputBox({
                prompt: 'Confirm password',
                password: true,
                placeHolder: 'password'
            });

            if (password !== confirmPassword) {
                vscode.window.showErrorMessage('Passwords do not match');
                return;
            }
        }

        try {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Generating keypair...',
                cancellable: false
            }, async () => {
                await this.sssWrapper.generateKey(isPasswordProtected, password);
            });

            vscode.window.showInformationMessage('Keypair generated successfully');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to generate key: ${error.message}`);
        }
    }

    async listKeys(): Promise<void> {
        try {
            const keys = await this.sssWrapper.listKeys();

            if (keys.length === 0) {
                vscode.window.showInformationMessage('No keypairs found');
                return;
            }

            // Format key list
            const keyList = keys.map(k =>
                `${k.isCurrent ? '* ' : '  '}${k.uuid} (${k.created})${k.isPasswordProtected ? ' [protected]' : ''}`
            ).join('\n');

            // Show in new document
            const doc = await vscode.workspace.openTextDocument({
                content: `Secret String Substitution Keypairs:\n(* = current)\n\n${keyList}`,
                language: 'plaintext'
            });

            await vscode.window.showTextDocument(doc, { preview: true });
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to list keys: ${error.message}`);
        }
    }

    async setCurrentKey(keyUuid?: string): Promise<void> {
        try {
            let selectedKeyUuid = keyUuid;

            // If no key UUID provided (called from command palette), show quick pick
            if (!selectedKeyUuid) {
                const keys = await this.sssWrapper.listKeys();

                if (keys.length === 0) {
                    vscode.window.showInformationMessage('No keypairs found. Generate one first.');
                    return;
                }

                const selectedKey = await vscode.window.showQuickPick(
                    keys.map(k => ({
                        label: k.uuid,
                        description: k.isCurrent ? '(current)' : '',
                        detail: `Created: ${k.created}${k.isPasswordProtected ? ' [password protected]' : ''}`,
                        uuid: k.uuid
                    })),
                    {
                        placeHolder: 'Select keypair to use'
                    }
                );

                if (!selectedKey) {
                    return;
                }

                selectedKeyUuid = selectedKey.uuid;
            }

            await this.sssWrapper.setCurrentKey(selectedKeyUuid);
            vscode.window.showInformationMessage(`Current key set to ${selectedKeyUuid}`);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to set current key: ${error.message}`);
        }
    }

    async showPublicKey(): Promise<void> {
        try {
            const publicKey = await this.sssWrapper.getPublicKey();

            // Copy directly to clipboard
            await vscode.env.clipboard.writeText(publicKey);
            vscode.window.showInformationMessage('Public key copied to clipboard');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to get public key: ${error.message}`);
        }
    }
}
