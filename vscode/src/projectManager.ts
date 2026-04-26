import * as vscode from 'vscode';
import * as os from 'os';
import { SSSWrapper } from './sssWrapper';

export class ProjectManager {
    private sssWrapper: SSSWrapper;

    constructor(sssWrapper: SSSWrapper) {
        this.sssWrapper = sssWrapper;
    }

    private getDefaultUsername(): string {
        // For project init username parameter, always use system username if not configured
        const config = vscode.workspace.getConfiguration('secrets');
        const configuredUsername = config.get<string>('user', '');
        return configuredUsername || os.userInfo().username;
    }

    async initProject(): Promise<void> {
        // Check if user has any keys
        const existingKeys = await this.sssWrapper.listKeys();

        if (existingKeys.length === 0) {
            // No keys exist, prompt to create one
            const createKey = await vscode.window.showInformationMessage(
                'You need a keypair to initialise a project. Would you like to create one?',
                'Yes', 'No'
            );

            if (createKey !== 'Yes') {
                return;
            }

            // Ask if they want password protection
            const passwordProtected = await vscode.window.showQuickPick(
                [
                    { label: 'Password-protected', value: true },
                    { label: 'No password', value: false }
                ],
                {
                    placeHolder: 'Choose keypair type'
                }
            );

            if (!passwordProtected) {
                return;
            }

            let password: string | undefined;
            if (passwordProtected.value) {
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

            // Generate the key — use 'both' so the keypair is ready for a hybrid project
            try {
                await vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: 'Generating keypair...',
                    cancellable: false
                }, async () => {
                    await this.sssWrapper.generateKey(passwordProtected.value, password, 'both');
                });

                vscode.window.showInformationMessage('Keypair generated successfully');
            } catch (error: any) {
                vscode.window.showErrorMessage(`Failed to generate keypair: ${error.message}`);
                return;
            }
        }

        // Use configured/default username automatically
        const username = this.getDefaultUsername();

        // Ask which crypto suite to use — hybrid (v2) is recommended for new projects
        const cryptoChoice = await vscode.window.showQuickPick(
            [
                { label: 'Hybrid — v2.0 (recommended)', description: 'X448 + sntrup761 KEM + XChaCha20-Poly1305 — requires hybrid build', value: 'hybrid' as const },
                { label: 'Classic — v1.0', description: 'X25519 / XChaCha20-Poly1305 (legacy)', value: 'classic' as const }
            ],
            { placeHolder: 'Choose cryptographic suite for new project' }
        );
        if (!cryptoChoice) {
            return;
        }

        try {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Initialising Secret String Substitution project...',
                cancellable: false
            }, async () => {
                const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
                await this.sssWrapper.initProject(username, workspaceFolder?.uri.fsPath, cryptoChoice.value);
            });

            vscode.window.showInformationMessage('Secret String Substitution project initialised successfully');

            // Update context
            await vscode.commands.executeCommand('setContext', 'sss.isProject', true);

            // Offer to install git hooks
            const installHooks = await vscode.window.showInformationMessage(
                'Would you like to install Git hooks for automatic sealing?',
                'Yes', 'No'
            );

            if (installHooks === 'Yes') {
                await this.sssWrapper.installHooks();
                vscode.window.showInformationMessage('Git hooks installed');
            }
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to initialise project: ${error.message}`);
        }
    }

    async showProjectInfo(): Promise<void> {
        try {
            const info = await this.sssWrapper.getProjectInfo();

            // Create a new text document to show the info
            const doc = await vscode.workspace.openTextDocument({
                content: info,
                language: 'plaintext'
            });

            await vscode.window.showTextDocument(doc, { preview: true });
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to get project info: ${error.message}`);
        }
    }
}
