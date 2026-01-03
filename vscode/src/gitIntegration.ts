import * as vscode from 'vscode';
import * as fs from 'fs';
import { SSSWrapper } from './sssWrapper';

/**
 * Integrates with VS Code's Git extension to ensure files are sealed before commit
 */
export class GitIntegration {
    private gitExtension: any;
    private git: any;

    constructor(private sssWrapper: SSSWrapper, private outputChannel: vscode.OutputChannel) {
        try {
            // Get the Git extension
            const extension = vscode.extensions.getExtension('vscode.git');
            this.gitExtension = extension?.exports;
            if (this.gitExtension) {
                this.git = this.gitExtension.getAPI(1);
                this.outputChannel.appendLine('[Git] Git extension found and loaded');
            } else {
                this.outputChannel.appendLine('[Git] Git extension not found');
            }
        } catch (error: any) {
            this.outputChannel.appendLine(`[Git] Error accessing Git extension: ${error.message}`);
        }
    }

    /**
     * Register Git pre-commit check
     */
    public registerPreCommitCheck(context: vscode.ExtensionContext): void {
        if (!this.git) {
            this.outputChannel.appendLine('[Git] Cannot register pre-commit check - Git extension not available');
            return;
        }

        const config = vscode.workspace.getConfiguration('secrets');
        const warnBeforeCommit = config.get<boolean>('warnBeforeCommit', true);

        if (!warnBeforeCommit) {
            this.outputChannel.appendLine('[Git] Pre-commit warnings disabled');
            return;
        }

        // Register input box for commit message - this is where we can intercept
        this.git.repositories.forEach((repo: any) => {
            this.outputChannel.appendLine(`[Git] Registered pre-commit check for repository: ${repo.rootUri.fsPath}`);

            // Hook into the commit process
            const originalCommit = repo.commit;
            repo.commit = async (message: string, opts?: any) => {
                this.outputChannel.appendLine('[Git] Commit triggered, checking for unsealed files...');

                // Check for unsealed files in the staging area
                const unsealedFiles = await this.checkForUnsealedFiles(repo);

                if (unsealedFiles.length > 0) {
                    this.outputChannel.appendLine(`[Git] Found ${unsealedFiles.length} unsealed files`);

                    // Ask user what to do
                    const action = await vscode.window.showWarningMessage(
                        `Found ${unsealedFiles.length} file(s) with plaintext secrets that should be sealed before committing:\n\n${unsealedFiles.map(f => `  - ${f}`).join('\n')}`,
                        { modal: true },
                        'Seal and Commit',
                        'Commit Anyway',
                        'Cancel'
                    );

                    if (action === 'Cancel' || !action) {
                        this.outputChannel.appendLine('[Git] Commit cancelled by user');
                        throw new Error('Commit cancelled - files contain unsealed secrets');
                    } else if (action === 'Seal and Commit') {
                        this.outputChannel.appendLine('[Git] Sealing files before commit...');

                        // Seal each file
                        for (const file of unsealedFiles) {
                            try {
                                const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
                                if (workspaceFolder) {
                                    const fullPath = vscode.Uri.joinPath(workspaceFolder.uri, file).fsPath;
                                    await this.sssWrapper.seal(fullPath);
                                    this.outputChannel.appendLine(`[Git] Sealed: ${file}`);
                                }
                            } catch (error: any) {
                                this.outputChannel.appendLine(`[Git] Failed to seal ${file}: ${error.message}`);
                                vscode.window.showErrorMessage(`Failed to seal ${file}: ${error.message}`);
                                throw error;
                            }
                        }

                        vscode.window.showInformationMessage(`Sealed ${unsealedFiles.length} file(s) before commit`);
                    } else {
                        this.outputChannel.appendLine('[Git] User chose to commit anyway (unsafe!)');
                    }
                }

                // Proceed with commit
                return originalCommit.call(repo, message, opts);
            };
        });

        this.outputChannel.appendLine('[Git] Pre-commit check registered');
    }

    /**
     * Check for files with plaintext markers in the staging area
     */
    private async checkForUnsealedFiles(repo: any): Promise<string[]> {
        const unsealedFiles: string[] = [];

        try {
            // Get staged files
            const changes = repo.state.indexChanges || [];
            this.outputChannel.appendLine(`[Git] Checking ${changes.length} staged files`);

            for (const change of changes) {
                const filePath = change.uri.fsPath;
                this.outputChannel.appendLine(`[Git] Checking: ${filePath}`);

                // Skip deleted files
                if (!fs.existsSync(filePath)) {
                    continue;
                }

                // Read file content
                const content = await fs.promises.readFile(filePath, 'utf8');

                // Check for plaintext markers
                if (this.sssWrapper.hasPlaintextMarkers(content)) {
                    const relativePath = vscode.workspace.asRelativePath(filePath);
                    unsealedFiles.push(relativePath);
                    this.outputChannel.appendLine(`[Git] Found unsealed file: ${relativePath}`);
                }
            }
        } catch (error: any) {
            this.outputChannel.appendLine(`[Git] Error checking staged files: ${error.message}`);
        }

        return unsealedFiles;
    }

    /**
     * Install Git hooks using sss CLI
     */
    public async installHooks(): Promise<void> {
        try {
            await this.sssWrapper.installHooks();
            vscode.window.showInformationMessage('Git hooks installed successfully. Files will be automatically sealed before commit.');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to install Git hooks: ${error.message}`);
        }
    }
}
