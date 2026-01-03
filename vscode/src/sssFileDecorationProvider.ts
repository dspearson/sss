import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * FileDecorationProvider that mirrors Git decorations from file:// URIs to sss-fs:// URIs
 * This ensures that files opened via sss-fs:// scheme show the same Git status colours/badges
 * as they would if opened directly.
 */
export class SSSFileDecorationProvider implements vscode.FileDecorationProvider {
    private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[]>();
    readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;

    private gitStatusCache = new Map<string, GitStatus | null>();
    private cacheTimeout = 5000; // 5 seconds

    constructor(private outputChannel: vscode.OutputChannel) {
        // Watch for Git status changes
        const gitExtension = vscode.extensions.getExtension('vscode.git')?.exports;
        if (gitExtension) {
            const git = gitExtension.getAPI(1);
            if (git.repositories.length > 0) {
                git.repositories[0].state.onDidChange(() => {
                    // Clear cache and refresh decorations
                    this.gitStatusCache.clear();
                    this._onDidChangeFileDecorations.fire(vscode.Uri.parse('sss-fs://'));
                });
            }
        }
    }

    async provideFileDecoration(uri: vscode.Uri): Promise<vscode.FileDecoration | undefined> {
        // Only decorate sss-fs:// URIs
        if (uri.scheme !== 'sss-fs') {
            return undefined;
        }

        // Get the actual file path
        const actualPath = uri.path;

        // Get Git status for this file
        const status = await this.getGitStatus(actualPath);

        if (!status) {
            return undefined;
        }

        // Return decoration based on Git status
        switch (status.status) {
            case 'M': // Modified
                return {
                    badge: 'M',
                    color: new vscode.ThemeColor('gitDecoration.modifiedResourceForeground'),
                    tooltip: 'Modified'
                };
            case 'A': // Added
                return {
                    badge: 'A',
                    color: new vscode.ThemeColor('gitDecoration.addedResourceForeground'),
                    tooltip: 'Added'
                };
            case 'D': // Deleted
                return {
                    badge: 'D',
                    color: new vscode.ThemeColor('gitDecoration.deletedResourceForeground'),
                    tooltip: 'Deleted'
                };
            case 'R': // Renamed
                return {
                    badge: 'R',
                    color: new vscode.ThemeColor('gitDecoration.renamedResourceForeground'),
                    tooltip: 'Renamed'
                };
            case 'C': // Copied
                return {
                    badge: 'C',
                    color: new vscode.ThemeColor('gitDecoration.addedResourceForeground'),
                    tooltip: 'Copied'
                };
            case 'U': // Untracked
                return {
                    badge: 'U',
                    color: new vscode.ThemeColor('gitDecoration.untrackedResourceForeground'),
                    tooltip: 'Untracked'
                };
            case '?': // Untracked
                return {
                    badge: 'U',
                    color: new vscode.ThemeColor('gitDecoration.untrackedResourceForeground'),
                    tooltip: 'Untracked'
                };
            case '!': // Ignored
                return {
                    badge: '!',
                    color: new vscode.ThemeColor('gitDecoration.ignoredResourceForeground'),
                    tooltip: 'Ignored'
                };
            default:
                return undefined;
        }
    }

    private async getGitStatus(filePath: string): Promise<GitStatus | null> {
        // Check cache first
        const cached = this.gitStatusCache.get(filePath);
        if (cached !== undefined) {
            return cached;
        }

        try {
            // Get workspace folder
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (!workspaceFolder) {
                return null;
            }

            // Run git status for this file
            const { stdout } = await execAsync(`git status --porcelain "${filePath}"`, {
                cwd: workspaceFolder.uri.fsPath
            });

            if (!stdout.trim()) {
                // File is not modified
                this.gitStatusCache.set(filePath, null);
                setTimeout(() => this.gitStatusCache.delete(filePath), this.cacheTimeout);
                return null;
            }

            // Parse git status output
            // Format: XY filename
            // X = status in index, Y = status in working tree
            const statusLine = stdout.trim().split('\n')[0];
            const statusChar = statusLine.charAt(1) !== ' ' ? statusLine.charAt(1) : statusLine.charAt(0);

            const status: GitStatus = {
                status: statusChar as any,
                path: filePath
            };

            this.gitStatusCache.set(filePath, status);
            setTimeout(() => this.gitStatusCache.delete(filePath), this.cacheTimeout);

            return status;
        } catch (error) {
            // Not a git repo or other error
            return null;
        }
    }

    public refresh(): void {
        this.gitStatusCache.clear();
        this._onDidChangeFileDecorations.fire(vscode.Uri.parse('sss-fs://'));
    }
}

interface GitStatus {
    status: 'M' | 'A' | 'D' | 'R' | 'C' | 'U' | '?' | '!' | ' ';
    path: string;
}
