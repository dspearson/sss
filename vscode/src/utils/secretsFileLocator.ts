import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SSSWrapper, SSSSettings } from '../sssWrapper';
import { showQuickPick, QuickPickOption } from './uiHelpers';

/**
 * Handles finding and creating secrets files following sss search order:
 * 1. currentFile + suffix in current directory (e.g., myfile.yaml.secrets)
 * 2. secretsFilename in current directory (e.g., secrets)
 * 3. secretsFilename in parent directories recursively up to filesystem root
 * 4. Create secrets file if not found
 */
export class SecretsFileLocator {
    constructor(
        private sssWrapper: SSSWrapper,
        private outputChannel: vscode.OutputChannel
    ) {}

    /**
     * Find existing secrets file using sss search order
     * Returns null if not found
     */
    async findSecretsFile(
        currentFilePath: string,
        settings?: SSSSettings
    ): Promise<string | null> {
        const currentDir = path.dirname(currentFilePath);
        const currentFileName = path.basename(currentFilePath);

        if (!settings) {
            settings = await this.sssWrapper.parseSettings();
        }

        let searchDir = path.normalize(currentDir);
        let isFirstIteration = true;

        this.log(`Starting search from: ${searchDir}`);
        this.log(`Looking for: ${currentFileName}${settings.secretsSuffix} (current dir only) or ${settings.secretsFilename} (recursively)`);

        while (true) {
            this.log(`Searching in: ${searchDir}`);

            // 1. Check for currentFile + suffix ONLY in current directory
            if (isFirstIteration && settings.secretsSuffix) {
                const filePlusSuffix = path.join(searchDir, currentFileName + settings.secretsSuffix);
                if (this.fileExists(filePlusSuffix)) {
                    this.log(`Found: ${filePlusSuffix}`);
                    return filePlusSuffix;
                }
            }

            // 2. Check for secretsFilename in all directories
            const secretsPath = path.join(searchDir, settings.secretsFilename);
            if (this.fileExists(secretsPath)) {
                this.log(`Found: ${secretsPath}`);
                return secretsPath;
            }

            isFirstIteration = false;

            // Move to parent directory
            const parentDir = path.dirname(searchDir);
            if (parentDir === searchDir) {
                this.log('Reached filesystem root, stopping search');
                break;
            }

            searchDir = parentDir;
        }

        return null;
    }

    /**
     * Find or create a secrets file, prompting user if creation is needed
     */
    async findOrCreateSecretsFile(
        currentFilePath: string,
        currentFileName: string,
        currentDir: string
    ): Promise<string | null> {
        const projectInfo = await this.sssWrapper.checkProjectStatus();
        const projectRoot = projectInfo.projectRoot || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

        if (!projectRoot) {
            vscode.window.showErrorMessage('Not in an sss project');
            return null;
        }

        // Try to find existing file first
        const existingFile = await this.findSecretsFile(currentFilePath);
        if (existingFile) {
            return existingFile;
        }

        // No file found, prompt user to create one
        return await this.promptToCreateSecretsFile(currentDir, projectRoot);
    }

    /**
     * Prompt user to choose where to create a new secrets file
     */
    private async promptToCreateSecretsFile(
        currentDir: string,
        projectRoot: string
    ): Promise<string | null> {
        const settings = await this.sssWrapper.parseSettings();
        const currentDirSecrets = path.join(currentDir, settings.secretsFilename);
        const projectRootSecrets = path.join(projectRoot, settings.secretsFilename);
        const currentDirRelative = path.relative(projectRoot, currentDir) || '.';

        const options: QuickPickOption<string>[] = [
            {
                label: '$(file-directory) Current directory',
                description: currentDirRelative,
                detail: `Create ${settings.secretsFilename} in the same directory as current file`,
                value: currentDirSecrets
            },
            {
                label: '$(root-folder) Project root',
                description: '.',
                detail: `Create ${settings.secretsFilename} in project root (shared across all subdirectories)`,
                value: projectRootSecrets
            }
        ];

        const secretsFilePath = await showQuickPick(
            options,
            'No secrets file found. Where would you like to create it?',
            'Create Secrets File'
        );

        if (!secretsFilePath) {
            return null;
        }

        await this.createSecretsFile(secretsFilePath, secretsFilePath === projectRootSecrets);
        return secretsFilePath;
    }

    /**
     * Create an empty secrets file
     */
    private async createSecretsFile(secretsFilePath: string, isProjectRoot: boolean): Promise<void> {
        const uri = vscode.Uri.file(secretsFilePath);
        await vscode.workspace.fs.writeFile(uri, new Uint8Array());

        const locationName = isProjectRoot ? 'project root' : 'current directory';
        vscode.window.showInformationMessage(`Created secrets file in ${locationName}`);
    }

    private fileExists(filePath: string): boolean {
        try {
            return fs.existsSync(filePath);
        } catch {
            return false;
        }
    }

    private log(message: string): void {
        this.outputChannel.appendLine(`[SecretsFileLocator] ${message}`);
    }
}
