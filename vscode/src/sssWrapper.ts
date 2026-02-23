import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as vscode from 'vscode';
import * as os from 'os';
import { RETRIES, PATTERNS } from './constants';

const execAsync = promisify(exec);

export interface SSSConfig {
    sssPath: string;
    verboseLogging: boolean;
}

export interface ProjectInfo {
    isProject: boolean;
    projectRoot?: string;
    version?: string;
}

export interface UserInfo {
    username: string;
    publicKey: string;
    added: string;
}

export interface KeyInfo {
    uuid: string;
    created: string;
    isPasswordProtected: boolean;
    isCurrent: boolean;
}

export interface SSSSettings {
    secretsFilename: string;
    secretsSuffix: string;
}

export class SSSWrapper {
    private config: SSSConfig;
    private outputChannel: vscode.OutputChannel;
    private cachedPassword: string | null = null;
    private cacheTimeoutHandle: NodeJS.Timeout | null = null;
    private authenticationPromise: Promise<void> | null = null;

    constructor(outputChannel: vscode.OutputChannel, sssPath?: string) {
        this.outputChannel = outputChannel;
        this.config = this.loadConfig(sssPath);
    }

    private loadConfig(sssPath?: string): SSSConfig {
        const config = vscode.workspace.getConfiguration('secrets');
        return {
            sssPath: sssPath || config.get<string>('binaryPath', 'sss'),
            verboseLogging: config.get<boolean>('verboseLogging', false)
        };
    }

    private log(message: string): void {
        if (this.config.verboseLogging) {
            this.outputChannel.appendLine(`[sss] ${message}`);
        }
    }

    private getUsername(): string | undefined {
        const config = vscode.workspace.getConfiguration('secrets');
        const configuredUsername = config.get<string>('user', '');
        return configuredUsername || undefined;
    }

    private async runCommandWithArgs(
        args: string[],
        cwd?: string,
        usePassword: boolean = false,
        additionalEnv?: Record<string, string>,
        retryCount: number = 0
    ): Promise<{ stdout: string; stderr: string }> {
        this.log(`Running: ${this.config.sssPath} ${args.join(' ')}`);

        // Build environment variables
        const env = { ...process.env };
        const sssEnvVars: Record<string, string> = {};

        // Only set SSS_USER if explicitly configured
        const username = this.getUsername();
        if (username) {
            env.SSS_USER = username;
            sssEnvVars.SSS_USER = username;
        }

        // Add any additional environment variables
        if (additionalEnv) {
            Object.assign(env, additionalEnv);
            Object.assign(sssEnvVars, additionalEnv);
        }

        if (usePassword) {
            // Check if key is password protected
            const needsPassword = await this.currentKeyIsPasswordProtected();

            if (needsPassword) {
                // If we don't have a cached password, prompt for it
                if (!this.cachedPassword) {
                    const promptMessage = retryCount > 0
                        ? 'Incorrect passphrase. Please try again'
                        : 'Enter passphrase for Secret String Substitution key';

                    const password = await vscode.window.showInputBox({
                        prompt: promptMessage,
                        password: true,
                        placeHolder: 'passphrase'
                    });

                    if (!password) {
                        throw new Error('Passphrase required but not provided');
                    }

                    this.setCachedPassword(password);
                }

                // Set the SSS_PASSPHRASE environment variable
                env.SSS_PASSPHRASE = this.cachedPassword!;
                sssEnvVars.SSS_PASSPHRASE = '[REDACTED]';
            }
        }

        // Log environment variables (with passphrase redacted)
        if (Object.keys(sssEnvVars).length > 0) {
            this.log(`Environment: ${JSON.stringify(sssEnvVars)}`);
        }

        return new Promise((resolve, reject) => {
            const child = spawn(this.config.sssPath, args, {
                cwd: cwd || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                env: env
            });

            let stdout = '';
            let stderr = '';

            child.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            child.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            child.on('error', (error) => {
                this.log(`Spawn error: ${error.message}`);
                reject(new Error(`Failed to execute sss binary. Please ensure the binary is installed or configure the path in settings. Error: ${error.message}`));
            });

            child.on('close', async (code) => {
                if (code === 0) {
                    this.log(`Success: ${stdout}`);
                    resolve({ stdout, stderr });
                } else {
                    this.log(`Error (code ${code}): ${stderr}`);

                    // Check if this is a passphrase/authentication error
                    const errorMessage = stderr || stdout;
                    const isAuthError =
                        errorMessage.includes('passphrase') ||
                        errorMessage.includes('password') ||
                        errorMessage.includes('authentication') ||
                        errorMessage.includes('decrypt');

                    // If it's an auth error and we haven't retried too many times, retry
                    if (isAuthError && usePassword && retryCount < RETRIES.AUTH_MAX) {
                        this.log(`Authentication error detected, clearing cached passphrase and retrying (attempt ${retryCount + 1})`);
                        this.cachedPassword = null;
                        try {
                            const result = await this.runCommandWithArgs(args, cwd, usePassword, additionalEnv, retryCount + 1);
                            resolve(result);
                        } catch (error) {
                            reject(error);
                        }
                        return;
                    }

                    reject(new Error(`sss command failed (exit code ${code}): ${stderr || stdout}`));
                }
            });
        });
    }

    private async runCommand(
        command: string,
        cwd?: string,
        usePassword: boolean = false,
        additionalEnv?: Record<string, string>,
        retryCount: number = 0
    ): Promise<{ stdout: string; stderr: string }> {
        // Parse command string into arguments
        // Match quoted strings or non-whitespace sequences
        const commandParts = command.match(/(?:[^\s"]+|"[^"]*")+/g) || [];

        // First part should be the binary path (skip it)
        // Remaining parts are arguments (remove quotes)
        const args = commandParts.slice(1).map(arg => arg.replace(/^"|"$/g, ''));

        return this.runCommandWithArgs(args, cwd, usePassword, additionalEnv, retryCount);
    }

    private async currentKeyIsPasswordProtected(): Promise<boolean> {
        try {
            const keys = await this.listKeys();
            const currentKey = keys.find(k => k.isCurrent);
            return currentKey?.isPasswordProtected || false;
        } catch (error) {
            // If we can't determine, assume not protected
            return false;
        }
    }

    private setCachedPassword(password: string): void {
        // Clear any existing timeout
        if (this.cacheTimeoutHandle) {
            clearTimeout(this.cacheTimeoutHandle);
            this.cacheTimeoutHandle = null;
        }

        this.cachedPassword = password;

        // Set up timeout if configured
        const config = vscode.workspace.getConfiguration('secrets');
        const timeoutMinutes = config.get<number>('passphraseCacheTimeout', 0);

        if (timeoutMinutes > 0) {
            const timeoutMs = timeoutMinutes * 60 * 1000;
            this.log(`Passphrase cached for ${timeoutMinutes} minute(s)`);

            this.cacheTimeoutHandle = setTimeout(() => {
                this.cachedPassword = null;
                this.cacheTimeoutHandle = null;
                this.log('Cached passphrase expired');
                vscode.window.showInformationMessage('Cached passphrase has expired');
            }, timeoutMs);
        } else {
            this.log('Passphrase cached for entire session');
        }
    }

    public clearCachedPassword(): void {
        if (this.cacheTimeoutHandle) {
            clearTimeout(this.cacheTimeoutHandle);
            this.cacheTimeoutHandle = null;
        }
        this.cachedPassword = null;
        this.authenticationPromise = null;
        this.log('Cached password cleared');
    }

    public async cachePassphrase(passphrase: string): Promise<void> {
        this.setCachedPassword(passphrase);
    }

    /**
     * Ensure authentication is ready for password-protected keys.
     * This method should be called:
     * 1. When the project loads (proactive authentication)
     * 2. Before any file operations that need the password
     *
     * It will prompt for the passphrase if needed, or return immediately if already authenticated.
     */
    public async ensureAuthenticated(): Promise<void> {
        // If authentication is already in progress, wait for it
        if (this.authenticationPromise) {
            this.log('Authentication already in progress, waiting...');
            return this.authenticationPromise;
        }

        // If we already have a cached password, we're authenticated
        if (this.cachedPassword) {
            this.log('Already authenticated (cached password exists)');
            return;
        }

        // Check if current key is password-protected
        const needsPassword = await this.currentKeyIsPasswordProtected();

        if (!needsPassword) {
            this.log('Key is not password-protected, authentication not needed');
            return;
        }

        // Create authentication promise
        this.authenticationPromise = (async () => {
            this.log('Key is password-protected, prompting for passphrase...');

            const password = await vscode.window.showInputBox({
                prompt: 'Enter passphrase for Secret String Substitution key',
                password: true,
                placeHolder: 'passphrase',
                ignoreFocusOut: true // Don't dismiss if user clicks away
            });

            if (!password) {
                this.authenticationPromise = null;
                throw new Error('Passphrase required but not provided');
            }

            this.setCachedPassword(password);
            this.log('Authentication successful');
        })();

        try {
            await this.authenticationPromise;
        } catch (error) {
            this.authenticationPromise = null;
            throw error;
        }
    }

    /**
     * Check if current workspace is an sss project
     */
    async checkProjectStatus(): Promise<ProjectInfo> {
        try {
            const { stdout } = await this.runCommand(`"${this.config.sssPath}" status`);

            // Output format is just the project root path
            const projectRoot = stdout.trim();

            return {
                isProject: true,
                projectRoot,
                version: '1.0' // Could parse from .sss.toml if needed
            };
        } catch (error) {
            return { isProject: false };
        }
    }

    /**
     * Seal (encrypt) a file or directory
     */
    async seal(filePath: string, inPlace: boolean = true): Promise<void> {
        const flags = inPlace ? '-x' : '';
        await this.runCommand(`"${this.config.sssPath}" seal ${flags} "${filePath}"`, undefined, true);
    }

    /**
     * Open (decrypt to markers) a file or directory
     */
    async open(filePath: string, inPlace: boolean = true): Promise<void> {
        const flags = inPlace ? '-x' : '';
        await this.runCommand(`"${this.config.sssPath}" open ${flags} "${filePath}"`, undefined, true);
    }

    /**
     * Open and return content (decrypt to markers) without modifying file
     */
    async openAndRead(filePath: string): Promise<string> {
        const { stdout } = await this.runCommand(
            `"${this.config.sssPath}" open "${filePath}"`,
            undefined,
            true,
            { SSS_PROJECT_OPEN: 'true' }
        );
        return stdout;
    }

    /**
     * Render (show plaintext) a file
     */
    async render(filePath: string): Promise<string> {
        const { stdout } = await this.runCommand(
            `"${this.config.sssPath}" render "${filePath}"`,
            undefined,
            true,
            { SSS_PROJECT_RENDER: 'true' }
        );
        return stdout;
    }

    /**
     * Seal entire workspace/project
     */
    async sealProject(projectPath: string): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" seal --project`, projectPath, true);
    }

    /**
     * Open entire workspace/project
     */
    async openProject(projectPath: string): Promise<void> {
        await this.runCommand(
            `"${this.config.sssPath}" open --project`,
            projectPath,
            true,
            { SSS_PROJECT_OPEN: 'true' }
        );
    }

    /**
     * Render entire workspace/project (DESTRUCTIVE - converts to plaintext)
     */
    async renderProject(projectPath: string): Promise<void> {
        await this.runCommand(
            `"${this.config.sssPath}" render --project`,
            projectPath,
            true,
            { SSS_PROJECT_RENDER: 'true' }
        );
    }

    /**
     * Seal all files in current workspace (alias for sealProject)
     */
    async sealAll(): Promise<void> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }
        await this.sealProject(workspaceFolder.uri.fsPath);
    }

    /**
     * Open all files in current workspace (alias for openProject)
     */
    async openAll(): Promise<string> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }
        await this.openProject(workspaceFolder.uri.fsPath);
        return 'Workspace files opened successfully';
    }

    /**
     * Initialise a new sss project
     */
    async initProject(username: string, projectPath?: string): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" init "${username}"`, projectPath, true);
    }

    /**
     * Get project information
     */
    async getProjectInfo(): Promise<string> {
        const { stdout } = await this.runCommand(`"${this.config.sssPath}" project show`);
        return stdout;
    }

    /**
     * List users in project
     */
    async listUsers(): Promise<UserInfo[]> {
        try {
            const { stdout } = await this.runCommand(`"${this.config.sssPath}" users list`);

            // Parse user list output
            // Format: "  username - Public key: publickey..."
            const users: UserInfo[] = [];
            const lines = stdout.trim().split('\n');

            for (const line of lines) {
                // Skip header line
                if (line.includes('Project users:')) {
                    continue;
                }

                // Match lines like "  ansible_tvhmmc1-vans003 - Public key: p+Q8Z9P886kLw+//..."
                const match = line.match(/^\s+([^\s]+)\s+-\s+Public key:\s+(.+)$/);
                if (match) {
                    users.push({
                        username: match[1],
                        publicKey: match[2],
                        added: '' // Not included in list output
                    });
                }
            }

            return users;
        } catch (error) {
            return [];
        }
    }

    /**
     * Add user to project
     */
    async addUser(username: string, publicKey: string): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" users add "${username}" "${publicKey}"`, undefined, true);
    }

    /**
     * Remove user from project
     */
    async removeUser(username: string): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" users remove "${username}"`, undefined, true);
    }

    /**
     * Generate new keypair
     */
    async generateKey(passwordProtected: boolean = false, password?: string): Promise<void> {
        // Always use --force (sss bug: it never overwrites, just creates new keypair)
        const flags = passwordProtected ? '--force' : '--force --no-password';

        // If password-protected and password provided, cache it and set environment variable
        const env: Record<string, string> | undefined = passwordProtected && password
            ? { SSS_PASSPHRASE: password }
            : undefined;

        await this.runCommand(`"${this.config.sssPath}" keys generate ${flags}`, undefined, false, env);

        // Cache the password for future use if provided
        if (passwordProtected && password) {
            this.setCachedPassword(password);
        }
    }

    /**
     * List available keypairs
     */
    async listKeys(): Promise<KeyInfo[]> {
        try {
            const { stdout } = await this.runCommand(`"${this.config.sssPath}" keys list`);

            // Parse key list output
            // Format: "  a9b83192... - Created: 2025-12-06 00:25 [protected] (current)"
            const keys: KeyInfo[] = [];
            const lines = stdout.trim().split('\n');

            for (const line of lines) {
                // Skip header line
                if (line.includes('Found') && line.includes('keypair')) {
                    continue;
                }

                // Match lines like "  a9b83192... - Created: 2025-12-06 00:25 [protected] (current)"
                // Captures: uuid, date/time, [protected] (optional), (current) (optional)
                const match = line.match(/^\s+([0-9a-f-]+)(?:\.\.\.)?\s+-\s+Created:\s+([^\[\(]+)\s*(?:\[protected\])?\s*(?:\((current)\))?/);
                if (match) {
                    const uuid = match[1];
                    const created = match[2].trim();
                    const isPasswordProtected = line.includes('[protected]');
                    const isCurrent = match[3] === 'current';

                    keys.push({
                        uuid,
                        created,
                        isPasswordProtected,
                        isCurrent
                    });
                }
            }

            return keys;
        } catch (error) {
            return [];
        }
    }

    /**
     * Get current key info
     */
    async getCurrentKey(): Promise<string> {
        const { stdout } = await this.runCommand(`"${this.config.sssPath}" keys current`, undefined, true);

        // Output format:
        // Current key ID: 079a9a96-bf46-47eb-8d6b-f7442fd35f12
        // Public key: 0H0IxDgPLX5YvTl3whrZXs5d9PtWvr0PISSuGnXKKHk=

        const lines = stdout.trim().split('\n');
        for (const line of lines) {
            if (line.startsWith('Current key ID:')) {
                return line.split(':')[1].trim();
            }
        }

        return '';
    }

    /**
     * Set current key
     */
    async setCurrentKey(uuid: string): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" keys current "${uuid}"`, undefined, true);
    }

    /**
     * Get public key
     */
    async getPublicKey(): Promise<string> {
        const { stdout } = await this.runCommand(`"${this.config.sssPath}" keys pubkey`, undefined, true);
        return stdout.trim();
    }

    /**
     * Install git hooks
     */
    async installHooks(): Promise<void> {
        await this.runCommand(`"${this.config.sssPath}" hooks install`, undefined, true);
    }

    /**
     * Get settings
     */
    async getSettings(): Promise<string> {
        const { stdout } = await this.runCommand(`"${this.config.sssPath}" settings show`);
        return stdout;
    }

    /**
     * Parse sss settings to extract secrets filename and suffix
     */
    async parseSettings(): Promise<SSSSettings> {
        try {
            const settingsOutput = await this.getSettings();
            const lines = settingsOutput.split('\n');

            let secretsFilename = 'secrets'; // Default
            let secretsSuffix = '.secrets'; // Default

            for (const line of lines) {
                if (line.includes('Secrets filename:')) {
                    secretsFilename = line.split(':')[1].trim();
                } else if (line.includes('Secrets suffix:')) {
                    secretsSuffix = line.split(':')[1].trim();
                }
            }

            return { secretsFilename, secretsSuffix };
        } catch (error) {
            // If we can't get settings, use defaults
            return { secretsFilename: 'secrets', secretsSuffix: '.secrets' };
        }
    }

    /**
     * Check if a file should be auto-sealed based on its path
     * Returns true if the file matches secrets filename or has secrets suffix
     */
    async shouldAutoSeal(filePath: string): Promise<boolean> {
        const settings = await this.parseSettings();
        const fileName = filePath.split('/').pop() || '';

        // Check if filename matches secrets filename exactly
        if (fileName === settings.secretsFilename) {
            return true;
        }

        // Check if filename ends with secrets suffix
        if (settings.secretsSuffix && fileName.endsWith(settings.secretsSuffix)) {
            return true;
        }

        return false;
    }

    /**
     * Check if file contains sss markers
     */
    hasMarkers(content: string): boolean {
        // Check for sss markers: ⊕{...}, ⊠{...}, o+{...}, <{...}, ⊲{...}
        return PATTERNS.ALL_MARKERS.test(content);
    }

    /**
     * Check if file is encrypted (has sealed markers)
     */
    isEncrypted(content: string): boolean {
        return PATTERNS.ENCRYPTED_MARKER.test(content);
    }

    /**
     * Check if file has plaintext markers
     */
    hasPlaintextMarkers(content: string): boolean {
        return PATTERNS.ANY_PLAINTEXT_MARKER.test(content);
    }
}
