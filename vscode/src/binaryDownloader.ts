import * as vscode from 'vscode';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { BINARY } from './constants';

export class BinaryDownloader {
    private outputChannel: vscode.OutputChannel;
    private storagePath: string;

    constructor(context: vscode.ExtensionContext, outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
        // Use globalStorageUri for storing binaries
        this.storagePath = context.globalStorageUri.fsPath;

        // Ensure storage directory exists
        if (!fs.existsSync(this.storagePath)) {
            fs.mkdirSync(this.storagePath, { recursive: true });
        }
    }

    private log(message: string): void {
        this.outputChannel.appendLine(`[Binary Download] ${message}`);
    }

    /**
     * Get the latest version number from the server
     */
    private async getLatestVersion(): Promise<string> {
        return new Promise((resolve, reject) => {
            https.get(`${BINARY.DOWNLOAD_URL}/latest`, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    const version = data.trim();
                    this.log(`Latest version: ${version}`);
                    resolve(version);
                });
            }).on('error', (err) => {
                reject(new Error(`Failed to fetch latest version: ${err.message}`));
            });
        });
    }

    /**
     * Determine platform-specific binary name
     */
    private async getBinaryName(version: string): Promise<string> {
        const platform = process.platform;
        const arch = process.arch;

        if (platform === 'darwin') {
            // macOS - currently only aarch64
            return `sss-${version}-macos-aarch64`;
        } else if (platform === 'linux') {
            // Linux - currently only x86_64-musl
            return `sss-${version}-linux-x86_64-musl`;
        } else {
            throw new Error(`Unsupported platform: ${platform}`);
        }
    }

    /**
     * Download binary from server
     */
    private async downloadBinary(binaryName: string, targetPath: string): Promise<void> {
        const url = `${BINARY.DOWNLOAD_URL}/${binaryName}`;
        this.log(`Downloading from: ${url}`);

        return new Promise((resolve, reject) => {
            const file = fs.createWriteStream(targetPath);

            https.get(url, (response) => {
                if (response.statusCode !== 200) {
                    reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
                    return;
                }

                response.pipe(file);

                file.on('finish', () => {
                    file.close();
                    this.log(`Downloaded to: ${targetPath}`);
                    resolve();
                });
            }).on('error', (err) => {
                fs.unlink(targetPath, () => {}); // Clean up on error
                reject(new Error(`Download failed: ${err.message}`));
            });
        });
    }

    /**
     * Set executable permissions and remove quarantine on macOS
     */
    private async setupBinary(binaryPath: string): Promise<void> {
        // Set executable permissions
        fs.chmodSync(binaryPath, 0o755);
        this.log(`Set executable permissions on: ${binaryPath}`);

        // Remove quarantine flag on macOS
        if (process.platform === 'darwin') {
            try {
                await this.removeQuarantine(binaryPath);
                this.log(`Removed quarantine flag from: ${binaryPath}`);
            } catch (error: any) {
                // Quarantine attribute might not exist, which is fine
                if (!error.message.includes('No such xattr')) {
                    this.log(`Warning: Could not remove quarantine: ${error.message}`);
                }
            }
        }
    }

    /**
     * Remove macOS quarantine flag using spawn (safer than exec)
     */
    private async removeQuarantine(binaryPath: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const child = spawn('xattr', ['-d', 'com.apple.quarantine', binaryPath]);

            let stderr = '';
            child.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            child.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(stderr || `xattr command failed with code ${code}`));
                }
            });

            child.on('error', (error) => {
                reject(new Error(`Failed to execute xattr: ${error.message}`));
            });
        });
    }

    /**
     * Ensure binary is downloaded and ready to use
     * Returns the path to the binary
     */
    async ensureBinary(): Promise<string> {
        const config = vscode.workspace.getConfiguration('secrets');
        const configuredPath = config.get<string>('binaryPath', '');

        // If user has configured a custom path, use it
        if (configuredPath) {
            this.log(`Using configured path: ${configuredPath}`);
            return configuredPath;
        }

        // Otherwise, download and manage the binary
        let versionToDownload = config.get<string>('upstreamVersion', 'latest');

        // Resolve "latest" to actual version number
        if (versionToDownload === 'latest') {
            versionToDownload = await this.getLatestVersion();
        }

        const binaryName = await this.getBinaryName(versionToDownload);
        const binaryPath = path.join(this.storagePath, 'sss');

        // Check if binary already exists
        if (fs.existsSync(binaryPath)) {
            // Check if it's the right version by storing version info
            const versionFile = path.join(this.storagePath, BINARY.VERSION_FILE);
            if (fs.existsSync(versionFile)) {
                const installedVersion = fs.readFileSync(versionFile, 'utf8').trim();
                if (installedVersion === versionToDownload) {
                    this.log(`Binary already installed: ${versionToDownload}`);
                    return binaryPath;
                }
            }
        }

        // Download the binary
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Downloading sss binary (${versionToDownload})...`,
            cancellable: false
        }, async () => {
            this.log(`Downloading version: ${versionToDownload}`);
            await this.downloadBinary(binaryName, binaryPath);
            await this.setupBinary(binaryPath);

            // Store version info
            const versionFile = path.join(this.storagePath, BINARY.VERSION_FILE);
            fs.writeFileSync(versionFile, versionToDownload);

            this.log(`Binary ready: ${binaryPath}`);
        });

        vscode.window.showInformationMessage(`sss binary ${versionToDownload} installed successfully`);
        return binaryPath;
    }

    /**
     * Force re-download of the binary (useful for updates)
     */
    async updateBinary(): Promise<string> {
        // Remove existing binary
        const binaryPath = path.join(this.storagePath, 'sss');
        const versionFile = path.join(this.storagePath, BINARY.VERSION_FILE);

        if (fs.existsSync(binaryPath)) {
            fs.unlinkSync(binaryPath);
        }
        if (fs.existsSync(versionFile)) {
            fs.unlinkSync(versionFile);
        }

        // Download fresh copy
        return await this.ensureBinary();
    }
}
