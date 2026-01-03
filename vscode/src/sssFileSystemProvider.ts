import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { SSSWrapper } from './sssWrapper';
import { activationComplete } from './extension';

/**
 * FileSystemProvider for transparent sss encryption/decryption
 *
 * This provider intercepts file read/write operations and automatically:
 * - Decrypts (renders) files when reading
 * - Encrypts (seals) files when writing
 *
 * Files on disk remain encrypted, but appear decrypted in the editor.
 */
export class SSSFileSystemProvider implements vscode.FileSystemProvider {
    private _emitter = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._emitter.event;

    constructor(private sssWrapper: SSSWrapper, private outputChannel: vscode.OutputChannel) {}

    // Convert sss-fs:// URI to regular file:// path
    private getActualPath(uri: vscode.Uri): string {
        // URI format: sss-fs:///absolute/path/to/file
        return uri.path;
    }

    watch(uri: vscode.Uri): vscode.Disposable {
        // Watch the underlying file system
        const actualPath = this.getActualPath(uri);
        const watcher = fs.watch(actualPath, () => {
            this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
        });

        return new vscode.Disposable(() => watcher.close());
    }

    async stat(uri: vscode.Uri): Promise<vscode.FileStat> {
        const actualPath = this.getActualPath(uri);
        const stats = await fs.promises.stat(actualPath);

        return {
            type: stats.isFile() ? vscode.FileType.File : vscode.FileType.Directory,
            ctime: stats.ctimeMs,
            mtime: stats.mtimeMs,
            size: stats.size
        };
    }

    async readDirectory(uri: vscode.Uri): Promise<[string, vscode.FileType][]> {
        const actualPath = this.getActualPath(uri);
        const entries = await fs.promises.readdir(actualPath, { withFileTypes: true });

        return entries.map(entry => {
            const type = entry.isFile() ? vscode.FileType.File :
                        entry.isDirectory() ? vscode.FileType.Directory :
                        entry.isSymbolicLink() ? vscode.FileType.SymbolicLink :
                        vscode.FileType.Unknown;
            return [entry.name, type];
        });
    }

    async createDirectory(uri: vscode.Uri): Promise<void> {
        const actualPath = this.getActualPath(uri);
        await fs.promises.mkdir(actualPath, { recursive: true });
    }

    async readFile(uri: vscode.Uri): Promise<Uint8Array> {
        const actualPath = this.getActualPath(uri);
        this.outputChannel.appendLine(`[FileSystemProvider] Reading: ${actualPath}`);

        // Wait for extension activation and authentication to complete
        if (activationComplete) {
            this.outputChannel.appendLine(`[FileSystemProvider] Waiting for activation to complete...`);
            await activationComplete;
            this.outputChannel.appendLine(`[FileSystemProvider] Activation complete, proceeding with read`);
        }

        try {
            // Read the file from disk (encrypted)
            const diskContent = await fs.promises.readFile(actualPath, 'utf8');

            // Check if file has sss markers
            if (this.sssWrapper.hasMarkers(diskContent)) {
                this.outputChannel.appendLine(`[FileSystemProvider] File has markers, ensuring authentication...`);

                try {
                    // Ensure we're authenticated before opening
                    await this.sssWrapper.ensureAuthenticated();

                    this.outputChannel.appendLine(`[FileSystemProvider] Authentication ready, opening file...`);

                    // Open (decrypt to markers) the content
                    const opened = await this.sssWrapper.openAndRead(actualPath);

                    // Return opened content (with markers like ⊕{...})
                    return Buffer.from(opened, 'utf8');
                } catch (authError: any) {
                    this.outputChannel.appendLine(`[FileSystemProvider] Authentication error: ${authError.message}`);

                    // Show a more helpful error message
                    const errorMessage = authError.message.includes('not provided')
                        ? 'Passphrase required to open encrypted files. Please reload the window and enter your passphrase.'
                        : `Failed to decrypt file: ${authError.message}`;

                    vscode.window.showErrorMessage(errorMessage);
                    throw vscode.FileSystemError.Unavailable(errorMessage);
                }
            } else {
                // No markers, return as-is
                this.outputChannel.appendLine(`[FileSystemProvider] No markers, returning as-is`);
                return Buffer.from(diskContent, 'utf8');
            }
        } catch (error: any) {
            // If it's already a FileSystemError, re-throw it
            if (error instanceof vscode.FileSystemError) {
                throw error;
            }

            this.outputChannel.appendLine(`[FileSystemProvider] Read error: ${error.message}`);
            throw vscode.FileSystemError.FileNotFound(uri);
        }
    }

    async writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean; overwrite: boolean }): Promise<void> {
        const actualPath = this.getActualPath(uri);
        this.outputChannel.appendLine(`[FileSystemProvider] Writing: ${actualPath}`);

        // Wait for extension activation and authentication to complete
        if (activationComplete) {
            await activationComplete;
        }

        try {
            // Ensure parent directory exists
            const parentDir = path.dirname(actualPath);
            try {
                await fs.promises.access(parentDir);
            } catch {
                // Parent directory doesn't exist, create it
                this.outputChannel.appendLine(`[FileSystemProvider] Creating parent directory: ${parentDir}`);
                await fs.promises.mkdir(parentDir, { recursive: true });
            }

            const textContent = Buffer.from(content).toString('utf8');

            // Check if file should be auto-sealed based on:
            // 1. Content has plaintext markers, OR
            // 2. Filename matches secrets filename/suffix pattern
            const hasPlaintextMarkers = this.sssWrapper.hasPlaintextMarkers(textContent);
            const shouldAutoSeal = await this.sssWrapper.shouldAutoSeal(actualPath);

            if (hasPlaintextMarkers || shouldAutoSeal) {
                if (hasPlaintextMarkers) {
                    this.outputChannel.appendLine(`[FileSystemProvider] Content has plaintext markers, sealing...`);
                } else {
                    this.outputChannel.appendLine(`[FileSystemProvider] Filename matches secrets pattern, sealing...`);
                }

                // Ensure we're authenticated before sealing
                await this.sssWrapper.ensureAuthenticated();

                this.outputChannel.appendLine(`[FileSystemProvider] Authentication ready, sealing...`);

                // Write plaintext content to a temporary location first
                const tempPath = actualPath + '.tmp';
                await fs.promises.writeFile(tempPath, textContent, 'utf8');

                try {
                    // Seal the temporary file
                    await this.sssWrapper.seal(tempPath);

                    // Read the sealed content
                    const sealedContent = await fs.promises.readFile(tempPath, 'utf8');

                    // Write sealed content to actual file
                    await fs.promises.writeFile(actualPath, sealedContent, 'utf8');

                    // Clean up temp file
                    await fs.promises.unlink(tempPath);
                } catch (error) {
                    // Clean up temp file on error
                    try {
                        await fs.promises.unlink(tempPath);
                    } catch {}
                    throw error;
                }
            } else {
                // No plaintext markers and doesn't match secrets pattern, write directly
                this.outputChannel.appendLine(`[FileSystemProvider] No sealing needed, writing directly`);
                await fs.promises.writeFile(actualPath, textContent, 'utf8');
            }

            // Fire change event
            this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
        } catch (error: any) {
            this.outputChannel.appendLine(`[FileSystemProvider] Write error: ${error.message}`);
            throw vscode.FileSystemError.Unavailable(uri);
        }
    }

    delete(uri: vscode.Uri, options: { recursive: boolean }): void | Thenable<void> {
        const actualPath = this.getActualPath(uri);

        if (options.recursive) {
            return fs.promises.rm(actualPath, { recursive: true, force: true });
        } else {
            return fs.promises.unlink(actualPath);
        }
    }

    rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean }): void | Thenable<void> {
        const oldPath = this.getActualPath(oldUri);
        const newPath = this.getActualPath(newUri);

        return fs.promises.rename(oldPath, newPath);
    }
}
