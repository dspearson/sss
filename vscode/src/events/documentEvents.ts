import * as vscode from 'vscode';
import { SSSWrapper } from '../sssWrapper';
import { URI_SCHEMES, MARKER_SEQUENCES } from '../constants';

/**
 * Document-related event handlers (save, open, change)
 */
export class DocumentEventHandlers {
    constructor(
        private sssWrapper: SSSWrapper,
        private outputChannel: vscode.OutputChannel,
        private authenticationSucceeded: () => boolean
    ) {}

    /**
     * Auto-seal files on save when they contain markers
     */
    async handleWillSaveDocument(event: vscode.TextDocumentWillSaveEvent): Promise<void> {
        if (!this.shouldProcessDocument(event.document, 'autoSealOnSave', true)) {
            return;
        }

        if (this.isSpecialFile(event.document.uri.fsPath)) {
            this.log('Auto-seal', `Skipping special file: ${event.document.uri.fsPath}`);
            return;
        }

        const projectInfo = await this.sssWrapper.checkProjectStatus();
        if (!projectInfo.isProject) {
            return;
        }

        const content = event.document.getText();
        const filePath = event.document.uri.fsPath;

        const hasPlaintextMarkers = this.sssWrapper.hasPlaintextMarkers(content);
        const shouldAutoSeal = await this.sssWrapper.shouldAutoSeal(filePath);

        if (hasPlaintextMarkers || shouldAutoSeal) {
            event.waitUntil(this.sealFile(filePath));
        }
    }

    /**
     * Convert file:// to sss-fs:// when appropriate
     */
    async handleDidOpenDocument(document: vscode.TextDocument): Promise<void> {
        if (document.uri.scheme !== URI_SCHEMES.FILE) {
            return;
        }

        if (!this.shouldProcessDocument(document, 'autoOpenOnLoad', false)) {
            return;
        }

        const filePath = document.uri.fsPath;
        if (this.isSpecialFile(filePath)) {
            return;
        }

        const projectInfo = await this.sssWrapper.checkProjectStatus();
        if (!projectInfo.isProject) {
            return;
        }

        if (!this.authenticationSucceeded()) {
            this.log('File Interception', `Skipping conversion - auth not successful: ${filePath}`);
            return;
        }

        await this.convertToSssFs(document);
    }

    /**
     * Auto-normalise ASCII markers to UTF-8 as you type
     */
    async handleDidChangeDocument(event: vscode.TextDocumentChangeEvent): Promise<void> {
        if (event.contentChanges.length === 0) {
            return;
        }

        if (event.document.uri.scheme !== URI_SCHEMES.FILE) {
            return;
        }

        const filePath = event.document.uri.fsPath;
        if (this.isGitFile(filePath)) {
            return;
        }

        const config = vscode.workspace.getConfiguration('secrets');
        const autoNormalise = config.get<boolean>('autoNormaliseMarkers', true);
        this.log('Auto-normalise', `Triggered. Enabled: ${autoNormalise}`);

        if (!autoNormalise) {
            return;
        }

        const projectInfo = await this.sssWrapper.checkProjectStatus();
        this.log('Auto-normalise', `Is project: ${projectInfo.isProject}`);

        if (!projectInfo.isProject) {
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document !== event.document) {
            this.log('Auto-normalise', 'No active editor or document mismatch');
            return;
        }

        await this.normaliseMarkersInChanges(editor, event.contentChanges);
    }

    private async sealFile(filePath: string): Promise<void> {
        try {
            await this.sssWrapper.seal(filePath);
            this.log('Auto-seal', `Sealed: ${filePath}`);
        } catch (error: any) {
            this.log('Auto-seal', `Failed: ${error.message}`);
        }
    }

    private async convertToSssFs(document: vscode.TextDocument): Promise<void> {
        const filePath = document.uri.fsPath;

        try {
            const content = await vscode.workspace.fs.readFile(document.uri);
            const text = Buffer.from(content).toString('utf8');

            if (!this.sssWrapper.hasMarkers(text)) {
                return;
            }

            this.log('File Interception', `Converting file:// to sss-fs://: ${filePath}`);

            const editor = vscode.window.visibleTextEditors.find(
                e => e.document.uri.toString() === document.uri.toString()
            );

            if (!editor) {
                return;
            }

            await this.reopenWithSssFs(editor, filePath);
            this.log('File Interception', `Successfully converted: ${filePath}`);
        } catch (error: any) {
            this.log('File Interception', `Error converting file: ${error.message}`);
        }
    }

    private async reopenWithSssFs(editor: vscode.TextEditor, filePath: string): Promise<void> {
        const viewColumn = editor.viewColumn;
        const selection = editor.selection;
        const visibleRanges = editor.visibleRanges;

        const sssUri = vscode.Uri.parse(`${URI_SCHEMES.SSS_FS}://${filePath}`);

        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');

        const doc = await vscode.workspace.openTextDocument(sssUri);
        const newEditor = await vscode.window.showTextDocument(doc, {
            viewColumn,
            preserveFocus: false,
            preview: false
        });

        newEditor.selection = selection;
        newEditor.revealRange(visibleRanges[0], vscode.TextEditorRevealType.InCenter);
    }

    private async normaliseMarkersInChanges(
        editor: vscode.TextEditor,
        changes: readonly vscode.TextDocumentContentChangeEvent[]
    ): Promise<void> {
        for (const change of changes) {
            this.log('Auto-normalise', `Change text: "${change.text}"`);

            const document = editor.document;
            const line = document.lineAt(change.range.start.line);
            const lineText = line.text;

            this.log('Auto-normalise', `Line text: "${lineText}"`);

            if (lineText.includes(MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN) || lineText.includes(MARKER_SEQUENCES.INTERPOLATION_ALT_OPEN)) {
                await this.normaliseLineMarkers(editor, line, lineText);
            }
        }
    }

    private async normaliseLineMarkers(
        editor: vscode.TextEditor,
        line: vscode.TextLine,
        lineText: string
    ): Promise<void> {
        this.log('Auto-normalise', 'Found ASCII markers, replacing...');

        const cursorPos = editor.selection.active;
        const offsetAdjustment = this.calculateOffsetAdjustment(lineText, cursorPos.character);

        let normalisedLine = lineText
            .replaceAll(MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN, MARKER_SEQUENCES.PLAINTEXT_OPEN)
            .replaceAll(MARKER_SEQUENCES.INTERPOLATION_ALT_OPEN, MARKER_SEQUENCES.INTERPOLATION_OPEN);

        if (normalisedLine !== lineText) {
            this.log('Auto-normalise', `Normalised: "${normalisedLine}"`);
            this.log('Auto-normalise', `Cursor adjustment: -${offsetAdjustment}`);

            await editor.edit(
                editBuilder => {
                    editBuilder.replace(line.range, normalisedLine);
                },
                {
                    undoStopBefore: false,
                    undoStopAfter: false
                }
            );

            if (offsetAdjustment > 0) {
                const newCursorPos = new vscode.Position(
                    cursorPos.line,
                    Math.max(0, cursorPos.character - offsetAdjustment)
                );
                editor.selection = new vscode.Selection(newCursorPos, newCursorPos);
                this.log('Auto-normalise', `Moved cursor from ${cursorPos.character} to ${newCursorPos.character}`);
            }
        }
    }

    private calculateOffsetAdjustment(lineText: string, cursorOffset: number): number {
        let adjustment = 0;
        let searchPos = 0;

        // Count o+{ replacements before cursor (3 chars -> 2 chars = -1 char each)
        while (true) {
            const oplusIndex = lineText.indexOf(MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN, searchPos);
            if (oplusIndex === -1 || oplusIndex >= cursorOffset) {
                break;
            }
            adjustment += 1;
            searchPos = oplusIndex + MARKER_SEQUENCES.ASCII_PLAINTEXT_OPEN.length;
        }

        return adjustment;
    }

    private shouldProcessDocument(
        document: vscode.TextDocument,
        configKey: string,
        defaultValue: boolean
    ): boolean {
        if (document.uri.scheme === URI_SCHEMES.SSS_FS) {
            this.log('Processing', `Skipping ${URI_SCHEMES.SSS_FS}:// URI (handled by FileSystemProvider)`);
            return false;
        }

        if (document.uri.scheme !== URI_SCHEMES.FILE) {
            this.log('Processing', `Skipping non-file URI: ${document.uri.scheme}`);
            return false;
        }

        const config = vscode.workspace.getConfiguration('secrets');
        return config.get<boolean>(configKey, defaultValue);
    }

    private isSpecialFile(filePath: string): boolean {
        return (
            filePath.includes('extension-output') ||
            this.isGitFile(filePath)
        );
    }

    private isGitFile(filePath: string): boolean {
        return filePath.includes('/.git/') || filePath.endsWith('.git');
    }

    private log(category: string, message: string): void {
        this.outputChannel.appendLine(`[${category}] ${message}`);
    }
}
