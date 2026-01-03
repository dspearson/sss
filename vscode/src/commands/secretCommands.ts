import * as vscode from 'vscode';
import * as path from 'path';
import { SecretsFileLocator, SecretsFileParser, addSecretToFile } from '../utils';
import { MARKER_SEQUENCES, PATTERNS } from '../constants';

/**
 * Commands for working with secrets and interpolation
 */
export class SecretCommands {
    constructor(
        private locator: SecretsFileLocator,
        private parser: SecretsFileParser,
        private outputChannel: vscode.OutputChannel
    ) {}

    async insertInterpolatedSecret(): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selection = editor.selection;
        const currentFilePath = this.getFilePath(editor);
        const currentDir = path.dirname(currentFilePath);
        const currentFileName = path.basename(currentFilePath);

        const secretsFile = await this.locator.findOrCreateSecretsFile(
            currentFilePath,
            currentFileName,
            currentDir
        );

        if (!secretsFile) {
            return;
        }

        const selectedSecretName = await this.selectOrCreateSecret(secretsFile);
        if (!selectedSecretName) {
            return;
        }

        await this.insertSecretReference(editor, selection, selectedSecretName);
        vscode.window.showInformationMessage(`Inserted: ${MARKER_SEQUENCES.INTERPOLATION_OPEN}${selectedSecretName}}`);
    }

    async goToSecretDefinition(): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const secretKey = this.findSecretKeyAtCursor(editor);
        if (!secretKey) {
            vscode.window.showInformationMessage('Cursor is not on an interpolated secret reference');
            return;
        }

        const currentFilePath = this.getFilePath(editor);
        const currentDir = path.dirname(currentFilePath);
        const currentFileName = path.basename(currentFilePath);

        const secretsFile = await this.locator.findOrCreateSecretsFile(
            currentFilePath,
            currentFileName,
            currentDir
        );

        if (!secretsFile) {
            vscode.window.showErrorMessage('No secrets file found');
            return;
        }

        const lineNumber = await this.parser.findSecretDefinitionLine(secretsFile, secretKey);
        if (lineNumber === null) {
            vscode.window.showInformationMessage(
                `Secret '${secretKey}' not found in ${path.basename(secretsFile)}`
            );
            return;
        }

        await this.openAndHighlightSecret(secretsFile, lineNumber, secretKey);
    }

    private async selectOrCreateSecret(secretsFile: string): Promise<string | null> {
        const keys = await this.parser.parseSecretsFile(secretsFile);

        if (keys.length === 0) {
            vscode.window.showInformationMessage('Secrets file is empty. Add your first secret.');
            return await addSecretToFile(secretsFile);
        }

        const items = [
            {
                label: '$(add) Create new secret...',
                description: '',
                detail: 'Add a new secret to the secrets file',
                value: '__CREATE_NEW__'
            },
            ...keys.map(k => ({
                label: k.key,
                description: k.hasValue ? '$(check) has value' : '$(circle-slash) no value',
                detail: `From ${path.basename(secretsFile)}`,
                value: k.key
            }))
        ];

        const selectedKey = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select secret to interpolate or create new',
            title: 'Insert Interpolated Secret'
        });

        if (!selectedKey) {
            return null;
        }

        if (selectedKey.value === '__CREATE_NEW__') {
            return await addSecretToFile(secretsFile);
        }

        return selectedKey.value;
    }

    private async insertSecretReference(
        editor: vscode.TextEditor,
        selection: vscode.Selection,
        secretName: string
    ): Promise<void> {
        const interpolatedText = `${MARKER_SEQUENCES.INTERPOLATION_OPEN}${secretName}}`;

        await editor.edit(editBuilder => {
            if (selection.isEmpty) {
                editBuilder.insert(selection.start, interpolatedText);
            } else {
                editBuilder.replace(selection, interpolatedText);
            }
        });
    }

    private findSecretKeyAtCursor(editor: vscode.TextEditor): string | null {
        const position = editor.selection.active;
        const line = editor.document.lineAt(position.line);
        const text = line.text;

        let match;

        while ((match = PATTERNS.ANY_INTERPOLATION_MARKER.exec(text))) {
            const start = match.index;
            const end = match.index + match[0].length;

            if (position.character >= start && position.character <= end) {
                return match[1];
            }
        }

        return null;
    }

    private async openAndHighlightSecret(
        secretsFile: string,
        lineNumber: number,
        secretKey: string
    ): Promise<void> {
        const sssUri = vscode.Uri.parse(`sss-fs://${secretsFile}`);
        const document = await vscode.workspace.openTextDocument(sssUri);

        await vscode.languages.setTextDocumentLanguage(document, 'sss-secrets');

        const targetPosition = new vscode.Position(lineNumber, 0);
        await vscode.window.showTextDocument(document, {
            selection: new vscode.Range(targetPosition, targetPosition),
            viewColumn: vscode.ViewColumn.Beside
        });

        await this.selectSecretValue(lineNumber, secretKey);
    }

    private async selectSecretValue(lineNumber: number, secretKey: string): Promise<void> {
        const targetEditor = vscode.window.activeTextEditor;
        if (!targetEditor) {
            return;
        }

        const targetLine = targetEditor.document.lineAt(lineNumber);
        const lineText = targetLine.text;

        const multiLineMatch = lineText.match(
            /^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*\|\s*$/
        );

        if (multiLineMatch) {
            this.selectMultilineValue(targetEditor, lineNumber);
        } else {
            this.selectSingleLineValue(targetEditor, lineNumber, lineText, secretKey);
        }
    }

    private selectMultilineValue(editor: vscode.TextEditor, lineNumber: number): void {
        if (lineNumber + 1 >= editor.document.lineCount) {
            return;
        }

        const nextLine = editor.document.lineAt(lineNumber + 1);
        const contentMatch = nextLine.text.match(/^\s+(.*)$/);

        if (contentMatch) {
            const indentLength = nextLine.text.length - contentMatch[1].length;
            const valueStart = new vscode.Position(lineNumber + 1, indentLength);
            const valueEnd = new vscode.Position(lineNumber + 1, nextLine.text.length);
            editor.selection = new vscode.Selection(valueStart, valueEnd);
            editor.revealRange(
                new vscode.Range(valueStart, valueEnd),
                vscode.TextEditorRevealType.InCenter
            );
        }
    }

    private selectSingleLineValue(
        editor: vscode.TextEditor,
        lineNumber: number,
        lineText: string,
        secretKey: string
    ): void {
        const colonIndex = lineText.indexOf(':', lineText.indexOf(secretKey));
        if (colonIndex === -1) {
            return;
        }

        let actualValueStart = colonIndex + 1;
        while (actualValueStart < lineText.length && lineText[actualValueStart] === ' ') {
            actualValueStart++;
        }

        const valueStart = new vscode.Position(lineNumber, actualValueStart);
        const valueEnd = new vscode.Position(lineNumber, lineText.length);
        editor.selection = new vscode.Selection(valueStart, valueEnd);
        editor.revealRange(
            new vscode.Range(valueStart, valueEnd),
            vscode.TextEditorRevealType.InCenter
        );
    }

    private getFilePath(editor: vscode.TextEditor): string {
        return editor.document.uri.scheme === 'sss-fs'
            ? editor.document.uri.path
            : editor.document.uri.fsPath;
    }
}
