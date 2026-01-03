import * as vscode from 'vscode';
import { SSSWrapper } from './sssWrapper';
import { DISPLAY } from './constants';

export class SSSStatusBar {
    private statusBarItem: vscode.StatusBarItem;
    private sssWrapper: SSSWrapper;

    constructor(sssWrapper: SSSWrapper) {
        this.sssWrapper = sssWrapper;
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        // Switch to the Secrets sidebar when clicked
        this.statusBarItem.command = 'workbench.view.extension.sss-secrets';
    }

    async update(): Promise<void> {
        const config = vscode.workspace.getConfiguration('secrets');
        const showStatusBar = config.get<boolean>('showStatusBar', true);

        if (!showStatusBar) {
            this.statusBarItem.hide();
            return;
        }

        const projectInfo = await this.sssWrapper.checkProjectStatus();

        if (!projectInfo.isProject) {
            this.statusBarItem.hide();
            return;
        }

        // Get current file info
        const editor = vscode.window.activeTextEditor;
        let fileStatus = '';

        if (editor) {
            const content = editor.document.getText();

            if (this.sssWrapper.isEncrypted(content)) {
                fileStatus = '$(lock) ';
            } else if (this.sssWrapper.hasPlaintextMarkers(content)) {
                fileStatus = '$(unlock) ';
            }
        }

        // Get current key info
        let keyInfo = '';
        try {
            const currentKey = await this.sssWrapper.getCurrentKey();
            if (currentKey) {
                // Extract first chars of UUID for display
                const shortKey = currentKey.substring(0, DISPLAY.UUID_LENGTH);
                keyInfo = ` [${shortKey}]`;
            }
        } catch (error) {
            // Ignore error, just don't show key info
        }

        this.statusBarItem.text = `${fileStatus}sss${keyInfo}`;
        this.statusBarItem.tooltip = 'Click to open Secrets panel';
        this.statusBarItem.show();
    }

    dispose(): void {
        this.statusBarItem.dispose();
    }
}
