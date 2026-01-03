import * as vscode from 'vscode';

/**
 * Shared types used across the extension
 */

/** Virtual document provider for rendered sss content */
export class SSSRenderProvider implements vscode.TextDocumentContentProvider {
    private renderedContent = new Map<string, string>();

    provideTextDocumentContent(uri: vscode.Uri): string {
        return this.renderedContent.get(uri.toString()) || '';
    }

    setContent(uri: vscode.Uri, content: string): void {
        this.renderedContent.set(uri.toString(), content);
    }
}
