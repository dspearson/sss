/**
 * Centralized event handler registration
 */

import * as vscode from 'vscode';
import { DocumentEventHandlers } from './documentEvents';
import { WorkspaceEventHandlers } from './workspaceEvents';

export * from './documentEvents';
export * from './workspaceEvents';

/**
 * Register all event handlers with VS Code
 */
export function registerAllEventHandlers(
    context: vscode.ExtensionContext,
    documentHandlers: DocumentEventHandlers,
    workspaceHandlers: WorkspaceEventHandlers
): void {
    // Document events
    context.subscriptions.push(
        vscode.workspace.onWillSaveTextDocument(e => documentHandlers.handleWillSaveDocument(e))
    );

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => documentHandlers.handleDidOpenDocument(doc))
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => documentHandlers.handleDidChangeDocument(e))
    );

    // Workspace and UI events
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(() =>
            workspaceHandlers.handleDidChangeActiveTextEditor()
        )
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeWorkspaceFolders(() =>
            workspaceHandlers.handleDidChangeWorkspaceFolders()
        )
    );

    context.subscriptions.push(
        vscode.workspace.onWillDeleteFiles(e => workspaceHandlers.handleWillDeleteFiles(e))
    );
}
