import * as vscode from 'vscode';
import * as path from 'path';
import { SSSWrapper } from './sssWrapper';
import { SSSStatusBar } from './statusBar';
import { ProjectManager } from './projectManager';
import { UserKeyManager } from './userKeyManager';
import { ProjectViewProvider, UsersViewProvider, KeysViewProvider, ActionsViewProvider } from './treeViews';
import { BinaryDownloader } from './binaryDownloader';
import { SSSFileSystemProvider } from './sssFileSystemProvider';
import { SSSFileDecorationProvider } from './sssFileDecorationProvider';
import { SSSDecorator } from './sssDecorator';
import { SSSHoverProvider } from './sssHoverProvider';
import { GitIntegration } from './gitIntegration';
import { SSSRenderProvider } from './types';
import { SecretsFileLocator, SecretsFileParser } from './utils';
import {
    FileCommands,
    SecretCommands,
    ProjectCommands,
    ConfigCommands,
    registerAllCommands
} from './commands';
import {
    DocumentEventHandlers,
    WorkspaceEventHandlers,
    registerAllEventHandlers
} from './events';
import {
    OUTPUT_CHANNEL_NAME,
    TREE_VIEWS,
    URI_SCHEMES,
    CONFIG_SECTION,
    CONFIG_KEYS,
    PROGRESS,
    BUTTONS,
    LANGUAGES,
    CONTEXT_KEYS
} from './constants';

let sssWrapper: SSSWrapper;
let statusBar: SSSStatusBar;
let projectManager: ProjectManager;
let userKeyManager: UserKeyManager;
let outputChannel: vscode.OutputChannel;
let projectViewProvider: ProjectViewProvider;
let usersViewProvider: UsersViewProvider;
let keysViewProvider: KeysViewProvider;
let actionsViewProvider: ActionsViewProvider;
let renderProvider: SSSRenderProvider;
let binaryDownloader: BinaryDownloader;
let fileSystemProvider: SSSFileSystemProvider;
let fileDecorationProvider: SSSFileDecorationProvider;
let sssDecorator: SSSDecorator;
let hoverProvider: SSSHoverProvider;
let gitIntegration: GitIntegration;

// Global promise to track when activation and authentication are complete
// FileSystemProvider will wait for this before processing file operations
export let activationComplete: Promise<void> | null = null;

// Track whether authentication succeeded (for file:// interception)
let authenticationSucceeded = false;

export async function activate(context: vscode.ExtensionContext) {
    // Create output channel
    outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
    context.subscriptions.push(outputChannel);

    outputChannel.appendLine('=== Extension Activation Started ===');
    outputChannel.appendLine(`Workspace folders: ${vscode.workspace.workspaceFolders?.map(f => `${f.name} (${f.uri.scheme}://${f.uri.path})`).join(', ') || 'none'}`);

    // Create activation promise that FileSystemProvider can wait for
    let resolveActivation: () => void;
    activationComplete = new Promise<void>((resolve) => {
        resolveActivation = resolve;
    });

    // Initialise binary downloader and ensure binary is available
    binaryDownloader = new BinaryDownloader(context, outputChannel);
    let sssPath: string;
    try {
        sssPath = await binaryDownloader.ensureBinary();
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to download sss binary: ${error.message}`);
        // Fall back to 'sss' in PATH
        sssPath = 'sss';
    }

    // Initialise components
    sssWrapper = new SSSWrapper(outputChannel, sssPath);
    statusBar = new SSSStatusBar(sssWrapper);
    projectManager = new ProjectManager(sssWrapper);
    userKeyManager = new UserKeyManager(sssWrapper);

    // Initialise tree view providers
    projectViewProvider = new ProjectViewProvider(sssWrapper);
    usersViewProvider = new UsersViewProvider(sssWrapper);
    keysViewProvider = new KeysViewProvider(sssWrapper);
    actionsViewProvider = new ActionsViewProvider(sssWrapper);

    // Register tree views
    context.subscriptions.push(
        vscode.window.registerTreeDataProvider(TREE_VIEWS.PROJECT, projectViewProvider),
        vscode.window.registerTreeDataProvider(TREE_VIEWS.USERS, usersViewProvider),
        vscode.window.registerTreeDataProvider(TREE_VIEWS.KEYS, keysViewProvider),
        vscode.window.registerTreeDataProvider(TREE_VIEWS.ACTIONS, actionsViewProvider)
    );

    // Register virtual document provider for rendered content
    renderProvider = new SSSRenderProvider();
    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider(URI_SCHEMES.SSS_RENDER, renderProvider)
    );

    // Register FileSystemProvider IMMEDIATELY to handle sss-fs:// URIs
    // This must be done early so VS Code can restore previously open files
    // Authentication will be handled inside the FileSystemProvider's readFile()
    fileSystemProvider = new SSSFileSystemProvider(sssWrapper, outputChannel);
    context.subscriptions.push(
        vscode.workspace.registerFileSystemProvider(URI_SCHEMES.SSS_FS, fileSystemProvider, {
            isCaseSensitive: true,
            isReadonly: false
        })
    );

    outputChannel.appendLine(`FileSystemProvider registered for ${URI_SCHEMES.SSS_FS}:// URIs`);

    // Initialise sss marker decorator EARLY (before authentication)
    // This ensures decorations appear as soon as files are opened
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const highlightMarkersEnabled = config.get<boolean>(CONFIG_KEYS.HIGHLIGHT_MARKERS, true);

    if (highlightMarkersEnabled) {
        sssDecorator = new SSSDecorator();
        context.subscriptions.push(sssDecorator);

        // Update decorations for all currently visible editors
        vscode.window.visibleTextEditors.forEach(editor => {
            sssDecorator.updateDecorations(editor);
        });

        // Update decorations when active editor changes
        context.subscriptions.push(
            vscode.window.onDidChangeActiveTextEditor(editor => {
                if (editor) {
                    sssDecorator.updateDecorations(editor);
                }
            })
        );

        // Update decorations when document changes
        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument(event => {
                const editor = vscode.window.activeTextEditor;
                if (editor && event.document === editor.document) {
                    sssDecorator.updateDecorations(editor);
                }
            })
        );

        outputChannel.appendLine('sss marker highlighting enabled');
    } else {
        outputChannel.appendLine('sss marker highlighting disabled');
    }

    // Check if we're in an sss project
    await updateProjectContext();
    const projectInfo = await sssWrapper.checkProjectStatus();

    // If in an sss project, proactively authenticate
    // This provides a better UX - user sees authentication prompt immediately
    // rather than when first file is accessed
    if (projectInfo.isProject) {
        // Use withProgress to show a clear authentication prompt
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: PROGRESS.TITLE,
            cancellable: false
        }, async (progress) => {
            try {
                progress.report({ message: PROGRESS.CHECKING_AUTH });
                outputChannel.appendLine('sss project detected, checking authentication...');
                await sssWrapper.ensureAuthenticated();
                progress.report({ message: PROGRESS.AUTH_SUCCESS });
                outputChannel.appendLine('Authentication ready');
                authenticationSucceeded = true;
            } catch (error: any) {
                outputChannel.appendLine(`Authentication failed: ${error.message}`);
                authenticationSucceeded = false;

                // If authentication failed, we'll fall back to file:// URIs
                const retry = await vscode.window.showErrorMessage(
                    `Failed to authenticate: ${error.message}`,
                    BUTTONS.RETRY,
                    BUTTONS.USE_FILE_SCHEME
                );

                if (retry === BUTTONS.RETRY) {
                    // Reload the window to try again
                    vscode.commands.executeCommand('workbench.action.reloadWindow');
                } else {
                    vscode.window.showWarningMessage(`Using ${URI_SCHEMES.FILE}:// scheme - files will appear encrypted on disk`);
                }
            }
        });
    }

    // Resolve activation promise - FileSystemProvider can now process file operations
    outputChannel.appendLine('Activation complete - resolving activation promise');
    resolveActivation!();

    // Refresh decorations for all visible editors after authentication
    // This catches any files that opened during the authentication process
    if (sssDecorator) {
        outputChannel.appendLine('Refreshing decorations for all visible editors...');
        vscode.window.visibleTextEditors.forEach(editor => {
            sssDecorator.updateDecorations(editor);
        });
    }

    // Register FileDecorationProvider to show Git status on sss-fs:// URIs
    fileDecorationProvider = new SSSFileDecorationProvider(outputChannel);
    context.subscriptions.push(
        vscode.window.registerFileDecorationProvider(fileDecorationProvider)
    );

    // Register hover provider for interpolated references
    hoverProvider = new SSSHoverProvider(sssWrapper, outputChannel);
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(
            { scheme: URI_SCHEMES.FILE, pattern: '**/*' },
            hoverProvider
        ),
        vscode.languages.registerHoverProvider(
            { scheme: URI_SCHEMES.SSS_FS, pattern: '**/*' },
            hoverProvider
        )
    );
    outputChannel.appendLine('sss hover provider registered');

    // Initialise Git integration for pre-commit checks
    // Do this asynchronously to avoid blocking activation if Git extension isn't ready
    (async () => {
        try {
            // Wait for Git extension to be available
            const gitExtension = vscode.extensions.getExtension('vscode.git');
            if (gitExtension && !gitExtension.isActive) {
                await gitExtension.activate();
            }

            gitIntegration = new GitIntegration(sssWrapper, outputChannel);

            // If in an sss project, register pre-commit check
            if (projectInfo.isProject) {
                gitIntegration.registerPreCommitCheck(context);
            }
        } catch (error: any) {
            outputChannel.appendLine(`Error initialising Git integration: ${error.message}`);
            // Continue even if Git integration fails
        }
    })();

    // If in an sss project, handle workspace folder URIs based on authentication
    if (projectInfo.isProject) {
        try {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (workspaceFolders && workspaceFolders.length > 0) {
                if (authenticationSucceeded) {
                    // Authentication succeeded - convert to sss-fs:// for transparent encryption
                    const hasFileScheme = workspaceFolders.some(f => f.uri.scheme === URI_SCHEMES.FILE);

                    if (hasFileScheme) {
                        outputChannel.appendLine(`Authentication successful, converting workspace folders to ${URI_SCHEMES.SSS_FS}:// URIs...`);

                        const newFolders = workspaceFolders.map(folder => {
                            if (folder.uri.scheme === URI_SCHEMES.FILE) {
                                return {
                                    uri: vscode.Uri.parse(`${URI_SCHEMES.SSS_FS}://${folder.uri.fsPath}`),
                                    name: folder.name,
                                    index: folder.index
                                };
                            }
                            return folder;
                        });

                        const result = vscode.workspace.updateWorkspaceFolders(
                            0,
                            workspaceFolders.length,
                            ...newFolders.map(f => ({ uri: f.uri, name: f.name }))
                        );

                        if (result) {
                            outputChannel.appendLine(`Workspace folders converted to ${URI_SCHEMES.SSS_FS}:// successfully`);
                        } else {
                            outputChannel.appendLine('Failed to update workspace folders');
                        }
                    }
                } else {
                    // Authentication failed - fall back to file:// scheme
                    const hasSssScheme = workspaceFolders.some(f => f.uri.scheme === URI_SCHEMES.SSS_FS);

                    if (hasSssScheme) {
                        outputChannel.appendLine(`Authentication failed, reverting workspace folders to ${URI_SCHEMES.FILE}:// URIs...`);

                        const newFolders = workspaceFolders.map(folder => {
                            if (folder.uri.scheme === URI_SCHEMES.SSS_FS) {
                                return {
                                    uri: vscode.Uri.file(folder.uri.path),
                                    name: folder.name,
                                    index: folder.index
                                };
                            }
                            return folder;
                        });

                        vscode.workspace.updateWorkspaceFolders(
                            0,
                            workspaceFolders.length,
                            ...newFolders.map(f => ({ uri: f.uri, name: f.name }))
                        );
                    }
                }
            }
        } catch (error: any) {
            outputChannel.appendLine(`Error updating workspace folders: ${error.message}`);
            // Continue with activation even if workspace folder update fails
        }
    }

    // Instantiate command handlers
    const secretsLocator = new SecretsFileLocator(sssWrapper, outputChannel);
    const secretsParser = new SecretsFileParser(sssWrapper, outputChannel);

    const fileCommands = new FileCommands(sssWrapper, renderProvider, outputChannel);
    const secretCommands = new SecretCommands(secretsLocator, secretsParser, outputChannel);
    const projectCommands = new ProjectCommands(
        sssWrapper,
        projectManager,
        gitIntegration,
        { project: projectViewProvider, users: usersViewProvider, keys: keysViewProvider, actions: actionsViewProvider },
        updateProjectContext
    );
    const configCommands = new ConfigCommands(
        sssWrapper,
        binaryDownloader,
        { project: projectViewProvider, users: usersViewProvider, keys: keysViewProvider, actions: actionsViewProvider }
    );

    // Register all commands using the new modular system
    outputChannel.appendLine('Registering commands...');
    registerAllCommands(
        context,
        fileCommands,
        secretCommands,
        projectCommands,
        configCommands,
        userKeyManager,
        { project: projectViewProvider, users: usersViewProvider, keys: keysViewProvider, actions: actionsViewProvider }
    );
    outputChannel.appendLine('Commands registered successfully');

    // Instantiate and register event handlers
    const documentHandlers = new DocumentEventHandlers(
        sssWrapper,
        outputChannel,
        () => authenticationSucceeded
    );
    const workspaceHandlers = new WorkspaceEventHandlers(
        statusBar,
        updateProjectContext
    );

    registerAllEventHandlers(context, documentHandlers, workspaceHandlers);

    // Auto-detect and set language mode for secrets files
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(async (document) => {
            const fileName = path.basename(document.uri.fsPath);
            const settings = await sssWrapper.parseSettings();

            // Check if this is a secrets file
            const isSecretsFile = fileName === settings.secretsFilename ||
                                (settings.secretsSuffix && fileName.endsWith(settings.secretsSuffix));

            if (isSecretsFile && document.languageId !== LANGUAGES.SECRETS) {
                await vscode.languages.setTextDocumentLanguage(document, LANGUAGES.SECRETS);
            }
        })
    );

    // Update status bar
    await statusBar.update();

    outputChannel.appendLine(`${OUTPUT_CHANNEL_NAME} extension activated successfully`);
}

async function updateProjectContext() {
    const projectInfo = await sssWrapper.checkProjectStatus();
    outputChannel.appendLine(`[updateProjectContext] isProject: ${projectInfo.isProject}, projectRoot: ${projectInfo.projectRoot}`);
    await vscode.commands.executeCommand('setContext', CONTEXT_KEYS.IS_PROJECT, projectInfo.isProject);
}

export function deactivate() {
    // Clear cached password for security
    if (sssWrapper) {
        sssWrapper.clearCachedPassword();
    }

    if (statusBar) {
        statusBar.dispose();
    }

    if (sssDecorator) {
        sssDecorator.dispose();
    }
}
