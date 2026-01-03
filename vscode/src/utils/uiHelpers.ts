import * as vscode from 'vscode';

/**
 * Common UI helper functions for prompts and validations
 */

export interface InputBoxOptions {
    prompt: string;
    placeHolder?: string;
    password?: boolean;
    validateInput?: (value: string) => string | null;
}

/** Validates that input is not empty */
export function validateNonEmpty(fieldName: string): (value: string) => string | null {
    return (value: string) => {
        if (!value || value.trim().length === 0) {
            return `${fieldName} cannot be empty`;
        }
        return null;
    };
}

/** Shows input box with validation */
export async function promptForInput(options: InputBoxOptions): Promise<string | undefined> {
    return await vscode.window.showInputBox({
        prompt: options.prompt,
        placeHolder: options.placeHolder,
        password: options.password,
        validateInput: options.validateInput
    });
}

/** Shows a non-empty input prompt */
export async function promptForNonEmptyInput(
    prompt: string,
    placeHolder: string,
    fieldName: string
): Promise<string | undefined> {
    return await promptForInput({
        prompt,
        placeHolder,
        validateInput: validateNonEmpty(fieldName)
    });
}

/** Shows password input prompt */
export async function promptForPassword(
    prompt: string = 'Enter password',
    placeHolder: string = 'password'
): Promise<string | undefined> {
    return await promptForInput({
        prompt,
        placeHolder,
        password: true
    });
}

export interface QuickPickOption<T = string> {
    label: string;
    description?: string;
    detail?: string;
    value: T;
}

/** Shows a quick pick menu with custom values */
export async function showQuickPick<T>(
    options: QuickPickOption<T>[],
    placeHolder: string,
    title?: string
): Promise<T | undefined> {
    const choice = await vscode.window.showQuickPick(options, {
        placeHolder,
        title
    });
    return choice?.value;
}

/** Shows an error message */
export function showError(message: string): void {
    vscode.window.showErrorMessage(message);
}

/** Shows an info message */
export function showInfo(message: string): void {
    vscode.window.showInformationMessage(message);
}

/** Shows a warning message */
export function showWarning(message: string): void {
    vscode.window.showWarningMessage(message);
}
