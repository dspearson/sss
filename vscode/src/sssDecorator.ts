import * as vscode from 'vscode';
import { DECORATION_COLORS, DECORATION_BORDER, PATTERNS } from './constants';

/**
 * Provides syntax highlighting for sss markers
 *
 * Marker types:
 * - ⊕{...} - Plaintext secret (green)
 * - ⊠{...} - Encrypted secret (blue)
 * - ⊲{...} - Interpolated secret reference (purple)
 * - o+{...} - ASCII plaintext marker (green)
 * - <{...} - ASCII interpolation marker (purple)
 */
export class SSSDecorator {
    private plaintextDecoration: vscode.TextEditorDecorationType;
    private encryptedDecoration: vscode.TextEditorDecorationType;
    private interpolationDecoration: vscode.TextEditorDecorationType;
    private asciiPlaintextDecoration: vscode.TextEditorDecorationType;
    private asciiInterpolationDecoration: vscode.TextEditorDecorationType;

    constructor() {
        // Plaintext marker: ⊕{...}
        this.plaintextDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: DECORATION_COLORS.PLAINTEXT.BACKGROUND,
            borderRadius: DECORATION_BORDER.RADIUS,
            border: `${DECORATION_BORDER.WIDTH} ${DECORATION_BORDER.STYLE} ${DECORATION_COLORS.PLAINTEXT.BORDER}`,
            color: new vscode.ThemeColor('editorInfo.foreground'),
            overviewRulerColor: new vscode.ThemeColor('editorInfo.foreground'),
            overviewRulerLane: vscode.OverviewRulerLane.Right
        });

        // Encrypted marker: ⊠{...}
        this.encryptedDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: DECORATION_COLORS.ENCRYPTED.BACKGROUND,
            borderRadius: DECORATION_BORDER.RADIUS,
            border: `${DECORATION_BORDER.WIDTH} ${DECORATION_BORDER.STYLE} ${DECORATION_COLORS.ENCRYPTED.BORDER}`,
            color: new vscode.ThemeColor('textLink.foreground'),
            overviewRulerColor: new vscode.ThemeColor('textLink.foreground'),
            overviewRulerLane: vscode.OverviewRulerLane.Right
        });

        // Interpolation marker: ⊲{...}
        this.interpolationDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: DECORATION_COLORS.INTERPOLATION.BACKGROUND,
            borderRadius: DECORATION_BORDER.RADIUS,
            border: `${DECORATION_BORDER.WIDTH} ${DECORATION_BORDER.STYLE} ${DECORATION_COLORS.INTERPOLATION.BORDER}`,
            color: new vscode.ThemeColor('symbolIcon.variableForeground'),
            overviewRulerColor: new vscode.ThemeColor('symbolIcon.variableForeground'),
            overviewRulerLane: vscode.OverviewRulerLane.Right
        });

        // ASCII plaintext: o+{...}
        this.asciiPlaintextDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: DECORATION_COLORS.PLAINTEXT.BACKGROUND,
            borderRadius: DECORATION_BORDER.RADIUS,
            border: `${DECORATION_BORDER.WIDTH} ${DECORATION_BORDER.STYLE} ${DECORATION_COLORS.PLAINTEXT.BORDER}`,
            color: new vscode.ThemeColor('editorInfo.foreground'),
            overviewRulerColor: new vscode.ThemeColor('editorInfo.foreground'),
            overviewRulerLane: vscode.OverviewRulerLane.Right
        });

        // ASCII interpolation: <{...}
        this.asciiInterpolationDecoration = vscode.window.createTextEditorDecorationType({
            backgroundColor: DECORATION_COLORS.INTERPOLATION.BACKGROUND,
            borderRadius: DECORATION_BORDER.RADIUS,
            border: `${DECORATION_BORDER.WIDTH} ${DECORATION_BORDER.STYLE} ${DECORATION_COLORS.INTERPOLATION.BORDER}`,
            color: new vscode.ThemeColor('symbolIcon.variableForeground'),
            overviewRulerColor: new vscode.ThemeColor('symbolIcon.variableForeground'),
            overviewRulerLane: vscode.OverviewRulerLane.Right
        });
    }

    /**
     * Update decorations for the given text editor
     */
    public updateDecorations(editor: vscode.TextEditor | undefined): void {
        if (!editor) {
            return;
        }

        const text = editor.document.getText();
        const plaintextRanges: vscode.Range[] = [];
        const encryptedRanges: vscode.Range[] = [];
        const interpolationRanges: vscode.Range[] = [];
        const asciiPlaintextRanges: vscode.Range[] = [];
        const asciiInterpolationRanges: vscode.Range[] = [];

        // Find ⊕{...} markers (plaintext)
        let match;
        while ((match = PATTERNS.PLAINTEXT_MARKER.exec(text))) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);
            plaintextRanges.push(new vscode.Range(startPos, endPos));
        }

        // Find ⊠{...} markers (encrypted)
        while ((match = PATTERNS.ENCRYPTED_MARKER.exec(text))) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);
            encryptedRanges.push(new vscode.Range(startPos, endPos));
        }

        // Find ⊲{...} markers (interpolation)
        while ((match = PATTERNS.INTERPOLATION_MARKER.exec(text))) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);
            interpolationRanges.push(new vscode.Range(startPos, endPos));
        }

        // Find o+{...} markers (ASCII plaintext)
        while ((match = PATTERNS.ASCII_PLAINTEXT_MARKER.exec(text))) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);
            asciiPlaintextRanges.push(new vscode.Range(startPos, endPos));
        }

        // Find <{...} markers (ASCII interpolation)
        while ((match = PATTERNS.ASCII_INTERPOLATION_MARKER.exec(text))) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);
            asciiInterpolationRanges.push(new vscode.Range(startPos, endPos));
        }

        // Apply decorations
        editor.setDecorations(this.plaintextDecoration, plaintextRanges);
        editor.setDecorations(this.encryptedDecoration, encryptedRanges);
        editor.setDecorations(this.interpolationDecoration, interpolationRanges);
        editor.setDecorations(this.asciiPlaintextDecoration, asciiPlaintextRanges);
        editor.setDecorations(this.asciiInterpolationDecoration, asciiInterpolationRanges);
    }

    /**
     * Dispose all decorations
     */
    public dispose(): void {
        this.plaintextDecoration.dispose();
        this.encryptedDecoration.dispose();
        this.interpolationDecoration.dispose();
        this.asciiPlaintextDecoration.dispose();
        this.asciiInterpolationDecoration.dispose();
    }
}
