# Quick Start Guide

## Setup

1. **Install Dependencies**
   ```bash
   cd vscode-extension
   npm install
   ```

2. **Compile the Extension**
   ```bash
   npm run compile
   ```

3. **Test the Extension**
   - Press F5 in VS Code to open a new window with the extension loaded
   - Or run: `code --extensionDevelopmentPath=/path/to/vscode-extension`

## Development Workflow

1. **Edit Source Files**
   - Main entry point: `src/extension.ts`
   - SSS wrapper: `src/sssWrapper.ts`
   - Status bar: `src/statusBar.ts`
   - Project management: `src/projectManager.ts`
   - User/Key management: `src/userKeyManager.ts`

2. **Watch Mode** (auto-compile on changes)
   ```bash
   npm run watch
   ```

3. **Reload Extension**
   - In the Extension Development Host window, press `Ctrl+R` (or `Cmd+R` on Mac)
   - Or use Command Palette: "Developer: Reload Window"

## Testing the Extension

1. **Open a Test Project**
   - Create a test directory
   - Initialize SSS: `sss init testuser`
   - Open the directory in the Extension Development Host

2. **Test Commands**
   - Open Command Palette (Ctrl+Shift+P)
   - Try commands: "SSS: Initialize Project", "SSS: Generate New Keypair", etc.

3. **Test Auto-Seal/Open**
   - Create a file with: `API_KEY=⊕{secret123}`
   - Save the file (should auto-seal)
   - Reload the file (should auto-open)

## Packaging

```bash
npm run package
```

This creates a `.vsix` file that can be installed in VS Code.

## Installing the VSIX

```bash
code --install-extension sss-vscode-0.1.0.vsix
```

## Next Steps

### Features to Implement

1. **Enhanced File System Provider**
   - Virtual file system for transparent rendering
   - In-memory decryption without modifying files

2. **Syntax Highlighting**
   - Custom TextMate grammar for SSS markers
   - Semantic highlighting for encrypted content

3. **Code Lens**
   - Inline preview of decrypted values
   - Quick actions for seal/open

4. **Tree View**
   - Sidebar view for project users
   - Key management interface
   - Project settings

5. **Decorations**
   - Visual indicators for encrypted content
   - Different colors for sealed vs unsealed markers

6. **Git Integration**
   - Pre-commit validation
   - Warning badges for unsealed files
   - Diff view with decrypted content

7. **Webview UI**
   - Graphical project settings
   - User management panel
   - Key management interface

### Improvements Needed

1. **Better Error Handling**
   - More descriptive error messages
   - Retry logic for failed operations
   - Graceful degradation

2. **Performance**
   - Cache project status
   - Debounce auto-seal/open operations
   - Background processing

3. **Testing**
   - Unit tests for each module
   - Integration tests
   - End-to-end tests

4. **Documentation**
   - API documentation
   - Architecture diagrams
   - Video tutorials

## Debugging

1. **Enable Verbose Logging**
   - Settings > SSS > Verbose Logging
   - View > Output > SSS

2. **Set Breakpoints**
   - Open source files in main VS Code window
   - Set breakpoints
   - Press F5 to start debugging

3. **Check Output**
   - View > Output > SSS
   - Look for error messages and stack traces

## Common Issues

### "sss command not found"
- Set `sss.sssPath` in settings to full path: `/path/to/sss`

### Auto-seal not working
- Check that `sss.autoSealOnSave` is enabled
- Verify file contains plaintext markers
- Check output panel for errors

### Extension not activating
- Check that workspace contains `.sss.toml`
- Or manually run a command to activate

### Commands not visible
- Ensure you're in an SSS project
- Check `package.json` activation events
- Reload window
