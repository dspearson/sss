# SSS - Secret String Substitution for VS Code

A VS Code extension for transparent encryption and decryption of files using the SSS (Secret String Substitution) tool.

## Features

### Primary Features

- **Transparent Encryption/Decryption**: Automatically decrypt files when opening and encrypt when saving
- **Auto-Seal on Save**: Automatically encrypt plaintext markers when saving files
- **Auto-Open on Load**: Automatically decrypt encrypted markers when opening files
- **Visual Indicators**: Status bar shows encryption status of current file

### Project Management

- Initialize new SSS projects
- View project information
- Install Git hooks for automatic sealing on commit

### User Management

- Add users to projects
- Remove users from projects
- List all project users

### Key Management

- Generate new keypairs
- List available keypairs
- Set current keypair
- View and share public keys

## Prerequisites

- VS Code 1.85.0 or higher
- SSS tool installed and available in PATH (or configured in settings)
- Git (for hook installation)

## Installation

### From VSIX

1. Download the `.vsix` file
2. Open VS Code
3. Go to Extensions view (Ctrl+Shift+X)
4. Click the "..." menu at the top
5. Select "Install from VSIX..."
6. Select the downloaded file

### Development Installation

1. Clone this repository
2. Run `npm install`
3. Run `npm run compile`
4. Press F5 to open a new VS Code window with the extension loaded

## Usage

### Getting Started

1. Open a folder in VS Code
2. Run command: **SSS: Initialize Project**
3. Enter your username when prompted
4. Optionally install Git hooks when prompted

### Working with Encrypted Files

#### Manual Operations

- **Seal File (Encrypt)**: Right-click file > SSS: Seal File
- **Open File (Decrypt to Markers)**: Right-click file > SSS: Open File
- **Render File (Show Plaintext)**: Right-click file > SSS: Render File
- **Seal All Files**: Command Palette > SSS: Seal All Files in Workspace
- **Open All Files**: Command Palette > SSS: Open All Files in Workspace

#### Automatic Operations

By default, the extension will:
- Automatically decrypt encrypted files when you open them
- Automatically encrypt plaintext markers when you save files

You can toggle these behaviors in settings or with the command:
- **SSS: Toggle Auto-Seal on Save**

### Managing Users

1. **Add User**:
   - Command Palette > SSS: Add User to Project
   - Enter username and public key

2. **Remove User**:
   - Command Palette > SSS: Remove User from Project
   - Select user from list

3. **List Users**:
   - Command Palette > SSS: List Project Users

### Managing Keys

1. **Generate Key**:
   - Command Palette > SSS: Generate New Keypair
   - Choose password protection option

2. **List Keys**:
   - Command Palette > SSS: List Keypairs

3. **Set Current Key**:
   - Command Palette > SSS: Set Current Keypair
   - Select from available keys

4. **Show Public Key**:
   - Command Palette > SSS: Show Public Key
   - Optionally copy to clipboard

### Git Integration

Install Git hooks to automatically seal files before committing:
- Command Palette > SSS: Install Git Hooks

## Configuration

Access settings via: File > Preferences > Settings > Extensions > SSS

### Available Settings

- `sss.autoSealOnSave` (default: `true`)
  - Automatically seal (encrypt) files when saving

- `sss.autoOpenOnLoad` (default: `true`)
  - Automatically open (decrypt) files when loading in editor

- `sss.showStatusBar` (default: `true`)
  - Show SSS status in status bar

- `sss.warnBeforeCommit` (default: `true`)
  - Warn if attempting to commit unsealed files

- `sss.highlightMarkers` (default: `true`)
  - Highlight SSS markers in editor

- `sss.sssPath` (default: `"sss"`)
  - Path to SSS binary (defaults to 'sss' in PATH)

- `sss.verboseLogging` (default: `false`)
  - Enable verbose logging for debugging

## Status Bar

When in an SSS project, the status bar shows:
- Lock icon (🔒) for encrypted files
- Unlock icon (🔓) for files with plaintext markers
- Current key UUID (first 8 characters)

Click the status bar item to view project information.

## SSS Markers

The extension recognizes these SSS markers:

- `⊕{plaintext}` - Plaintext marker (will be encrypted)
- `o+{plaintext}` - Alternative plaintext marker
- `<{plaintext}` - Left-angle marker
- `⊲{plaintext}` - Triangle marker (preserved as-is)
- `⊠{ciphertext}` - Encrypted marker (result of sealing)

## Workflow Example

1. Create a file with secrets:
   ```
   API_KEY=⊕{my-secret-key}
   DB_PASSWORD=⊕{super-secret-password}
   ```

2. Save the file (auto-seal encrypts it):
   ```
   API_KEY=⊠{oD5Ouv4S18BCXetqWgl2ZFlyN2P0DcOAbRca...}
   DB_PASSWORD=⊠{kL3Pmw6T29CDYfurXhm3AGmzO3Q1EdPBcSdb...}
   ```

3. Commit the file (encrypted markers are safe in Git)

4. Open the file later (auto-open decrypts it):
   ```
   API_KEY=⊕{my-secret-key}
   DB_PASSWORD=⊕{super-secret-password}
   ```

## Troubleshooting

### Extension not working

1. Check that SSS is installed: `sss --version`
2. Check the extension output: View > Output > SSS
3. Enable verbose logging in settings
4. Verify you're in an SSS project: `sss status`

### Auto-seal/open not working

1. Check settings are enabled
2. Verify file contains SSS markers
3. Check output panel for errors
4. Try manual seal/open to see error messages

### Commands not visible

1. Verify you're in an SSS project (`.sss.toml` exists)
2. Reload VS Code window
3. Check that workspace folder is open

## Development

### Building

```bash
npm install
npm run compile
```

### Testing

```bash
npm run test
```

### Packaging

```bash
npm run package
```

This creates a `.vsix` file that can be distributed and installed.

## Contributing

Please report issues and feature requests on the project repository.

## License

See LICENSE file for details.

## Related Links

- [SSS Tool Documentation](https://github.com/dspearson/sss)
- [VS Code Extension API](https://code.visualstudio.com/api)
