/**
 * Centralized constants for the SSS VS Code extension
 *
 * This file consolidates all hard-coded values to:
 * - Improve maintainability (single source of truth)
 * - Enhance readability (self-documenting constant names)
 * - Reduce duplication (DRY principle)
 * - Simplify testing (easy to mock/override)
 */

/**
 * SSS marker characters used for encryption state indication
 */
export const MARKERS = {
    /** Plaintext marker: ⊕{secret_key} */
    PLAINTEXT: '⊕',
    /** Encrypted marker: ⊠{encrypted_data} */
    ENCRYPTED: '⊠',
    /** Interpolation marker: ⊲{secret_key} or <{secret_key} */
    INTERPOLATION: '⊲',
    /** Alternative interpolation marker */
    INTERPOLATION_ALT: '<',
    /** ASCII plaintext marker */
    PLAINTEXT_ASCII: 'o+',
} as const;

/**
 * Common regex patterns for SSS marker detection
 */
export const PATTERNS = {
    /** Matches ALL SSS markers: ⊕{...}, ⊠{...}, ⊲{...}, o+{...}, <{...} */
    ALL_MARKERS: /[⊕⊠]\{[^}]*\}|o\+\{[^}]*\}|<\{[^}]*\}|⊲\{[^}]*\}/g,
    /** Matches both encrypted and plaintext markers: [⊕⊠]{...} */
    ANY_MARKER: /[⊕⊠]\{[^}]*\}/g,
    /** Matches only encrypted markers: ⊠{...} */
    ENCRYPTED_MARKER: /⊠\{[^}]*\}/g,
    /** Matches only plaintext markers: ⊕{...} */
    PLAINTEXT_MARKER: /⊕\{[^}]*\}/g,
    /** Matches plaintext markers (both Unicode and ASCII): ⊕{...} or o+{...} */
    ANY_PLAINTEXT_MARKER: /[⊕]\{[^}]*\}|o\+\{[^}]*\}/g,
    /** Matches only interpolation markers: ⊲{...} */
    INTERPOLATION_MARKER: /⊲\{[^}]*\}/g,
    /** Matches both interpolation markers: ⊲{...} or <{...} */
    ANY_INTERPOLATION_MARKER: /[⊲<]\{[^}]+\}/g,
    /** Matches ASCII plaintext marker: o+{...} */
    ASCII_PLAINTEXT_MARKER: /o\+\{[^}]*\}/g,
    /** Matches ASCII interpolation marker: <{...} */
    ASCII_INTERPOLATION_MARKER: /<\{[^}]*\}/g,
} as const;

/**
 * Marker opening sequences (used for string replacement/detection)
 */
export const MARKER_SEQUENCES = {
    PLAINTEXT_OPEN: '⊕{',
    ENCRYPTED_OPEN: '⊠{',
    INTERPOLATION_OPEN: '⊲{',
    INTERPOLATION_ALT_OPEN: '<{',
    ASCII_PLAINTEXT_OPEN: 'o+{',
} as const;

/**
 * Display truncation lengths for UI elements
 */
export const DISPLAY = {
    /** UUID truncation length for tree views */
    UUID_LENGTH: 8,
    /** Public key truncation length for tree views */
    PUBLIC_KEY_LENGTH: 16,
    /** Maximum secret value length to display */
    SECRET_MAX_LENGTH: 500,
} as const;

/**
 * Timeout and retry configuration
 */
export const TIMEOUTS = {
    /** Git status cache timeout in milliseconds */
    GIT_CACHE: 5000,
    /** Binary download timeout in milliseconds (10 minutes) */
    DOWNLOAD: 600000,
} as const;

/**
 * Retry configuration
 */
export const RETRIES = {
    /** Maximum authentication retry attempts */
    AUTH_MAX: 3,
} as const;

/**
 * Decoration colors for SSS markers in editor
 */
export const DECORATION_COLORS = {
    PLAINTEXT: {
        /** Background color for plaintext markers */
        BACKGROUND: 'rgba(40, 180, 80, 0.08)',
        /** Border color for plaintext markers */
        BORDER: 'rgba(40, 180, 80, 0.25)',
    },
    ENCRYPTED: {
        /** Background color for encrypted markers */
        BACKGROUND: 'rgba(100, 150, 230, 0.08)',
        /** Border color for encrypted markers */
        BORDER: 'rgba(100, 150, 230, 0.25)',
    },
    INTERPOLATION: {
        /** Background color for interpolation markers */
        BACKGROUND: 'rgba(180, 120, 200, 0.08)',
        /** Border color for interpolation markers */
        BORDER: 'rgba(180, 120, 200, 0.25)',
    },
} as const;

/**
 * Border style configuration for decorations
 */
export const DECORATION_BORDER = {
    WIDTH: '1px',
    STYLE: 'solid',
    RADIUS: '2px',
} as const;

/**
 * Binary download configuration
 */
export const BINARY = {
    /** Base URL for SSS binary downloads */
    DOWNLOAD_URL: 'https://technoanimal.net/sss',
    /** Version file name */
    VERSION_FILE: 'version.txt',
} as const;

/**
 * Default file names
 */
export const FILES = {
    /** Default secrets file name */
    SECRETS: 'secrets',
    /** Alternative secrets file name */
    SECRETS_ALT: '.secrets',
    /** SSS project configuration file */
    PROJECT_CONFIG: '.sss.toml',
} as const;

/**
 * Git integration configuration
 */
export const GIT = {
    /** Enable/disable git status checking */
    STATUS_CHECK_ENABLED: true,
} as const;

/**
 * Language IDs
 */
export const LANGUAGES = {
    /** Language ID for secrets files */
    SECRETS: 'sss-secrets',
} as const;

/**
 * URI schemes
 */
export const URI_SCHEMES = {
    /** File system scheme */
    FILE: 'file',
    /** SSS virtual file system scheme */
    SSS_FS: 'sss-fs',
    /** SSS render scheme */
    SSS_RENDER: 'sss-render',
} as const;

/**
 * Tree view IDs
 */
export const TREE_VIEWS = {
    PROJECT: 'sss.projectView',
    USERS: 'sss.usersView',
    KEYS: 'sss.keysView',
    ACTIONS: 'sss.actionsView',
} as const;

/**
 * Context keys
 */
export const CONTEXT_KEYS = {
    IS_PROJECT: 'sss.isProject',
} as const;

/**
 * Configuration section
 */
export const CONFIG_SECTION = 'secrets';

/**
 * Configuration keys
 */
export const CONFIG_KEYS = {
    HIGHLIGHT_MARKERS: 'highlightMarkers',
    AUTO_SEAL_ON_SAVE: 'autoSealOnSave',
    AUTO_OPEN_ON_OPEN: 'autoOpenOnOpen',
    GIT_HOOKS_ENABLED: 'gitHooksEnabled',
} as const;

/**
 * User messages
 */
export const MESSAGES = {
    /** Warning when deleting .sss.toml */
    DELETE_SSS_TOML_WARNING: 'You are about to delete .sss.toml which will disable encryption for this project. Are you sure?',
    /** Authentication failed message */
    AUTH_FAILED: 'Failed to authenticate',
    /** No workspace folder message */
    NO_WORKSPACE: 'No workspace folder open',
    /** Binary download failed message */
    BINARY_DOWNLOAD_FAILED: 'Failed to download sss binary',
} as const;

/**
 * Button labels
 */
export const BUTTONS = {
    DELETE: 'Delete',
    CANCEL: 'Cancel',
    RETRY: 'Retry',
    USE_FILE_SCHEME: 'Use file:// (no encryption)',
    OK: 'OK',
} as const;

/**
 * Output channel name
 */
export const OUTPUT_CHANNEL_NAME = 'Secret String Substitution';

/**
 * Progress locations
 */
export const PROGRESS = {
    TITLE: 'Secret String Substitution',
    CHECKING_AUTH: 'Checking authentication...',
    AUTH_SUCCESS: 'Authentication successful',
} as const;
