/**
 * Shared types for command modules
 */

export interface TreeViewProviders {
    project: { refresh(): void };
    users: { refresh(): void };
    keys: { refresh(): void };
    actions: { refresh(): void };
}
