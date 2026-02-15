/**
 * Pure utility functions extracted from main.js for testability.
 * No Electron dependencies -- all functions are side-effect-free.
 */

'use strict';

// Allows: alphanumeric, hyphens, underscores, dots, spaces (not newlines), slashes, parentheses
// Blocks: semicolons, backticks, pipes, $, &, |, newlines, and other shell metacharacters
const SAFE_INPUT = /^[a-zA-Z0-9\-_. /()]+$/;

/**
 * Validates a user-supplied string is safe for use in shell arguments.
 * @param {string} str - Input string to validate
 * @returns {boolean} true if safe, false otherwise
 */
function validateInput(str) {
    if (typeof str !== 'string' || str.length === 0 || str.length > 256) return false;
    return SAFE_INPUT.test(str);
}

/**
 * Builds the argument array for spawning the export-azure-data.sh script.
 * @param {string} scriptPath - Absolute path to export-azure-data.sh
 * @param {string} subscription - Azure subscription name or ID
 * @param {string} [resourceGroup] - Optional resource group filter
 * @returns {string[]} Arguments array for spawn()
 * @throws {Error} If subscription or resourceGroup contain unsafe characters
 */
function buildScanArgs(scriptPath, subscription, resourceGroup) {
    if (!subscription || typeof subscription !== 'string') {
        throw new Error('Subscription is required');
    }
    if (!validateInput(subscription)) {
        throw new Error('Invalid subscription: contains unsafe characters');
    }
    const args = [scriptPath, '-s', subscription];
    if (resourceGroup) {
        if (!validateInput(resourceGroup)) {
            throw new Error('Invalid resource group: contains unsafe characters');
        }
        args.push('-g', resourceGroup);
    }
    return args;
}

/**
 * Parses the output directory path from scan script stdout.
 * The export script prints progress lines, with guidance for loading
 * the data on the last line. The output directory is on the line before.
 * Format: "To load: Use 'Upload JSON Files' ... from <dir>/"
 * We look for the "Output directory: <path>" line instead for reliability.
 * @param {string} stdout - Raw stdout from the scan process
 * @returns {string|null} Directory path, or null if not found
 */
function parseOutputDir(stdout) {
    if (!stdout || typeof stdout !== 'string') return null;
    const lines = stdout.split('\n');
    // Look for the "Output directory:" line first (most reliable)
    for (const line of lines) {
        const match = line.match(/^Output directory:\s*(.+)$/);
        if (match) return match[1].trim();
    }
    // Fallback: last non-empty line (original behavior)
    for (let i = lines.length - 1; i >= 0; i--) {
        const trimmed = lines[i].trim();
        if (trimmed.length > 0) return trimmed;
    }
    return null;
}

/**
 * Maps a folder's JSON files to a {basename: content} object.
 * @param {string[]} fileList - Array of filenames in the folder
 * @param {function} readFileFn - Function(filename) => string content
 * @returns {Object} Map of basename (without .json) to file content
 */
function mapFolderFiles(fileList, readFileFn) {
    const data = {};
    if (!Array.isArray(fileList)) return data;
    const jsonFiles = fileList.filter(f => f.endsWith('.json'));
    for (const file of jsonFiles) {
        const key = file.replace(/\.json$/, '');
        data[key] = readFileFn(file);
    }
    return data;
}

module.exports = {
    SAFE_INPUT,
    validateInput,
    buildScanArgs,
    parseOutputDir,
    mapFolderFiles
};
