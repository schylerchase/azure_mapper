/**
 * Pure utility functions extracted from main.js for testability.
 * No Electron dependencies -- all functions are side-effect-free.
 */

'use strict';

const path = require('path');

// Allows: alphanumeric, hyphens, underscores, dots, spaces (not newlines), slashes, parentheses
// Blocks: semicolons, backticks, pipes, $, &, |, newlines, and other shell metacharacters
const SAFE_INPUT = /^[a-zA-Z0-9\-_. /()]+$/;
const MAX_IPC_TEXT_BYTES = 50 * 1024 * 1024;

/**
 * Validates a user-supplied string is safe for use in shell arguments.
 * @param {string} str - Input string to validate
 * @returns {boolean} true if safe, false otherwise
 */
function validateInput(str) {
    if (typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (trimmed.length === 0 || trimmed.length > 256) return false;
    return SAFE_INPUT.test(trimmed);
}

function validateTextPayload(value, label = 'payload', maxBytes = MAX_IPC_TEXT_BYTES) {
    if (typeof value !== 'string') {
        throw new Error(`Invalid ${label}: expected string`);
    }
    if (Buffer.byteLength(value, 'utf8') > maxBytes) {
        throw new Error(`Invalid ${label}: exceeds ${(maxBytes / 1024 / 1024).toFixed(0)} MB limit`);
    }
    return value;
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
    const safeSubscription = subscription.trim();
    if (!validateInput(safeSubscription)) {
        throw new Error('Invalid subscription: contains unsafe characters');
    }
    const args = [scriptPath, '-s', safeSubscription];
    if (resourceGroup) {
        const safeResourceGroup = resourceGroup.trim();
        if (!validateInput(safeResourceGroup)) {
            throw new Error('Invalid resource group: contains unsafe characters');
        }
        args.push('-g', safeResourceGroup);
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

function resolveOutputDir(baseDir, outputDir) {
    if (!outputDir || typeof outputDir !== 'string') {
        throw new Error('Output directory was not reported by scan script');
    }
    if (path.isAbsolute(outputDir)) {
        throw new Error('Invalid output directory: absolute paths are not allowed');
    }
    const resolvedBase = path.resolve(baseDir);
    const resolvedOutput = path.resolve(resolvedBase, outputDir);
    const prefix = resolvedBase.endsWith(path.sep) ? resolvedBase : resolvedBase + path.sep;
    if (resolvedOutput !== resolvedBase && !resolvedOutput.startsWith(prefix)) {
        throw new Error('Invalid output directory: traversal detected');
    }
    return resolvedOutput;
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
    MAX_IPC_TEXT_BYTES,
    validateInput,
    validateTextPayload,
    buildScanArgs,
    parseOutputDir,
    resolveOutputDir,
    mapFolderFiles
};
