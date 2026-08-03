/**
 * PixelCrypt v2 — Secure Steganography Portal
 *
 * Custom encrypted steganography format with PRNG-scattered LSB embedding.
 * Every payload is AES-256-GCM encrypted and embedded at pseudo-random pixel
 * positions derived from the credential, making generic LSB extraction tools
 * useless without the correct password or key.
 *
 * Architecture:
 *   1. PRNG Engine        — SFC32 seeded from SHA-256(credential)
 *   2. Pixel Randomizer   — Incremental Fisher-Yates index generator
 *   3. Crypto Engine      — AES-256-GCM encrypt/decrypt via Web Crypto API
 *   4. Key Derivation     — PBKDF2 (password mode) or raw import (key mode)
 *   5. Payload Protocol   — Custom binary format (no plaintext headers)
 *   6. LSB Engine         — Bit scatter/gather at PRNG-derived positions
 *   7. UI Module          — Event handlers, overlays, toasts, sandbox
 */

// ========================================
// Constants
// ========================================
const PROTOCOL_VERSION  = 0x02;          // PixelCrypt v2
const MODE_RAW_KEY      = 0x00;          // Auto-generated 256-bit key
const MODE_PASSWORD     = 0x01;          // Password → PBKDF2 → AES key
const PBKDF2_ITERATIONS = 100000;        // OWASP-recommended minimum
const SALT_LENGTH       = 16;            // 128-bit random salt
const IV_LENGTH         = 12;            // 96-bit IV for AES-GCM
const AES_KEY_BITS      = 256;
const AES_KEY_BYTES     = 32;
const GCM_TAG_BYTES     = 16;            // Auth tag appended by Web Crypto
const MAX_MESSAGE_CHARS = 10240;         // UI character limit

// Payload overhead (header bytes excluding ciphertext):
//   Password mode: version(1) + mode(1) + salt(16) + iv(12) + len(4) = 34
//   Key mode:      version(1) + mode(1) + iv(12) + len(4)            = 18
// Plus GCM tag (16) is part of ciphertext, so effective overhead:
const OVERHEAD_PASSWORD = 34 + GCM_TAG_BYTES; // 50 bytes
const OVERHEAD_KEY      = 18 + GCM_TAG_BYTES; // 34 bytes


// ========================================
// DOM Elements
// ========================================
const elements = {
    // Navigation
    tabBtns:           document.querySelectorAll('.tab-btn'),
    tabContents:       document.querySelectorAll('.tab-content'),

    // Encode — Image
    encodeDropZone:    document.getElementById('encode-drop-zone'),
    encodeFileInput:   document.getElementById('encode-file-input'),
    encodeFileInfo:    document.getElementById('encode-file-info'),
    encodeThumb:       document.getElementById('encode-thumb'),
    encodeFilename:    document.getElementById('encode-filename'),
    encodeFilesize:    document.getElementById('encode-filesize'),
    encodeClear:       document.getElementById('encode-clear'),
    capacityMeter:     document.getElementById('capacity-meter'),
    capacityText:      document.getElementById('capacity-text'),
    capacityFill:      document.getElementById('capacity-fill'),

    // Encode — Payload
    messageInput:      document.getElementById('message-input'),
    charCount:         document.getElementById('char-count'),
    bundleHintInput:   document.getElementById('bundle-hint-input'),
    encodePassword:    document.getElementById('encode-password'),
    toggleEncodePassword: document.getElementById('toggle-encode-password'),
    encodeBtn:         document.getElementById('encode-btn'),

    // Encode — Progress & Result
    encodeProgress:    document.getElementById('encode-progress'),
    encodeProgressFill: document.getElementById('encode-progress-fill'),
    encodeProgressText: document.getElementById('encode-progress-text'),
    encodeResult:      document.getElementById('encode-result'),
    originalThumb:     document.getElementById('original-thumb'),
    resultThumb:       document.getElementById('result-thumb'),
    differenceThumb:   document.getElementById('difference-thumb'),
    downloadBtn:       document.getElementById('download-btn'),
    downloadBundleBtn: document.getElementById('download-bundle-btn'),
    copyResultBtn:     document.getElementById('copy-result-btn'),
    bundleChecksumShort: document.getElementById('bundle-checksum-short'),
    bundleSize:        document.getElementById('bundle-size'),

    // Encode — Generated Key
    generatedKeyCard:  document.getElementById('generated-key-card'),
    generatedKeyCode:  document.getElementById('generated-key-code'),
    copyKeyBtn:        document.getElementById('copy-key-btn'),
    downloadKeyBtn:    document.getElementById('download-key-btn'),

    // Decode
    decodeDropZone:    document.getElementById('decode-drop-zone'),
    decodeFileInput:   document.getElementById('decode-file-input'),
    decodeFileInfo:    document.getElementById('decode-file-info'),
    decodeThumb:       document.getElementById('decode-thumb'),
    decodeFilename:    document.getElementById('decode-filename'),
    decodeFilesize:    document.getElementById('decode-filesize'),
    decodeClear:       document.getElementById('decode-clear'),
    decodePasswordField: document.getElementById('decode-password-field'),
    decodePassword:    document.getElementById('decode-password'),
    toggleDecodePassword: document.getElementById('toggle-decode-password'),
    decodeBtn:         document.getElementById('decode-btn'),
    decodeProgress:    document.getElementById('decode-progress'),
    decodeProgressFill: document.getElementById('decode-progress-fill'),
    decodeProgressText: document.getElementById('decode-progress-text'),
    decodeResult:      document.getElementById('decode-result'),
    extractedText:     document.getElementById('extracted-text'),
    copyExtractedBtn:  document.getElementById('copy-extracted-btn'),
    decodeError:       document.getElementById('decode-error'),
    decodeErrorMsg:    document.getElementById('decode-error-msg'),
    decodeRetryBtn:    document.getElementById('decode-retry-btn'),

    // Close buttons
    encodeProgressClose: document.getElementById('encode-progress-close'),
    encodeResultClose:   document.getElementById('encode-result-close'),
    decodeProgressClose: document.getElementById('decode-progress-close'),
    decodeResultClose:   document.getElementById('decode-result-close'),

    // Toast
    toast: document.getElementById('toast')
};


// ========================================
// State
// ========================================
let encodeImageData      = null;
let encodeImageWidth     = 0;
let encodeImageHeight    = 0;
let encodeOriginalDataURL = '';
let encodeSourceFileName = 'image.png';
let decodeImageData      = null;
let resultCanvas         = null;
let latestShareBundle    = null;
let lastGeneratedKey     = '';  // Formatted key string for copy/download


// ========================================
// 1. PRNG Engine — SFC32 (Simple Fast Counter)
// ========================================
// Seeded with 4 × 32-bit values from SHA-256(credential).
// Produces uniformly distributed 32-bit unsigned integers.

/**
 * Create a deterministic PRNG from a 32-byte seed (SHA-256 output).
 * Uses the SFC32 algorithm for speed and quality.
 * @param {Uint8Array} seedBytes — exactly 32 bytes
 * @returns {Function} — returns a float in [0, 1) on each call
 */
function createPRNG(seedBytes) {
    const view = new DataView(seedBytes.buffer, seedBytes.byteOffset, seedBytes.byteLength);
    let a = view.getUint32(0,  true);
    let b = view.getUint32(4,  true);
    let c = view.getUint32(8,  true);
    let d = view.getUint32(12, true);

    return function () {
        a |= 0; b |= 0; c |= 0; d |= 0;
        const t = (a + b | 0) + d | 0;
        d = (d + 1) | 0;
        a = b ^ (b >>> 9);
        b = (c + (c << 3)) | 0;
        c = (c << 21) | (c >>> 11);
        c = (c + t) | 0;
        return (t >>> 0) / 4294967296;
    };
}


// ========================================
// 2. Pixel Randomizer — Incremental Fisher-Yates
// ========================================
// Generates unique pseudo-random pixel-channel indices on demand without
// allocating an array for every pixel in the image. Uses a sparse swap-map
// to track the partial Fisher-Yates permutation state.

/**
 * Create an incremental index generator that yields unique slot indices
 * in pseudo-random order determined by the PRNG.
 *
 * A "slot" maps to one colour channel of one pixel:
 *   slotIndex 0 → pixel 0 Red, 1 → pixel 0 Green, 2 → pixel 0 Blue,
 *   3 → pixel 1 Red, etc.  Alpha channels are never used.
 *
 * @param {Function} prng       — seeded PRNG returning [0, 1)
 * @param {number}   totalSlots — width × height × 3
 * @returns {{ next(): number, nextN(n: number): number[] }}
 */
function createIndexGenerator(prng, totalSlots) {
    const swaps = new Map();
    let cursor  = 0;

    return {
        /** Return the next unique pseudo-random slot index. */
        next() {
            if (cursor >= totalSlots) {
                throw new Error('Exceeded available pixel slots');
            }
            // Pick a random position in the remaining un-shuffled range
            const j  = cursor + Math.floor(prng() * (totalSlots - cursor));
            const vi = swaps.has(cursor) ? swaps.get(cursor) : cursor;
            const vj = swaps.has(j)      ? swaps.get(j)      : j;

            // Swap
            swaps.set(cursor, vj);
            swaps.set(j,      vi);

            // Clean up entries we'll never revisit to save memory
            // (cursor will never be accessed again)
            cursor++;
            return vj;
        },

        /** Return an array of the next `count` unique indices. */
        nextN(count) {
            const out = new Array(count);
            for (let i = 0; i < count; i++) {
                out[i] = this.next();
            }
            return out;
        }
    };
}

/**
 * Convert a slot index to the corresponding imageData.data array offset.
 * Slots skip the alpha channel: slot 0 → data[0] (R), slot 2 → data[2] (B),
 * slot 3 → data[4] (next pixel R), etc.
 */
function slotToDataIndex(slot) {
    const pixel   = Math.floor(slot / 3);
    const channel = slot % 3;
    return pixel * 4 + channel;
}


// ========================================
// 3. Crypto Engine — AES-256-GCM
// ========================================

/**
 * Derive the 32-byte PRNG seed from a credential (password bytes or raw key).
 * @param {Uint8Array|ArrayBuffer} credential
 * @returns {Promise<Uint8Array>}
 */
async function derivePRNGSeed(credential) {
    const hash = await crypto.subtle.digest('SHA-256', credential);
    return new Uint8Array(hash);
}

/**
 * Generate a cryptographically secure random 256-bit key.
 * @returns {Uint8Array} — 32 random bytes
 */
function generateRandomKey() {
    return crypto.getRandomValues(new Uint8Array(AES_KEY_BYTES));
}

/**
 * Format raw key bytes as a dash-separated uppercase hex string.
 * Example: "D4A9-7F22-8BC1-…"
 * @param {Uint8Array} keyBytes
 * @returns {string}
 */
function formatKeyForDisplay(keyBytes) {
    const hex = Array.from(keyBytes)
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join('');
    return hex.match(/.{1,4}/g).join('-');
}

/**
 * Parse a displayed hex key back to raw bytes.
 * Accepts with or without dashes/spaces, case-insensitive.
 * @param {string} keyString
 * @returns {Uint8Array|null} — null if invalid
 */
function parseHexKey(keyString) {
    const hex = keyString.replace(/[\s\-]/g, '');
    if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Heuristic: does the input look like a formatted 256-bit hex key?
 * A key contains dashes and, when cleaned, is exactly 64 hex chars.
 * @param {string} input
 * @returns {boolean}
 */
function looksLikeHexKey(input) {
    const cleaned = input.replace(/[\s\-]/g, '');
    return cleaned.length === 64 && /^[0-9a-fA-F]+$/.test(cleaned);
}


// ========================================
// 4. Key Derivation
// ========================================

/**
 * Derive an AES-256-GCM CryptoKey from a password via PBKDF2.
 * @param {string}     password
 * @param {Uint8Array} salt — 16 random bytes
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromPassword(password, salt) {
    const encoder     = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name:       'PBKDF2',
            salt:       salt,
            iterations: PBKDF2_ITERATIONS,
            hash:       'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Import raw 256-bit key bytes as a CryptoKey for AES-GCM.
 * @param {Uint8Array} keyBytes — 32 bytes
 * @returns {Promise<CryptoKey>}
 */
async function importRawKey(keyBytes) {
    return crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
        ['encrypt', 'decrypt']
    );
}


// ========================================
// 5. Payload Protocol — Custom Binary Format
// ========================================
//
// The payload contains NO plaintext magic strings.  Its structure:
//
//   ┌──────────┬──────┬────────────┬─────────┬────────────────┬─────────────────────┐
//   │ Version  │ Mode │ Salt       │ IV      │ Ciphertext Len │ Ciphertext + Tag    │
//   │ (1 byte) │(1 B) │(16 B if    │ (12 B)  │ (4 B, big-end) │ (variable)          │
//   │  0x02    │      │ mode=0x01) │         │                │                     │
//   └──────────┴──────┴────────────┴─────────┴────────────────┴─────────────────────┘
//
// Mode 0x00 = raw-key   (no salt field)
// Mode 0x01 = password  (salt present)
//
// With a wrong credential the PRNG produces wrong indices, so the extracted
// bytes are random noise.  Even if by chance the version/mode bytes match,
// AES-GCM decryption will fail due to authentication tag mismatch.

/**
 * Assemble the binary payload from its components.
 * @param {number}     mode             — MODE_RAW_KEY or MODE_PASSWORD
 * @param {Uint8Array|null} salt        — 16 bytes (password mode) or null
 * @param {Uint8Array} iv               — 12 bytes
 * @param {Uint8Array} ciphertextAndTag — AES-GCM output (ciphertext + 16-byte tag)
 * @returns {Uint8Array}
 */
function assemblePayload(mode, salt, iv, ciphertextAndTag) {
    // Calculate total size
    let headerSize = 1 + 1 + IV_LENGTH + 4; // version + mode + iv + length
    if (mode === MODE_PASSWORD) headerSize += SALT_LENGTH;
    const total = headerSize + ciphertextAndTag.length;

    const payload = new Uint8Array(total);
    let off = 0;

    // Version
    payload[off++] = PROTOCOL_VERSION;

    // Mode
    payload[off++] = mode;

    // Salt (password mode only)
    if (mode === MODE_PASSWORD) {
        payload.set(salt, off);
        off += SALT_LENGTH;
    }

    // IV
    payload.set(iv, off);
    off += IV_LENGTH;

    // Ciphertext length — 4 bytes big-endian
    const len = ciphertextAndTag.length;
    payload[off++] = (len >>> 24) & 0xFF;
    payload[off++] = (len >>> 16) & 0xFF;
    payload[off++] = (len >>>  8) & 0xFF;
    payload[off++] =  len         & 0xFF;

    // Ciphertext + authentication tag
    payload.set(ciphertextAndTag, off);

    return payload;
}


// ========================================
// 6. LSB Engine — Scatter / Gather
// ========================================

/**
 * Convert a Uint8Array of bytes to an array of individual bits (MSB first).
 */
function bytesToBits(bytes) {
    const bits = new Uint8Array(bytes.length * 8);
    for (let i = 0; i < bytes.length; i++) {
        for (let j = 0; j < 8; j++) {
            bits[i * 8 + j] = (bytes[i] >>> (7 - j)) & 1;
        }
    }
    return bits;
}

/**
 * Convert an array of individual bits back to a Uint8Array of bytes.
 */
function bitsToBytes(bits) {
    const len   = Math.ceil(bits.length / 8);
    const bytes = new Uint8Array(len);
    for (let i = 0; i < bits.length; i++) {
        if (bits[i]) {
            bytes[i >>> 3] |= (1 << (7 - (i & 7)));
        }
    }
    return bytes;
}

/**
 * Embed individual bits into the image at the given slot indices.
 * Modifies imageData.data in place.
 */
function embedBits(imageData, bitArray, indices) {
    const data = imageData.data;
    for (let i = 0; i < bitArray.length; i++) {
        const idx = slotToDataIndex(indices[i]);
        data[idx] = (data[idx] & 0xFE) | bitArray[i];
    }
}

/**
 * Extract bits from the image using the index generator.
 * @param {ImageData}  imageData
 * @param {object}     indexGen — created by createIndexGenerator
 * @param {number}     count   — number of bits to extract
 * @returns {Uint8Array} — array of individual bit values (0 or 1)
 */
function extractBits(imageData, indexGen, count) {
    const data = imageData.data;
    const bits = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
        const slot = indexGen.next();
        const idx  = slotToDataIndex(slot);
        bits[i]    = data[idx] & 1;
    }
    return bits;
}


// ========================================
// Utility Functions
// ========================================
function showToast(message, duration = 3000) {
    const toast     = elements.toast;
    const messageEl = toast.querySelector('.toast-message');

    toast.classList.remove('show');
    setTimeout(() => {
        messageEl.textContent = message;
        toast.classList.add('show');
    }, 50);

    clearTimeout(toast.timeout);
    toast.timeout = setTimeout(() => {
        toast.classList.remove('show');
    }, duration);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/**
 * Calculate embedding capacity in bytes.
 * Uses pessimistic overhead (password mode = 50 bytes).
 */
function calculateCapacity(width, height) {
    const totalBits  = width * height * 3;
    const totalBytes = Math.floor(totalBits / 8);
    const maxMessage = totalBytes - OVERHEAD_PASSWORD;
    return Math.max(0, maxMessage);
}

function updateCapacityMeter() {
    if (!encodeImageData) return;

    const capacity   = calculateCapacity(encodeImageWidth, encodeImageHeight);
    const msgLen     = new TextEncoder().encode(elements.messageInput.value).length;
    const percentage = capacity > 0 ? (msgLen / capacity) * 100 : 0;

    elements.capacityText.textContent =
        `${(msgLen / 1024).toFixed(2)} / ${(capacity / 1024).toFixed(2)} KB`;
    elements.capacityFill.style.width = Math.min(percentage, 100) + '%';

    elements.capacityFill.classList.remove('warning', 'danger');
    if (percentage > 80) elements.capacityFill.classList.add('warning');
    if (percentage > 95) elements.capacityFill.classList.add('danger');
}


// ========================================
// File Handling
// ========================================
function loadImage(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement('canvas');
                canvas.width  = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                resolve({
                    image:   img,
                    canvas:  canvas,
                    ctx:     ctx,
                    data:    ctx.getImageData(0, 0, img.width, img.height),
                    width:   img.width,
                    height:  img.height,
                    dataURL: e.target.result
                });
            };
            img.onerror = () => reject(new Error('Failed to load image'));
            img.src = e.target.result;
        };
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsDataURL(file);
    });
}

function sanitizeFileBase(name) {
    return (name || 'image')
        .replace(/\.[^/.]+$/, '')
        .replace(/[^a-z0-9_-]+/gi, '-')
        .replace(/^-+|-+$/g, '')
        .toLowerCase() || 'image';
}

function dataUrlToBytes(dataUrl) {
    const base64 = dataUrl.split(',')[1] || '';
    const binary = atob(base64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(digest);
}


// ========================================
// Difference Map
// ========================================
function makeDifferenceCanvas(originalData, encodedData) {
    const diffCanvas = document.createElement('canvas');
    diffCanvas.width  = originalData.width;
    diffCanvas.height = originalData.height;

    const diffCtx  = diffCanvas.getContext('2d');
    const diffData = diffCtx.createImageData(originalData.width, originalData.height);
    const orig     = originalData.data;
    const enc      = encodedData.data;
    const out      = diffData.data;

    for (let i = 0; i < orig.length; i += 4) {
        const dr = Math.abs(enc[i]     - orig[i]);
        const dg = Math.abs(enc[i + 1] - orig[i + 1]);
        const db = Math.abs(enc[i + 2] - orig[i + 2]);
        const changed = dr || dg || db;

        out[i]     = dr ? 255 : 3;
        out[i + 1] = dg ? 255 : 8;
        out[i + 2] = db ? 255 : 18;
        out[i + 3] = changed ? 255 : 255;
    }

    diffCtx.putImageData(diffData, 0, 0);
    return diffCanvas;
}


// ========================================
// ZIP Builder (pure JS, no dependencies)
// ========================================
function makeCrcTable() {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c >>> 0;
    }
    return table;
}

const CRC_TABLE = makeCrcTable();

function crc32(bytes) {
    let crc = 0xFFFFFFFF;
    for (const byte of bytes) {
        crc = CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function getDosDateTime(date = new Date()) {
    const time    = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
    const dosDate = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { time, date: dosDate };
}

function createZip(files) {
    const encoder  = new TextEncoder();
    const prepared = files.map(f => ({
        ...f,
        nameBytes: encoder.encode(f.name),
        crc:       crc32(f.bytes)
    }));

    const localSize   = prepared.reduce((s, f) => s + 30 + f.nameBytes.length + f.bytes.length, 0);
    const centralSize = prepared.reduce((s, f) => s + 46 + f.nameBytes.length, 0);
    const zipBytes    = new Uint8Array(localSize + centralSize + 22);
    const view        = new DataView(zipBytes.buffer);
    const { time, date } = getDosDateTime();
    let offset = 0;
    const centralEntries = [];

    for (const f of prepared) {
        const localOffset = offset;
        view.setUint32(offset, 0x04034b50, true); offset += 4;
        view.setUint16(offset, 10, true);          offset += 2;
        view.setUint16(offset, 0x0800, true);      offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint16(offset, time, true);        offset += 2;
        view.setUint16(offset, date, true);        offset += 2;
        view.setUint32(offset, f.crc, true);       offset += 4;
        view.setUint32(offset, f.bytes.length, true); offset += 4;
        view.setUint32(offset, f.bytes.length, true); offset += 4;
        view.setUint16(offset, f.nameBytes.length, true); offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        zipBytes.set(f.nameBytes, offset);         offset += f.nameBytes.length;
        zipBytes.set(f.bytes, offset);             offset += f.bytes.length;
        centralEntries.push({ ...f, localOffset });
    }

    const centralOffset = offset;
    for (const f of centralEntries) {
        view.setUint32(offset, 0x02014b50, true); offset += 4;
        view.setUint16(offset, 20, true);          offset += 2;
        view.setUint16(offset, 10, true);          offset += 2;
        view.setUint16(offset, 0x0800, true);      offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint16(offset, time, true);        offset += 2;
        view.setUint16(offset, date, true);        offset += 2;
        view.setUint32(offset, f.crc, true);       offset += 4;
        view.setUint32(offset, f.bytes.length, true); offset += 4;
        view.setUint32(offset, f.bytes.length, true); offset += 4;
        view.setUint16(offset, f.nameBytes.length, true); offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint16(offset, 0, true);           offset += 2;
        view.setUint32(offset, 0, true);           offset += 4;
        view.setUint32(offset, f.localOffset, true); offset += 4;
        zipBytes.set(f.nameBytes, offset);         offset += f.nameBytes.length;
    }

    view.setUint32(offset, 0x06054b50, true); offset += 4;
    view.setUint16(offset, 0, true);          offset += 2;
    view.setUint16(offset, 0, true);          offset += 2;
    view.setUint16(offset, prepared.length, true); offset += 2;
    view.setUint16(offset, prepared.length, true); offset += 2;
    view.setUint32(offset, centralSize, true);     offset += 4;
    view.setUint32(offset, centralOffset, true);   offset += 4;
    view.setUint16(offset, 0, true);

    return new Blob([zipBytes], { type: 'application/zip' });
}

function textFile(content) {
    return new TextEncoder().encode(content);
}


// ========================================
// Share Bundle Builder
// ========================================
async function buildShareBundle(encodedCanvas, metadata) {
    const encodedFileName = `encoded_${sanitizeFileBase(metadata.sourceFileName)}.png`;
    const encodedDataUrl  = encodedCanvas.toDataURL('image/png');
    const encodedBytes    = dataUrlToBytes(encodedDataUrl);
    const checksum        = await sha256Hex(encodedBytes);

    const hint = metadata.hint ||
        'Decode the included PNG with PixelCrypt v2. ' +
        'You will need the password or encryption key shared by the sender through a separate secure channel.';

    const instructions = [
        'PixelCrypt v2 Decode Instructions',
        '==================================',
        '',
        `1. Open PixelCrypt v2 and switch to the Decode tab.`,
        `2. Upload ${encodedFileName}.`,
        '3. Enter the password or 256-bit encryption key provided by the sender.',
        '4. Press "Extract Hidden Payload" to reveal the message.',
        '',
        'IMPORTANT: The payload is AES-256-GCM encrypted and embedded using',
        'a pseudo-random pixel scattering algorithm. Generic LSB extraction',
        'tools will NOT work. Only PixelCrypt v2 with the correct credential',
        'can recover the hidden message.',
        '',
        'Integrity Check',
        '---------------',
        `SHA-256: ${checksum}`,
        'Compare this checksum with the included checksum.sha256 file before decoding.'
    ].join('\n');

    const manifest = {
        app:              'PixelCrypt',
        protocolVersion:  2,
        bundleVersion:    1,
        createdAt:        new Date().toISOString(),
        sourceFileName:   metadata.sourceFileName,
        encodedFileName,
        encrypted:        true,       // Always true in v2
        imageSize:        `${metadata.width}x${metadata.height}`,
        payloadCharacters: metadata.messageLength,
        checksumAlgorithm: 'SHA-256',
        checksum,
        hintIncluded:     Boolean(metadata.hint)
    };

    const zipBlob = createZip([
        { name: encodedFileName,           bytes: encodedBytes },
        { name: 'hint-note.txt',           bytes: textFile(hint + '\n') },
        { name: 'checksum.sha256',         bytes: textFile(`${checksum}  ${encodedFileName}\n`) },
        { name: 'decode-instructions.txt', bytes: textFile(instructions + '\n') },
        { name: 'manifest.json',           bytes: textFile(JSON.stringify(manifest, null, 2) + '\n') }
    ]);

    return {
        blob:            zipBlob,
        checksum,
        encodedFileName,
        bundleFileName:  `pixelcrypt_bundle_${sanitizeFileBase(metadata.sourceFileName)}.zip`
    };
}


// ========================================
// Progress Animation
// ========================================
function animateProgress(element, fillElement, textElement, duration = 1500) {
    return new Promise(resolve => {
        let start = null;
        const step = (timestamp) => {
            if (!start) start = timestamp;
            const progress = Math.min((timestamp - start) / duration, 1);

            fillElement.style.width    = (progress * 100) + '%';
            textElement.textContent    = Math.round(progress * 100) + '%';

            if (progress < 1) {
                requestAnimationFrame(step);
            } else {
                resolve();
            }
        };
        requestAnimationFrame(step);
    });
}


// ========================================
// 7. Encode — Main Handler
// ========================================
async function handleEncode() {
    const message = elements.messageInput.value.trim();
    if (!message) {
        showToast('Please enter a message to hide');
        return;
    }
    if (!encodeImageData) {
        showToast('Please upload a source image');
        return;
    }

    const password   = elements.encodePassword.value;
    const bundleHint = elements.bundleHintInput.value.trim();

    // ---------------------------------------------------
    // Determine encryption mode and derive keys
    // ---------------------------------------------------
    let mode, salt, iv, cryptoKey, prngSeedInput;
    let generatedKeyBytes = null;

    if (password) {
        // Password mode: PBKDF2 → AES key
        mode  = MODE_PASSWORD;
        salt  = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        iv    = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        cryptoKey     = await deriveKeyFromPassword(password, salt);
        prngSeedInput = new TextEncoder().encode(password);
    } else {
        // Auto-generated key mode: random 256-bit key → AES key
        mode  = MODE_RAW_KEY;
        salt  = null;
        iv    = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        generatedKeyBytes = generateRandomKey();
        cryptoKey     = await importRawKey(generatedKeyBytes);
        prngSeedInput = generatedKeyBytes;
    }

    // ---------------------------------------------------
    // Encrypt the message with AES-256-GCM
    // ---------------------------------------------------
    const encoder     = new TextEncoder();
    const messageData = encoder.encode(message);
    let ciphertextAndTag;
    try {
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            messageData
        );
        ciphertextAndTag = new Uint8Array(encrypted);
    } catch (e) {
        showToast('Encryption failed');
        return;
    }

    // ---------------------------------------------------
    // Assemble the custom binary payload
    // ---------------------------------------------------
    const payload  = assemblePayload(mode, salt, iv, ciphertextAndTag);
    const bitArray = bytesToBits(payload);

    // ---------------------------------------------------
    // Capacity check
    // ---------------------------------------------------
    const totalSlots = encodeImageWidth * encodeImageHeight * 3;
    if (bitArray.length > totalSlots) {
        showToast(`Message too large. Max: ${(calculateCapacity(encodeImageWidth, encodeImageHeight) / 1024).toFixed(2)} KB`);
        return;
    }

    // ---------------------------------------------------
    // Show progress overlay
    // ---------------------------------------------------
    elements.encodeProgress.hidden = false;
    elements.encodeBtn.disabled    = true;

    await animateProgress(
        elements.encodeProgress,
        elements.encodeProgressFill,
        elements.encodeProgressText
    );

    // ---------------------------------------------------
    // Derive PRNG seed and generate pseudo-random pixel indices
    // ---------------------------------------------------
    const prngSeed = await derivePRNGSeed(prngSeedInput);
    const prng     = createPRNG(prngSeed);
    const indexGen = createIndexGenerator(prng, totalSlots);
    const indices  = indexGen.nextN(bitArray.length);

    // ---------------------------------------------------
    // Embed encrypted payload into LSB at scattered positions
    // ---------------------------------------------------
    const workingData = new ImageData(
        new Uint8ClampedArray(encodeImageData.data),
        encodeImageData.width,
        encodeImageData.height
    );

    embedBits(workingData, bitArray, indices);

    // ---------------------------------------------------
    // Create result canvas and visual diff
    // ---------------------------------------------------
    resultCanvas        = document.createElement('canvas');
    resultCanvas.width  = workingData.width;
    resultCanvas.height = workingData.height;
    const resultCtx     = resultCanvas.getContext('2d');
    resultCtx.putImageData(workingData, 0, 0);

    const differenceCanvas = makeDifferenceCanvas(encodeImageData, workingData);

    latestShareBundle = await buildShareBundle(resultCanvas, {
        sourceFileName: encodeSourceFileName,
        width:          encodeImageWidth,
        height:         encodeImageHeight,
        messageLength:  message.length,
        hint:           bundleHint
    });

    // ---------------------------------------------------
    // Update result overlay UI
    // ---------------------------------------------------
    elements.encodeProgress.hidden     = true;
    elements.encodeProgressFill.style.width = '0%';
    elements.encodeProgressText.textContent = '0%';

    elements.originalThumb.src   = encodeOriginalDataURL;
    elements.resultThumb.src     = resultCanvas.toDataURL();
    elements.differenceThumb.src = differenceCanvas.toDataURL();
    elements.bundleChecksumShort.textContent = `SHA-256 ${latestShareBundle.checksum.slice(0, 12)}…`;
    elements.bundleSize.textContent          = `Bundle ${formatFileSize(latestShareBundle.blob.size)}`;

    // ---------------------------------------------------
    // Show / hide generated key card
    // ---------------------------------------------------
    if (generatedKeyBytes) {
        lastGeneratedKey = formatKeyForDisplay(generatedKeyBytes);
        elements.generatedKeyCode.textContent = lastGeneratedKey;
        elements.generatedKeyCard.hidden      = false;
    } else {
        elements.generatedKeyCard.hidden = true;
        lastGeneratedKey = '';
    }

    elements.encodeResult.hidden = false;

    // ---------------------------------------------------
    // Wire up download / copy buttons
    // ---------------------------------------------------
    elements.downloadBtn.onclick = () => {
        const link  = document.createElement('a');
        link.download = latestShareBundle.encodedFileName;
        link.href     = resultCanvas.toDataURL('image/png');
        link.click();
    };

    elements.downloadBundleBtn.onclick = () => {
        if (!latestShareBundle) { showToast('Bundle is still being prepared'); return; }
        const link  = document.createElement('a');
        link.download = latestShareBundle.bundleFileName;
        link.href     = URL.createObjectURL(latestShareBundle.blob);
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    };

    elements.copyResultBtn.onclick = () => {
        const dataUrl = resultCanvas.toDataURL('image/png');
        navigator.clipboard.writeText(dataUrl).then(() => {
            showToast('Image copied to clipboard');
        }).catch(() => {
            showToast('Failed to copy');
        });
    };

    elements.encodeBtn.disabled = false;
    showToast('Message encrypted and hidden successfully!');
}


// ========================================
// 8. Decode — Main Handler
// ========================================

/**
 * Attempt to decode using a specific credential interpretation.
 * @param {ImageData}  imgData
 * @param {Uint8Array} seedInput    — bytes to hash for PRNG seed
 * @param {string}     credential   — original user input (for PBKDF2 if password mode)
 * @param {Uint8Array|null} keyBytes — parsed raw key bytes (if key mode attempted)
 * @returns {Promise<string>} — decrypted message text
 * @throws on any failure
 */
async function tryDecode(imgData, seedInput, credential, keyBytes) {
    const totalSlots = imgData.width * imgData.height * 3;

    // Derive PRNG seed and create index generator
    const prngSeed = await derivePRNGSeed(seedInput);
    const prng     = createPRNG(prngSeed);
    const indexGen = createIndexGenerator(prng, totalSlots);

    // Phase 1: Extract version + mode (2 bytes = 16 bits)
    const headerBits1  = extractBits(imgData, indexGen, 16);
    const headerBytes1 = bitsToBytes(headerBits1);
    const version      = headerBytes1[0];
    const mode         = headerBytes1[1];

    if (version !== PROTOCOL_VERSION)                   throw new Error('bad');
    if (mode !== MODE_RAW_KEY && mode !== MODE_PASSWORD) throw new Error('bad');

    // Phase 2: Extract remaining header based on mode
    let remainingHeaderBytes;
    if (mode === MODE_PASSWORD) {
        remainingHeaderBytes = SALT_LENGTH + IV_LENGTH + 4; // salt + iv + len
    } else {
        remainingHeaderBytes = IV_LENGTH + 4;               // iv + len
    }

    const headerBits2  = extractBits(imgData, indexGen, remainingHeaderBytes * 8);
    const headerBytes2 = bitsToBytes(headerBits2);

    let off = 0;
    let salt = null;
    if (mode === MODE_PASSWORD) {
        salt = headerBytes2.slice(off, off + SALT_LENGTH);
        off += SALT_LENGTH;
    }

    const iv = headerBytes2.slice(off, off + IV_LENGTH);
    off += IV_LENGTH;

    const ciphertextLen =
        (headerBytes2[off] << 24) |
        (headerBytes2[off + 1] << 16) |
        (headerBytes2[off + 2] << 8) |
         headerBytes2[off + 3];

    // Sanity checks
    if (ciphertextLen <= GCM_TAG_BYTES)        throw new Error('bad');
    if (ciphertextLen > Math.floor(totalSlots / 8)) throw new Error('bad');

    // Phase 3: Extract ciphertext + auth tag
    const ciphertextBits = extractBits(imgData, indexGen, ciphertextLen * 8);
    const ciphertextAndTag = bitsToBytes(ciphertextBits);

    // Phase 4: Derive decryption key
    let cryptoKey;
    if (mode === MODE_PASSWORD) {
        cryptoKey = await deriveKeyFromPassword(credential, salt);
    } else {
        // Mode is RAW_KEY — we need raw key bytes
        if (!keyBytes) throw new Error('bad');
        cryptoKey = await importRawKey(keyBytes);
    }

    // Phase 5: Decrypt with AES-256-GCM
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        ciphertextAndTag
    );

    return new TextDecoder().decode(decrypted);
}

async function handleDecode() {
    if (!decodeImageData) {
        showToast('Please upload an image');
        return;
    }

    const credential = elements.decodePassword.value;
    if (!credential) {
        showToast('Please enter password or encryption key');
        return;
    }

    // Show progress
    elements.decodeProgress.hidden = false;
    elements.decodeBtn.disabled    = true;
    elements.decodeResult.hidden   = true;
    elements.decodeError.hidden    = true;

    await animateProgress(
        elements.decodeProgress,
        elements.decodeProgressFill,
        elements.decodeProgressText
    );

    try {
        // ---------------------------------------------------
        // Determine credential type and build attempt order
        // ---------------------------------------------------
        const isKey    = looksLikeHexKey(credential);
        const keyBytes = isKey ? parseHexKey(credential) : null;

        // Build ordered list of decode attempts.
        // If input has dashes and looks like a key, try key first.
        // Otherwise try as password first, then key as fallback.
        const attempts = [];

        if (isKey && credential.includes('-')) {
            // Likely a formatted key — try key-mode first
            attempts.push({ seedInput: keyBytes, keyBytes: keyBytes });
            attempts.push({ seedInput: new TextEncoder().encode(credential), keyBytes: null });
        } else if (isKey) {
            // 64-hex-char without dashes — could be either; try password first
            attempts.push({ seedInput: new TextEncoder().encode(credential), keyBytes: null });
            attempts.push({ seedInput: keyBytes, keyBytes: keyBytes });
        } else {
            // Definitely a password
            attempts.push({ seedInput: new TextEncoder().encode(credential), keyBytes: null });
        }

        let decryptedMessage = null;

        for (const attempt of attempts) {
            try {
                decryptedMessage = await tryDecode(
                    decodeImageData,
                    attempt.seedInput,
                    credential,
                    attempt.keyBytes
                );
                break; // Success
            } catch {
                continue; // Try next interpretation
            }
        }

        if (decryptedMessage === null) {
            throw new Error('All attempts failed');
        }

        // ---------------------------------------------------
        // Show success
        // ---------------------------------------------------
        elements.decodeProgress.hidden              = true;
        elements.decodeProgressFill.style.width      = '0%';
        elements.decodeProgressText.textContent      = '0%';

        elements.extractedText.textContent = decryptedMessage;
        elements.decodeResult.hidden       = false;
        elements.decodeError.hidden        = true;

    } catch {
        // ---------------------------------------------------
        // Show generic error — never leak partial data
        // ---------------------------------------------------
        elements.decodeProgress.hidden              = true;
        elements.decodeProgressFill.style.width      = '0%';
        elements.decodeProgressText.textContent      = '0%';

        elements.decodeErrorMsg.textContent = 'Incorrect password or encryption key.';
        elements.decodeResult.hidden        = true;
        elements.decodeError.hidden         = false;
    }

    elements.decodeBtn.disabled = false;
}


// ========================================
// Event Handlers
// ========================================

// Tab Navigation
elements.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const tabId = btn.dataset.tab;
        elements.tabBtns.forEach(b => b.classList.remove('active'));
        elements.tabContents.forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    });
});

// Drop Zone Setup
function setupDropZone(dropZone, fileInput, onFile) {
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) onFile(file);
    });
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) onFile(file);
    });
}

// Encode Drop Zone
setupDropZone(
    elements.encodeDropZone,
    elements.encodeFileInput,
    async (file) => {
        if (!file.type.match('image/png')) {
            showToast('Only PNG files are supported');
            return;
        }
        try {
            const imageData = await loadImage(file);

            encodeImageData      = imageData.data;
            encodeImageWidth     = imageData.width;
            encodeImageHeight    = imageData.height;
            encodeOriginalDataURL = imageData.dataURL;
            encodeSourceFileName = file.name;
            latestShareBundle    = null;

            elements.encodeThumb.src           = imageData.dataURL;
            elements.encodeFilename.textContent = file.name;
            elements.encodeFilesize.textContent = formatFileSize(file.size);

            elements.encodeDropZone.hidden = true;
            elements.encodeFileInfo.hidden = false;
            elements.capacityMeter.hidden  = false;

            updateCapacityMeter();
            elements.encodeBtn.disabled = false;
        } catch {
            showToast('Failed to load image');
        }
    }
);

elements.encodeClear.addEventListener('click', () => {
    encodeImageData      = null;
    encodeOriginalDataURL = '';
    encodeSourceFileName = 'image.png';
    latestShareBundle    = null;
    elements.encodeDropZone.hidden = false;
    elements.encodeFileInfo.hidden = true;
    elements.capacityMeter.hidden  = true;
    elements.encodeResult.hidden   = true;
    elements.encodeFileInput.value = '';
    elements.encodeBtn.disabled    = true;
});

// Message Input
elements.messageInput.addEventListener('input', () => {
    elements.charCount.textContent = elements.messageInput.value.length;
    updateCapacityMeter();
});

// Password Toggle (Encode)
elements.toggleEncodePassword.addEventListener('click', () => {
    const inp  = elements.encodePassword;
    inp.type = inp.type === 'password' ? 'text' : 'password';
});

// Encode Button
elements.encodeBtn.addEventListener('click', handleEncode);

// Generated Key — Copy
if (elements.copyKeyBtn) {
    elements.copyKeyBtn.addEventListener('click', () => {
        if (!lastGeneratedKey) return;
        navigator.clipboard.writeText(lastGeneratedKey).then(() => {
            showToast('Encryption key copied to clipboard');
        }).catch(() => {
            showToast('Failed to copy key');
        });
    });
}

// Generated Key — Download as TXT
if (elements.downloadKeyBtn) {
    elements.downloadKeyBtn.addEventListener('click', () => {
        if (!lastGeneratedKey) return;
        const content = [
            'PixelCrypt v2 — Generated Encryption Key',
            '=========================================',
            '',
            lastGeneratedKey,
            '',
            'WARNING: Save this key carefully.',
            'Without it, the hidden message can never be recovered.',
            '',
            `Generated: ${new Date().toISOString()}`
        ].join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const link = document.createElement('a');
        link.download = 'pixelcrypt-key.txt';
        link.href     = URL.createObjectURL(blob);
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
        showToast('Key file downloaded');
    });
}

// Decode Drop Zone
setupDropZone(
    elements.decodeDropZone,
    elements.decodeFileInput,
    async (file) => {
        if (!file.type.match('image/png')) {
            showToast('Only PNG files are supported');
            return;
        }
        try {
            const imageData = await loadImage(file);

            decodeImageData = imageData.data;

            elements.decodeThumb.src           = imageData.dataURL;
            elements.decodeFilename.textContent = file.name;
            elements.decodeFilesize.textContent = formatFileSize(file.size);

            elements.decodeDropZone.hidden      = false;
            elements.decodeFileInfo.hidden      = false;
            // Always show password/key field — no header detection in v2
            elements.decodePasswordField.hidden = false;
            elements.decodePassword.value       = '';
            elements.decodeResult.hidden        = true;
            elements.decodeError.hidden         = true;

            elements.decodeBtn.disabled = false;
        } catch {
            showToast('Failed to load image');
        }
    }
);

elements.decodeClear.addEventListener('click', () => {
    decodeImageData = null;
    elements.decodeFileInfo.hidden      = true;
    elements.decodePasswordField.hidden = true;
    elements.decodeResult.hidden        = true;
    elements.decodeError.hidden         = true;
    elements.decodeFileInput.value      = '';
    elements.decodeBtn.disabled         = true;
});

// Password Toggle (Decode)
elements.toggleDecodePassword.addEventListener('click', () => {
    const inp  = elements.decodePassword;
    inp.type = inp.type === 'password' ? 'text' : 'password';
});

// Decode Button
elements.decodeBtn.addEventListener('click', handleDecode);

// Copy Extracted Message
elements.copyExtractedBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(elements.extractedText.textContent).then(() => {
        showToast('Copied to clipboard');
    }).catch(() => {
        showToast('Failed to copy');
    });
});

// Decode Retry
elements.decodeRetryBtn.addEventListener('click', () => {
    elements.decodeError.hidden    = true;
    elements.decodeFileInput.value = '';
    elements.decodeFileInfo.hidden = true;
    decodeImageData = null;
    elements.decodeBtn.disabled    = true;
});

// Overlay Close Listeners
elements.encodeProgressClose.addEventListener('click', () => {
    elements.encodeProgress.hidden = true;
    elements.encodeBtn.disabled    = false;
});
elements.encodeResultClose.addEventListener('click', () => {
    elements.encodeResult.hidden = true;
});
elements.decodeProgressClose.addEventListener('click', () => {
    elements.decodeProgress.hidden = true;
    elements.decodeBtn.disabled    = false;
});
elements.decodeResultClose.addEventListener('click', () => {
    elements.decodeResult.hidden = true;
});


// ========================================
// Interactive Effects & Sandbox
// ========================================
function initInteractions() {
    document.querySelectorAll('.drop-zone').forEach(zone => {
        zone.addEventListener('mousemove', e => {
            const rect = zone.getBoundingClientRect();
            const x    = e.clientX - rect.left;
            const y    = e.clientY - rect.top;
            zone.style.setProperty('--mouse-x', `${x}px`);
            zone.style.setProperty('--mouse-y', `${y}px`);
        });
    });
}

function initSandbox() {
    const input        = document.getElementById('sandbox-input');
    const binaryDisplay = document.getElementById('sandbox-binary');
    const pixelPreview = document.getElementById('sandbox-pixel-preview');
    const bitRows = {
        R: document.getElementById('sandbox-bits-R'),
        G: document.getElementById('sandbox-bits-G'),
        B: document.getElementById('sandbox-bits-B')
    };

    const basePixel = { R: 120, G: 200, B: 150 };

    function updateSandbox() {
        const char   = input.value || 'A';
        const code   = char.charCodeAt(0);
        const binary = code.toString(2).padStart(8, '0');

        binaryDisplay.textContent = binary;

        ['R', 'G', 'B'].forEach((channel, idx) => {
            const val       = basePixel[channel];
            const valBinary = val.toString(2).padStart(8, '0');
            const targetBit = binary[idx];

            bitRows[channel].innerHTML = '';
            for (let i = 0; i < 8; i++) {
                const bit       = document.createElement('div');
                bit.className   = 'bit-box';
                if (i === 7) {
                    bit.classList.add('bit-lsb');
                    bit.textContent = targetBit;
                    if (targetBit !== valBinary[7]) {
                        bit.classList.add('bit-changed');
                    }
                } else {
                    bit.textContent = valBinary[i];
                }
                bitRows[channel].appendChild(bit);
            }
        });

        const newPixel = {
            R: (basePixel.R & 0xFE) | parseInt(binary[0], 10),
            G: (basePixel.G & 0xFE) | parseInt(binary[1], 10),
            B: (basePixel.B & 0xFE) | parseInt(binary[2], 10)
        };
        pixelPreview.style.background = `rgb(${newPixel.R}, ${newPixel.G}, ${newPixel.B})`;
        pixelPreview.style.boxShadow  = `0 0 20px rgba(${newPixel.R}, ${newPixel.G}, ${newPixel.B}, 0.3)`;
    }

    input.addEventListener('input', updateSandbox);
    updateSandbox();
}


// ========================================
// Initialize
// ========================================
initInteractions();
initSandbox();
console.log('PixelCrypt v2 initialized — all payloads encrypted, PRNG-scattered');
