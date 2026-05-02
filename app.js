/**
 * PixelCrypt - Steganography Portal
 * LSB-based image steganography with AES encryption
 */

// ========================================
// Constants
// ========================================
const HEADER_MAGIC = 'PIXELCRYPT';
const HEADER_VERSION = '1';
const MAX_MESSAGE_SIZE = 10240; // 10KB
const RESERVED_HEADER_BYTES = 64;

// ========================================
// DOM Elements
// ========================================
const elements = {
    // Navigation
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),

    // Encode Tab
    encodeDropZone: document.getElementById('encode-drop-zone'),
    encodeFileInput: document.getElementById('encode-file-input'),
    encodeFileInfo: document.getElementById('encode-file-info'),
    encodeThumb: document.getElementById('encode-thumb'),
    encodeFilename: document.getElementById('encode-filename'),
    encodeFilesize: document.getElementById('encode-filesize'),
    encodeClear: document.getElementById('encode-clear'),
    capacityMeter: document.getElementById('capacity-meter'),
    capacityText: document.getElementById('capacity-text'),
    capacityFill: document.getElementById('capacity-fill'),
    messageInput: document.getElementById('message-input'),
    charCount: document.getElementById('char-count'),
    enableEncryption: document.getElementById('enable-encryption'),
    passwordField: document.getElementById('password-field'),
    encodePassword: document.getElementById('encode-password'),
    toggleEncodePassword: document.getElementById('toggle-encode-password'),
    encodeBtn: document.getElementById('encode-btn'),
    encodeProgress: document.getElementById('encode-progress'),
    encodeProgressFill: document.getElementById('encode-progress-fill'),
    encodeProgressText: document.getElementById('encode-progress-text'),
    encodeResult: document.getElementById('encode-result'),
    resultThumb: document.getElementById('result-thumb'),
    downloadBtn: document.getElementById('download-btn'),
    copyResultBtn: document.getElementById('copy-result-btn'),

    // Decode Tab
    decodeDropZone: document.getElementById('decode-drop-zone'),
    decodeFileInput: document.getElementById('decode-file-input'),
    decodeFileInfo: document.getElementById('decode-file-info'),
    decodeThumb: document.getElementById('decode-thumb'),
    decodeFilename: document.getElementById('decode-filename'),
    decodeFilesize: document.getElementById('decode-filesize'),
    decodeClear: document.getElementById('decode-clear'),
    decodePasswordField: document.getElementById('decode-password-field'),
    decodePassword: document.getElementById('decode-password'),
    toggleDecodePassword: document.getElementById('toggle-decode-password'),
    decodeBtn: document.getElementById('decode-btn'),
    decodeProgress: document.getElementById('decode-progress'),
    decodeProgressFill: document.getElementById('decode-progress-fill'),
    decodeProgressText: document.getElementById('decode-progress-text'),
    decodeResult: document.getElementById('decode-result'),
    extractedText: document.getElementById('extracted-text'),
    copyExtractedBtn: document.getElementById('copy-extracted-btn'),
    decodeError: document.getElementById('decode-error'),
    decodeErrorMsg: document.getElementById('decode-error-msg'),
    decodeRetryBtn: document.getElementById('decode-retry-btn'),

    // Close Buttons
    encodeProgressClose: document.getElementById('encode-progress-close'),
    encodeResultClose: document.getElementById('encode-result-close'),
    decodeProgressClose: document.getElementById('decode-progress-close'),
    decodeResultClose: document.getElementById('decode-result-close'),

    // Toast
    toast: document.getElementById('toast')
};

// ========================================
// State
// ========================================
let encodeImageData = null;
let encodeImageWidth = 0;
let encodeImageHeight = 0;
let decodeImageData = null;
let resultCanvas = null;

// ========================================
// Utility Functions
// ========================================
function showToast(message, duration = 3000) {
    const toast = elements.toast;
    const messageEl = toast.querySelector('.toast-message');
    
    // Reset if already showing
    toast.classList.remove('show');
    
    // Small delay to allow CSS transition to reset
    setTimeout(() => {
        messageEl.textContent = message;
        toast.classList.add('show');
    }, 50);

    // Auto hide
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

function calculateCapacity(width, height) {
    const totalBits = width * height * 3;
    const maxBytes = Math.floor(totalBits / 8) - RESERVED_HEADER_BYTES;
    return Math.max(0, maxBytes);
}

function updateCapacityMeter() {
    if (!encodeImageData) return;

    const capacity = calculateCapacity(encodeImageWidth, encodeImageHeight);
    const messageLength = elements.messageInput.value.length;
    const used = messageLength;
    const percentage = capacity > 0 ? (used / capacity) * 100 : 0;

    elements.capacityText.textContent = `${(used / 1024).toFixed(2)} / ${(capacity / 1024).toFixed(2)} KB`;
    elements.capacityFill.style.width = Math.min(percentage, 100) + '%';

    elements.capacityFill.classList.remove('warning', 'danger');
    if (percentage > 80) elements.capacityFill.classList.add('warning');
    if (percentage > 95) elements.capacityFill.classList.add('danger');
}

// ========================================
// Binary Conversion
// ========================================
function stringToBits(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let bits = '';
    for (const byte of bytes) {
        bits += byte.toString(2).padStart(8, '0');
    }
    return bits;
}

function bitsToString(bits) {
    let bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        const byte = bits.slice(i, i + 8);
        if (byte.length === 8) {
            bytes.push(parseInt(byte, 2));
        }
    }
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

// ========================================
// Encryption (AES-GCM)
// ========================================
async function encryptMessage(message, password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        data
    );

    const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);

    return btoa(String.fromCharCode(...result));
}

async function decryptMessage(encryptedBase64, password) {
    try {
        const encoder = new TextEncoder();
        const data = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));

        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const ciphertext = data.slice(28);

        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const aesKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        throw new Error('Decryption failed - wrong password?');
    }
}

// ========================================
// LSB Steganography
// ========================================
function encodeLSB(imageData, messageBits) {
    const data = imageData.data;
    let bitIndex = 0;

    for (let i = 0; i < data.length && bitIndex < messageBits.length; i += 4) {
        // Skip alpha channel (i + 3)
        for (let j = 0; j < 3 && bitIndex < messageBits.length; j++) {
            const currentBit = data[i + j] & 1;
            const newBit = parseInt(messageBits[bitIndex], 10);

            if (currentBit !== newBit) {
                data[i + j] = (data[i + j] & 0xFE) | newBit;
            }
            bitIndex++;
        }
    }

    return imageData;
}

function decodeLSB(imageData, numBits, offsetBits = 0) {
    const data = imageData.data;
    let allBits = '';
    let messageBits = '';

    for (let i = 0; i < data.length && allBits.length < numBits + offsetBits; i += 4) {
        for (let j = 0; j < 3 && allBits.length < numBits + offsetBits; j++) {
            allBits += (data[i + j] & 1).toString();
        }
    }

    return allBits.slice(offsetBits, offsetBits + numBits);
}

function findHeader(imageData) {
    const data = imageData.data;
    let headerBits = '';
    // Read only what we need: header + some extra for safety
    const maxHeaderLength = RESERVED_HEADER_BYTES * 8;

    for (let i = 0; i < data.length && headerBits.length < maxHeaderLength; i += 4) {
        for (let j = 0; j < 3 && headerBits.length < maxHeaderLength; j++) {
            headerBits += (data[i + j] & 1).toString();
        }
    }

    const headerStr = bitsToString(headerBits);

    // Find the magic header
    const magicIndex = headerStr.indexOf(HEADER_MAGIC + '|');
    if (magicIndex === -1) {
        return null;
    }

    // Extract only the header portion (skip the magicIndex characters)
    const headerOnly = headerStr.slice(magicIndex);
    const parts = headerOnly.split('|');
    if (parts.length < 3) {
        return null;
    }

    // We need to be careful: parts[2] might contain the start of the message
    // The encrypted flag is either 'true' or 'false'
    const isEncrypted = parts[2].startsWith('true');
    const encryptFlagStr = isEncrypted ? 'true' : 'false';

    // Calculate actual header bit length - header starts at magicIndex, not bit 0!
    const headerStored = HEADER_MAGIC + '|' + parts[1] + '|' + encryptFlagStr;
    const actualHeaderBits = stringToBits(headerStored).length;

    // Account for the bits before the magic header that we skipped
    const bitsBeforeMagic = magicIndex * 8;
    const totalSkipBits = bitsBeforeMagic + actualHeaderBits;

    return {
        length: parseInt(parts[1], 10),
        isEncrypted: isEncrypted,
        headerBitLength: totalSkipBits
    };
}

// ========================================
// File Handling
// ========================================
function loadImage(file, target) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement('canvas');
                canvas.width = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                resolve({
                    image: img,
                    canvas: canvas,
                    ctx: ctx,
                    data: ctx.getImageData(0, 0, img.width, img.height),
                    width: img.width,
                    height: img.height,
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

function saveImage(canvas) {
    return canvas.toDataURL('image/png').split(',')[1];
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

            fillElement.style.width = (progress * 100) + '%';
            textElement.textContent = Math.round(progress * 100) + '%';

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
// Encode Functions
// ========================================
async function handleEncode() {
    const message = elements.messageInput.value.trim();
    if (!message) {
        showToast('Please enter a message to hide');
        return;
    }

    const isEncrypted = elements.enableEncryption.checked;
    let password = '';
    let finalMessage = message;

    if (isEncrypted) {
        password = elements.encodePassword.value;
        if (password.length < 4) {
            showToast('Password must be at least 4 characters');
            return;
        }
        try {
            finalMessage = await encryptMessage(message, password);
        } catch (e) {
            showToast('Encryption failed');
            return;
        }
    }

    const capacity = calculateCapacity(encodeImageWidth, encodeImageHeight);
    if (finalMessage.length > capacity) {
        showToast(`Message too large. Max: ${(capacity / 1024).toFixed(2)} KB`);
        return;
    }

    // Create working copy
    const workingData = new ImageData(
        new Uint8ClampedArray(encodeImageData.data),
        encodeImageData.width,
        encodeImageData.height
    );

    // Show progress
    elements.encodeProgress.hidden = false;
    elements.encodeBtn.disabled = true;

    await animateProgress(
        elements.encodeProgress,
        elements.encodeProgressFill,
        elements.encodeProgressText
    );

    // Create header
    const header = `${HEADER_MAGIC}|${finalMessage.length}|${isEncrypted}`;
    const headerBits = stringToBits(header);
    const messageBits = stringToBits(finalMessage);
    const allBits = headerBits + messageBits;

    // Encode
    encodeLSB(workingData, allBits);

    // Create result
    const resultCanvas = document.createElement('canvas');
    resultCanvas.width = workingData.width;
    resultCanvas.height = workingData.height;
    const resultCtx = resultCanvas.getContext('2d');
    resultCtx.putImageData(workingData, 0, 0);

    // Show result
    elements.encodeProgress.hidden = true;
    elements.encodeProgressFill.style.width = '0%';
    elements.encodeProgressText.textContent = '0%';

    elements.resultThumb.src = resultCanvas.toDataURL();
    elements.encodeResult.hidden = false;

    // Setup download
    elements.downloadBtn.onclick = () => {
        const link = document.createElement('a');
        link.download = 'encoded_' + (elements.encodeFilename.textContent || 'image.png');
        link.href = resultCanvas.toDataURL('image/png');
        link.click();
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
    showToast('Message hidden successfully!');
}

// ========================================
// Decode Functions
// ========================================
async function handleDecode() {
    if (!decodeImageData) {
        showToast('Please upload an image');
        return;
    }

    elements.decodeProgress.hidden = false;
    elements.decodeBtn.disabled = true;
    elements.decodeResult.hidden = true;
    elements.decodeError.hidden = true;

    await animateProgress(
        elements.decodeProgress,
        elements.decodeProgressFill,
        elements.decodeProgressText
    );

    try {
        // Find header
        const headerInfo = findHeader(decodeImageData);

        if (!headerInfo) {
            throw new Error('No hidden data found');
        }

        // Decode message (skip past header bits)
        const messageBits = decodeLSB(decodeImageData, headerInfo.length * 8, headerInfo.headerBitLength);
        const message = bitsToString(messageBits);

        let finalMessage = message;

        if (headerInfo.isEncrypted) {
            const password = elements.decodePassword.value;
            if (!password) {
                elements.decodeProgress.hidden = true;
                elements.decodePasswordField.hidden = false;
                elements.decodeBtn.disabled = false;
                showToast('Please enter password');
                return;
            }
            finalMessage = await decryptMessage(message, password);
        }

        elements.decodeProgress.hidden = true;
        elements.decodeProgressFill.style.width = '0%';
        elements.decodeProgressText.textContent = '0%';

        elements.extractedText.textContent = finalMessage;
        elements.decodeResult.hidden = false;
        elements.decodeError.hidden = true;

    } catch (e) {
        elements.decodeProgress.hidden = true;
        elements.decodeProgressFill.style.width = '0%';
        elements.decodeProgressText.textContent = '0%';

        elements.decodeErrorMsg.textContent = e.message || 'No hidden data found';
        elements.decodeResult.hidden = true;
        elements.decodeError.hidden = false;
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
            const imageData = await loadImage(file, 'encode');

            encodeImageData = imageData.data;
            encodeImageWidth = imageData.width;
            encodeImageHeight = imageData.height;

            elements.encodeThumb.src = imageData.dataURL;
            elements.encodeFilename.textContent = file.name;
            elements.encodeFilesize.textContent = formatFileSize(file.size);

            elements.encodeDropZone.hidden = true;
            elements.encodeFileInfo.hidden = false;
            elements.capacityMeter.hidden = false;

            updateCapacityMeter();
            elements.encodeBtn.disabled = false;
        } catch (e) {
            showToast('Failed to load image');
        }
    }
);

elements.encodeClear.addEventListener('click', () => {
    encodeImageData = null;
    elements.encodeDropZone.hidden = false;
    elements.encodeFileInfo.hidden = true;
    elements.capacityMeter.hidden = true;
    elements.encodeFileInput.value = '';
    elements.encodeBtn.disabled = true;
});

// Message Input
elements.messageInput.addEventListener('input', () => {
    elements.charCount.textContent = elements.messageInput.value.length;
    updateCapacityMeter();
});

// Encryption Toggle
elements.enableEncryption.addEventListener('change', () => {
    elements.passwordField.hidden = !elements.enableEncryption.checked;
});

// Password Toggle
elements.toggleEncodePassword.addEventListener('click', () => {
    const type = elements.encodePassword.type === 'password' ? 'text' : 'password';
    elements.encodePassword.type = type;
});

// Encode Button
elements.encodeBtn.addEventListener('click', handleEncode);

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
            const imageData = await loadImage(file, 'decode');

            decodeImageData = imageData.data;

            elements.decodeThumb.src = imageData.dataURL;
            elements.decodeFilename.textContent = file.name;
            elements.decodeFilesize.textContent = formatFileSize(file.size);

            elements.decodeDropZone.hidden = false;
            elements.decodeFileInfo.hidden = false;
            elements.decodePasswordField.hidden = true;
            elements.decodePassword.value = '';
            elements.decodeResult.hidden = true;
            elements.decodeError.hidden = true;

            elements.decodeBtn.disabled = false;
        } catch (e) {
            showToast('Failed to load image');
        }
    }
);

elements.decodeClear.addEventListener('click', () => {
    decodeImageData = null;
    elements.decodeFileInfo.hidden = true;
    elements.decodePasswordField.hidden = true;
    elements.decodeResult.hidden = true;
    elements.decodeError.hidden = true;
    elements.decodeFileInput.value = '';
    elements.decodeBtn.disabled = true;
});

elements.toggleDecodePassword.addEventListener('click', () => {
    const type = elements.decodePassword.type === 'password' ? 'text' : 'password';
    elements.decodePassword.type = type;
});

elements.decodeBtn.addEventListener('click', handleDecode);

elements.copyExtractedBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(elements.extractedText.textContent).then(() => {
        showToast('Copied to clipboard');
    }).catch(() => {
        showToast('Failed to copy');
    });
});

elements.decodeRetryBtn.addEventListener('click', () => {
    elements.decodeError.hidden = true;
    elements.decodeFileInput.value = '';
    elements.decodeFileInfo.hidden = true;
    decodeImageData = null;
    elements.decodeBtn.disabled = true;
});

// Overlay Close Listeners
elements.encodeProgressClose.addEventListener('click', () => {
    elements.encodeProgress.hidden = true;
    elements.encodeBtn.disabled = false;
});

elements.encodeResultClose.addEventListener('click', () => {
    elements.encodeResult.hidden = true;
});

elements.decodeProgressClose.addEventListener('click', () => {
    elements.decodeProgress.hidden = true;
    elements.decodeBtn.disabled = false;
});

elements.decodeResultClose.addEventListener('click', () => {
    elements.decodeResult.hidden = true;
});

// Interactive Effects
function initInteractions() {
    document.querySelectorAll('.drop-zone').forEach(zone => {
        zone.addEventListener('mousemove', e => {
            const rect = zone.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            zone.style.setProperty('--mouse-x', `${x}px`);
            zone.style.setProperty('--mouse-y', `${y}px`);
        });
    });
}

function initSandbox() {
    const input = document.getElementById('sandbox-input');
    const binaryDisplay = document.getElementById('sandbox-binary');
    const pixelPreview = document.getElementById('sandbox-pixel-preview');
    const bitRows = {
        R: document.getElementById('sandbox-bits-R'),
        G: document.getElementById('sandbox-bits-G'),
        B: document.getElementById('sandbox-bits-B')
    };

    const basePixel = { R: 120, G: 200, B: 150 };

    function updateSandbox() {
        const char = input.value || 'A';
        const code = char.charCodeAt(0);
        const binary = code.toString(2).padStart(8, '0');
        
        binaryDisplay.textContent = binary;
        
        // Update bit rows
        ['R', 'G', 'B'].forEach((channel, idx) => {
            const val = basePixel[channel];
            const valBinary = val.toString(2).padStart(8, '0');
            const targetBit = binary[idx]; // Just take first 3 bits for R, G, B
            
            bitRows[channel].innerHTML = '';
            for (let i = 0; i < 8; i++) {
                const bit = document.createElement('div');
                bit.className = 'bit-box';
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

        // Update preview color with new LSBs
        const newPixel = {
            R: (basePixel.R & 0xFE) | parseInt(binary[0], 10),
            G: (basePixel.G & 0xFE) | parseInt(binary[1], 10),
            B: (basePixel.B & 0xFE) | parseInt(binary[2], 10)
        };
        pixelPreview.style.background = `rgb(${newPixel.R}, ${newPixel.G}, ${newPixel.B})`;
        pixelPreview.style.boxShadow = `0 0 20px rgba(${newPixel.R}, ${newPixel.G}, ${newPixel.B}, 0.3)`;
    }

    input.addEventListener('input', updateSandbox);
    updateSandbox(); // Initial call
}

// Initialize
initInteractions();
initSandbox();
console.log('PixelCrypt initialized');