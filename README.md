<p align="center">
  <img src="assets/banner.jpg" alt="PIXELCRYPT Banner" width="100%" />
</p>

<h1 align="center">🔐 PixelCrypt v2 — Client-Side Encrypted Steganography Portal</h1>

<p align="center">
  <b>Hide AES-256-GCM encrypted messages inside image pixels with PRNG-scattered LSB embedding.</b>
</p>

<p align="center">
  <a href="#-version"><img src="https://img.shields.io/badge/version-v2.0.0--SECURE-00d4aa.svg?style=for-the-badge" alt="Version"></a>
  <a href="#-encryption"><img src="https://img.shields.io/badge/encryption-AES--256--GCM-8b5cf6.svg?style=for-the-badge" alt="Encryption"></a>
  <a href="#-privacy"><img src="https://img.shields.io/badge/privacy-100%25%20Offline%20%26%20Client--Side-10b981.svg?style=for-the-badge" alt="Privacy"></a>
  <a href="#-license"><img src="https://img.shields.io/badge/license-MIT-f59e0b.svg?style=for-the-badge" alt="License"></a>
</p>

---

## 📖 Table of Contents

- [What is PixelCrypt?](#-what-is-pixelcrypt)
- [Beginner's Guide: Steganography vs Encryption](#-beginners-guide-steganography-vs-encryption)
- [✨ Key Features](#-key-features)
- [🔒 Security & Architecture (How It Works)](#-security--architecture-how-it-works)
- [🎯 Step-by-Step User Guide](#-step-by-step-user-guide)
  - [Hiding a Secret Message (Encoding)](#1-hiding-a-secret-message-encoding)
  - [Extracting a Secret Message (Decoding)](#2-extracting-a-secret-message-decoding)
- [🛡️ Why Generic Steganography Tools Fail Against PixelCrypt v2](#️-why-generic-steganography-tools-fail-against-pixelcrypt-v2)
- [💻 Technical Stack](#-technical-stack)
- [🚀 Quick Start & Installation](#-quick-start--installation)
- [👤 Author & License](#-author--license)

---

## 💡 What is PixelCrypt?

**PixelCrypt v2** is a zero-knowledge, browser-native cybersecurity tool that hides secret text messages inside normal digital PNG images. 

Unlike basic steganography programs that leave unencrypted text embedded sequentially inside image pixels, **PixelCrypt v2** encrypts your message using military-grade **AES-256-GCM** encryption and scatters the encrypted bits randomly across the image canvas using a **key-derived pseudo-random number generator (PRNG)**.

To anyone looking at the image, it appears completely untouched. Even if an attacker uploads the image to automated forensic tools or generic online steganography extractors, all they obtain is uncorrelated random noise.

---

## 🐣 Beginner's Guide: Steganography vs Encryption

If you are new to cybersecurity concepts, here is a simple analogy:

| Concept | What It Does | Simple Analogy |
| :--- | :--- | :--- |
| **Encryption** | Locks your message so only someone with the key can read it. | Putting a written message inside an unbreakable locked steel safe. Anyone can see the safe, but can't open it. |
| **Steganography** | Hides the *fact* that a message even exists. | Writing a message in invisible ink on a picture hanging on the wall. Nobody suspects there is a message. |
| **PixelCrypt v2** | **Combines both!** Encrypts the text first, then hides the encrypted bits inside random image pixels. | Putting an encrypted secret inside a locked safe, shrinking the safe, and hiding it inside a brick in a wall. |

---

## ✨ Key Features

- **🔒 Mandatory AES-256-GCM Encryption**: Every single payload is encrypted before embedding. Unencrypted plaintext embedding is strictly impossible.
- **🎲 Key-Derived PRNG Pixel Scattering**: Bits are scattered non-sequentially using an SFC32 PRNG and an incremental Fisher-Yates shuffle seeded by `SHA-256(password/key)`.
- **🔑 Auto 256-Bit Cryptographic Key Generation**: Leave the password field blank, and PixelCrypt auto-generates a secure 256-bit key (`crypto.getRandomValues()`) formatted as `D4A9-7F22-8BC1-...`.
- **📋 One-Click Key Copy & Download**: Copy generated keys directly to your clipboard or download them as a `.txt` key backup file.
- **📦 Secure Handoff Bundles**: Export a ZIP package containing your encoded PNG, a hint note, SHA-256 checksum, manifest file, and recipient instructions.
- **🌐 100% Client-Side & Offline**: Built using native browser Web Crypto APIs. Zero server calls, zero network tracking, zero cookies, zero data storage.
- **🔬 Visual Difference Inspector**: Built-in inspector compares the original image, encoded image, and an amplified difference map showing modified pixel channels.
- **🧬 Interactive Binary Sandbox**: Learn how Least Significant Bits (LSB) work in real time by testing character-to-bit channel shifts.

---

## 🔒 Security & Architecture (How It Works)

### Encoding Pipeline

```
  +-----------------------------------------------------------------------+
  |                          PIXELCRYPT v2 PIPELINE                        |
  +-----------------------------------------------------------------------+
  | Secret Message                                                        |
  |      │                                                                |
  |      ▼                                                                |
  | Credential Mode:                                                      |
  |   • User Password  --> PBKDF2 (SHA-256, 100k) --> AES-256 Key         |
  |   • Empty Password --> crypto.getRandomValues(32) --> 256-bit Key    |
  |      │                                                                |
  |      ▼                                                                |
  | AES-256-GCM Encryption (with fresh 96-bit IV)                        |
  |      │                                                                |
  |      ▼                                                                |
  | Custom Binary Payload Assembly:                                      |
  |   [Version (1B)] + [Mode (1B)] + [Salt (16B)] + [IV (12B)]            |
  |   + [Ciphertext Length (4B)] + [Ciphertext + Auth Tag (16B)]          |
  |      │                                                                |
  |      ▼                                                                |
  | Seed PRNG: SHA-256(Password or Key)                                   |
  |      │                                                                |
  |      ▼                                                                |
  | PRNG Fisher-Yates Permutation -> Pseudo-Random Pixel Channel Indices   |
  |      │                                                                |
  |      ▼                                                                |
  | Embed Bits into LSB of Pseudo-Random Pixel Channels                   |
  +-----------------------------------------------------------------------+
```

### Custom Binary Payload Layout
PixelCrypt v2 uses a custom headerless binary format with **no human-readable magic strings** (such as `PIXELCRYPT` or `STEGO`):

```
┌──────────┬──────┬────────────┬─────────┬────────────────┬─────────────────────┐
│ Version  │ Mode │ Salt       │ IV      │ Ciphertext Len │ Ciphertext + Tag    │
│ (1 byte) │(1 B) │(16 B if    │ (12 B)  │ (4 B, big-end) │ (variable)          │
│  0x02    │      │ mode=0x01) │         │                │                     │
└──────────┴──────┴────────────┴─────────┴────────────────┴─────────────────────┘
```

---

## 🎯 Step-by-Step User Guide

### 1. Hiding a Secret Message (Encoding)

1. **Open PixelCrypt** in any modern web browser.
2. Under the **Encode** tab, click or drag-and-drop a **PNG image** into the Source Image area.
3. Type your secret text in the **Secret Message** field.
4. **Choose your Security Mode**:
   - **Custom Password**: Type a password of your choice in the **Password (Optional)** field.
   - **Auto-Generated Key**: Leave the password field **blank**. PixelCrypt will generate a secure 256-bit encryption key for you.
5. Click **Generate Encoded Portal**.
6. **Save Your Results**:
   - Download your encoded PNG image.
   - If an auto-generated key was created, click **Copy Key** or **Download TXT** to save it safely.

> [!WARNING]
> Save your encryption key or password carefully! Without the exact credential, hidden messages can **never** be recovered.

---

### 2. Extracting a Secret Message (Decoding)

1. Switch to the **Decode** tab.
2. Drag-and-drop the encoded PNG image into the **Extraction Chamber**.
3. In the **Password or Encryption Key** field, enter either:
   - The **password** set by the sender.
   - The **generated encryption key** (e.g. `D4A9-7F22-8BC1-...`, with or without dashes).
4. Click **Extract Hidden Payload**.
5. Your decrypted message will appear cleanly on screen with a one-click **Copy to Clipboard** button.

> [!NOTE]
> If an incorrect password or key is entered, PixelCrypt displays `"Incorrect password or encryption key."` without exposing any partial text or stack traces.

---

## 🛡️ Why Generic Steganography Tools Fail Against PixelCrypt v2

Most generic LSB extraction tools (such as CacheSleuth, StegSolve, zsteg, or online web extractors) read pixel bits sequentially starting from the top-left pixel (Index 0, 1, 2, 3...).

| Steganography Feature | Traditional LSB Tools | PixelCrypt v2 Protocol |
| :--- | :--- | :--- |
| **Bit Order** | Sequential (0, 1, 2, 3...) | **Pseudo-Random PRNG Permutation** |
| **Payload Encryption** | None or optional plaintext | **Mandatory AES-256-GCM** |
| **Header Signatures** | Predictable magic bytes (`STEGO`, `PIXELCRYPT`) | **Binary Payload (No plaintext headers)** |
| **Generic Tool Result** | Plaintext extracted easily | **Uncorrelated Random Noise** |

---

## 💻 Technical Stack

- **Frontend Core**: HTML5 & Vanilla JavaScript (ES6+ Modules)
- **Styling**: Vanilla CSS3 with Glassmorphism, CSS Custom Properties, and smooth keyframe animations
- **Cryptography Engine**: Native Browser **Web Crypto API** (`crypto.subtle`, `crypto.getRandomValues`)
  - **Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data)
  - **Key Derivation**: PBKDF2 with SHA-256 & 100,000 iterations
  - **PRNG**: SFC32 (Simple Fast Counter) initialized via `SHA-256` seed digest
- **Fonts**: [Outfit](https://fonts.google.com/specimen/Outfit), [DM Sans](https://fonts.google.com/specimen/DM+Sans), and [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono)

---

## 🚀 Quick Start & Installation

Because PixelCrypt is 100% client-side and serverless, no installation or package managers are required!

### Option 1: Open Directly in Browser
1. Clone or download the repository:
   ```bash
   git clone https://github.com/Farhan0629/PixelCrypt.git
   ```
2. Double-click `index.html` to open it in Chrome, Firefox, Edge, or Safari.

### Option 2: Run with a Local Server
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx serve .
```
Then navigate to `http://localhost:8000` or `http://localhost:3000`.

---

## 👤 Author & License

Developed with 💎 by **Farhan**

- **GitHub**: [@Farhan0629](https://github.com/Farhan0629)
- **License**: [MIT License](LICENSE) — Feel free to use, modify, and distribute!

---

<p align="center">
  <sub>© 2026 PixelCrypt Protocol • v2.0.0-SECURE</sub>
</p>
