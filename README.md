# 🌌 PixelCrypt

[![Project Status: Active](https://img.shields.io/badge/Status-Active-00d4aa.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-8b5cf6.svg)](LICENSE)
[![Author: Farhan0629](https://img.shields.io/badge/Author-Farhan0629-fcf6ba.svg)](https://github.com/Farhan0629)

**PixelCrypt** is a premium, client-side steganography portal that allows you to hide secret messages within PNG images using LSB (Least Significant Bit) encoding and AES-GCM encryption. Designed with a high-fidelity **Cipher-Glass** aesthetic.

![PixelCrypt Preview](preview.png)

## ✨ Features

- **🛡️ Secure Encoding:** Inject text messages into image pixels with zero visual degradation.
- **🔐 AES-256 Encryption:** Optional military-grade encryption using the Web Crypto API (AES-GCM).
- **💎 Cipher-Glass UI:** A premium, frosted-glass interface with ambient background motion and interactive glow effects.
- **🧬 Binary Sandbox:** An interactive educational tool to visualize how bits are manipulated in the LSB layer.
- **🚀 Zero Knowledge:** 100% client-side processing. Your images and passwords never leave your browser.
- **📱 Responsive Design:** Fully optimized for desktop and mobile "secret agent" experiences.

## 🛠️ How It Works

PixelCrypt utilizes the **Least Significant Bit (LSB)** technique. Every pixel in a digital image is composed of Red, Green, and Blue (RGB) channels, each represented by 8 bits (0-255). 

1. **Text to Binary:** Your message is converted into a stream of bits.
2. **Bit Substitution:** PixelCrypt replaces the last bit (the least significant one) of each color channel with a bit from your message.
3. **Visual Integrity:** Because the modified bit represents the smallest possible value change (±1), the resulting color shift is invisible to the human eye.

## 🚀 Getting Started

Since PixelCrypt is a static web application, you can run it instantly:

1.  Clone the repository:
    ```bash
    git clone https://github.com/Farhan0629/PixelCrypt.git
    ```
2.  Open `index.html` in any modern web browser.

Alternatively, use a local server for better performance:
```bash
# Python
python -m http.server 8000

# Node.js
npx serve .
```

## 📜 Technical Stack

- **HTML5 & CSS3:** Custom glassmorphism system with CSS Variables and Keyframe animations.
- **Vanilla JavaScript:** High-performance LSB manipulation using `CanvasRenderingContext2D` and `ImageData`.
- **Web Crypto API:** PBKDF2 key derivation and AES-GCM encryption.
- **Fonts:** [Outfit](https://fonts.google.com/specimen/Outfit) (Headings), [DM Sans](https://fonts.google.com/specimen/DM+Sans) (Body), [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) (Data).

## 👤 Author

**Farhan**  
GitHub: [@Farhan0629](https://github.com/Farhan0629)

---

*Made with 💎 by Farhan*
