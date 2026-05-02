# Steganography-as-a-Service Portal - Specification

## 1. Project Overview

**Project Name:** PixelCrypt
**Type:** Client-side Web Application (Single-page)
**Core Functionality:** LSB-based image steganography for encoding/decoding text messages in PNG images
**Target Users:** Security enthusiasts, developers, students learning steganography

---

## 2. UI/UX Specification

### 2.1 Layout Structure

**Page Sections:**
- **Header**: Logo + Navigation tabs (Encode | Decode | How It Works)
- **Main Content**: Tab-based content area
- **Footer**: Minimal - copyright + links

**Responsive Breakpoints:**
- Mobile: < 768px (stacked layout)
- Desktop: >= 768px (centered max-width container)

### 2.2 Visual Design

**Color Palette:**
- Primary: `#00d4aa` (Neon Cyan/Teal)
- Primary Hover: `#00f5c4`
- Secondary: `#0a0e17` (Deep Dark Blue/Black)
- Secondary Light: `#141b2d` (Card backgrounds)
- Accent: `#8b5cf6` (Subtle Purple)
- Text Primary: `#e2e8f0` (Light gray)
- Text Secondary: `#94a3b8` (Muted gray)
- Border: `#1e293b` (Subtle borders)
- Success: `#10b981`
- Error: `#ef4444`

**Typography:**
- Headings: `'Outfit'`, sans-serif (Google Fonts)
- Body: `'DM Sans'`, sans-serif (Google Fonts)
- Monospace: `'JetBrains Mono'`, monospace (for binary/technical)

**Font Sizes:**
- H1: 2.5rem (40px)
- H2: 1.75rem (28px)
- H3: 1.25rem (20px)
- Body: 1rem (16px)
- Small: 0.875rem (14px)

**Spacing System:**
- Base unit: 8px
- Section padding: 64px vertical
- Card padding: 24px
- Element gap: 16px

**Visual Effects:**
- Cards: `box-shadow: 0 4px 24px rgba(0, 212, 170, 0.08)`
- Buttons: Subtle glow on hover (`box-shadow: 0 0 20px rgba(0, 212, 170, 0.3)`)
- Transitions: `all 0.3s cubic-bezier(0.4, 0, 0.2, 1)`
- Border radius: 12px (cards), 8px (buttons/inputs)

### 2.3 Components

**Navigation Tabs:**
- Horizontal pill-style tabs
- Active state: filled with primary color
- Inactive: transparent with border
- Hover: subtle background shift

**Drop Zone:**
- Dashed border (`2px dashed #1e293b`)
- Drag-over state: border becomes primary color, background shifts
- Icon: upload cloud icon
- Text: "Drop PNG here or click to browse"

**Input Fields:**
- Dark background (`#141b2d`)
- Border: `1px solid #1e293b`
- Focus: border becomes primary color
- Placeholder: muted gray

**Buttons:**
- Primary: filled with primary color, dark text
- Secondary: outlined with border
- Disabled: reduced opacity (0.5)

**Progress Indicator:**
- Linear progress bar with gradient fill
- Animated shimmer effect
- Percentage text overlay

**Capacity Meter:**
- Horizontal bar showing used/available
- Color transitions: green → yellow → red based on capacity

**Cards:**
- Elevated with subtle shadow
- Rounded corners
- Dark background with slight transparency

---

## 3. Functionality Specification

### 3.1 Core Features

**A. Encode Tab**
1. Image Upload
   - Drag-and-drop zone
   - Click-to-browse fallback
   - Accept only PNG files
   - Display thumbnail preview
   - Show file name and size

2. Text Input
   - Textarea for message (max 10KB)
   - Character count display
   - Real-time capacity calculation

3. Password (Optional)
   - Checkbox to enable encryption
   - Password input field (show/hide toggle)
   - Minimum 4 characters when enabled

4. Encode Action
   - "Hide Message" button
   - Progress indicator during encoding
   - Success: show download button + preview
   - Error: display clear error message

5. Output
   - Download encoded PNG
   - Copy to clipboard option
   - Success confirmation animation

**B. Decode Tab**
1. Image Upload
   - Same drop zone as encode
   - Display thumbnail preview

2. Password (Optional)
   - If encoded image was encrypted
   - Input field for password

3. Decode Action
   - "Extract Message" button
   - Progress indicator
   - Auto-display extracted text

4. Output
   - Display extracted text in styled box
   - Copy to clipboard
   - Clear "empty" message if no hidden data

**C. How It Works Tab**
1. Explanation content
2. Animated diagram (CSS-only)
3. Technical notes

### 3.2 User Interactions & Flows

**Encode Flow:**
1. User drops/selects PNG image
2. System validates image and calculates capacity
3. User enters text message
4. System shows real-time capacity usage
5. User optionally enables encryption + password
6. User clicks "Hide Message"
7. System encodes (with progress)
8. System provides download + preview

**Decode Flow:**
1. User drops/selects encoded PNG
2. System validates image
3. User optionally enters password (if encrypted)
4. User clicks "Extract Message"
5. System extracts (with progress)
6. System displays extracted text

### 3.3 Data Handling

**Capacity Calculation:**
- Each pixel can store 3 bits (1 bit per RGB channel)
- Formula: `(width × height × 3) / 8` = max bytes
- Reserve 44 bytes for header/metadata
- Display: "X KB of Y KB used"

**LSB Encoding Algorithm:**
1. Convert text to binary (UTF-8)
2. Prepend header: `PIXELCRYPT|{length}|{isEncrypted:bool}`
3. For each bit, modify LSB of consecutive pixels
4. Modify alpha channel only if needed (preserve transparency)

**Encryption (AES):**
- Use Web Crypto API
- AES-GCM 256-bit
- Derive key from password using PBKDF2
- Store encrypted flag in header

### 3.4 Edge Cases

- Non-PNG file: Show error "Only PNG files supported"
- Text too large: Show error with capacity needed
- Corrupted encoded image: Show "No hidden data found"
- Wrong password: Show "Decryption failed - wrong password?"
- Empty text: Disable encode button

---

## 4. Acceptance Criteria

### Visual Checkpoints
- [ ] Dark theme with neon cyan accents renders correctly
- [ ] All three tabs (Encode/Decode/How It Works) are accessible
- [ ] Drop zones respond to drag events with visual feedback
- [ ] Buttons show hover states with glow effect
- [ ] Progress bar animates during encode/decode
- [ ] Capacity meter updates in real-time
- [ ] Mobile layout stacks correctly

### Functional Checkpoints
- [ ] PNG files can be uploaded via drag-drop and click
- [ ] Non-PNG files show error message
- [ ] Text capacity is calculated and displayed
- [ ] Encode produces downloadable PNG with hidden text
- [ ] Decode extracts hidden text from encoded PNG
- [ ] Optional encryption works with password
- [ ] Wrong password shows appropriate error
- [ ] Copy to clipboard works for text output
- [ ] Progress indicator shows during processing

### Technical Checkpoints
- [ ] No external dependencies except Google Fonts
- [ ] All operations are client-side (no network requests)
- [ ] No console errors in normal operation
- [ ] Works in modern browsers (Chrome, Firefox, Edge)