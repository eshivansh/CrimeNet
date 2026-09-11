package com.crimenet.documents;

/**
 * Output scan filter mode applied to documents prior to OCR recognition.
 * Matches standard mobile forensic scan options.
 */
public enum ScanFilterMode {
    AUTO_ENHANCE,     // contrast-boosted adaptive sharpening (recommended for document scans)
    GRAYSCALE,        // grayscale with noise reduction
    BLACK_AND_WHITE,  // high-contrast adaptive binarization for clean text
    COLOR_ORIGINAL    // raw camera/scanner image capture
}
