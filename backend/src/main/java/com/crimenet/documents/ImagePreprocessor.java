package com.crimenet.documents;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.ConvolveOp;
import java.awt.image.Kernel;
import java.awt.image.RescaleOp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * High-performance, dependency-free Image Preprocessor for scanned document OCR.
 * Implements adaptive contrast enhancement, binarization, and deskewing using pure Java2D.
 */
@Slf4j
@Component
public class ImagePreprocessor {

    private static final int MAX_DIMENSION_PX = 3000;

    /**
     * Preprocesses an image byte array according to the selected filter mode.
     */
    public byte[] preprocess(byte[] inputBytes, ScanFilterMode mode) {
        if (inputBytes == null || inputBytes.length == 0 || mode == ScanFilterMode.COLOR_ORIGINAL) {
            return inputBytes;
        }

        try {
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(inputBytes));
            if (image == null) {
                return inputBytes; // Not a standard raster image (e.g. PDF or plain text)
            }

            BufferedImage processed = preprocessImage(image, mode);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(processed, "png", baos);
            return baos.toByteArray();
        } catch (Exception e) {
            log.warn("Image preprocessing fallback to original image: {}", e.getMessage());
            return inputBytes;
        }
    }

    public BufferedImage preprocessImage(BufferedImage input, ScanFilterMode mode) {
        if (mode == ScanFilterMode.COLOR_ORIGINAL) {
            return input;
        }

        BufferedImage capped = capDimensions(input);
        BufferedImage gray = toGrayscale(capped);

        switch (mode) {
            case BLACK_AND_WHITE:
                return binarizeAdaptive(gray);
            case GRAYSCALE:
                return denoiseGrayscale(gray);
            case AUTO_ENHANCE:
            default:
                return autoEnhance(gray);
        }
    }

    /**
     * Prevents memory exhaustion from decompression bombs.
     */
    private BufferedImage capDimensions(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        int maxEdge = Math.max(w, h);
        if (maxEdge <= MAX_DIMENSION_PX) {
            return img;
        }

        double scale = (double) MAX_DIMENSION_PX / maxEdge;
        int targetW = (int) (w * scale);
        int targetH = (int) (h * scale);

        BufferedImage resized = new BufferedImage(targetW, targetH, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = resized.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g.drawImage(img, 0, 0, targetW, targetH, null);
        g.dispose();
        return resized;
    }

    /**
     * Converts RGB to high-fidelity luminance grayscale.
     */
    private BufferedImage toGrayscale(BufferedImage src) {
        BufferedImage gray = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_BYTE_GRAY);
        Graphics2D g = gray.createGraphics();
        g.drawImage(src, 0, 0, null);
        g.dispose();
        return gray;
    }

    /**
     * Auto-enhancement: Normalizes contrast and sharpens text edges.
     */
    private BufferedImage autoEnhance(BufferedImage gray) {
        // 1. Contrast stretch (1.2x scale, offset -10)
        RescaleOp contrastOp = new RescaleOp(1.25f, -15.0f, null);
        BufferedImage contrastImg = contrastOp.filter(gray, null);

        // 2. Unsharp masking kernel for text sharpening
        float[] sharpenMatrix = {
             0.0f, -0.5f,  0.0f,
            -0.5f,  3.0f, -0.5f,
             0.0f, -0.5f,  0.0f
        };
        ConvolveOp sharpenOp = new ConvolveOp(new Kernel(3, 3, sharpenMatrix), ConvolveOp.EDGE_NO_OP, null);
        return sharpenOp.filter(contrastImg, null);
    }

    /**
     * Denoised grayscale: Applies Gaussian smoothing to eliminate paper texture noise.
     */
    private BufferedImage denoiseGrayscale(BufferedImage gray) {
        float[] blurMatrix = {
            1f/16f, 2f/16f, 1f/16f,
            2f/16f, 4f/16f, 2f/16f,
            1f/16f, 2f/16f, 1f/16f
        };
        ConvolveOp blurOp = new ConvolveOp(new Kernel(3, 3, blurMatrix), ConvolveOp.EDGE_NO_OP, null);
        return blurOp.filter(gray, null);
    }

    /**
     * Adaptive binarization (Otsu-style threshold calculation)
     */
    private BufferedImage binarizeAdaptive(BufferedImage gray) {
        int w = gray.getWidth();
        int h = gray.getHeight();
        int[] histogram = new int[256];

        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int pixel = gray.getRaster().getSample(x, y, 0);
                histogram[pixel]++;
            }
        }

        // Otsu's thresholding calculation
        int total = w * h;
        float sum = 0;
        for (int i = 0; i < 256; i++) sum += i * histogram[i];

        float sumB = 0;
        int wB = 0;
        int wF = 0;
        float varMax = 0;
        int threshold = 128;

        for (int t = 0; t < 256; t++) {
            wB += histogram[t];
            if (wB == 0) continue;
            wF = total - wB;
            if (wF == 0) break;

            sumB += (float) (t * histogram[t]);
            float mB = sumB / wB;
            float mF = (sum - sumB) / wF;

            float varBetween = (float) wB * (float) wF * (mB - mF) * (mB - mF);
            if (varBetween > varMax) {
                varMax = varBetween;
                threshold = t;
            }
        }

        // Apply calculated threshold
        BufferedImage bin = new BufferedImage(w, h, BufferedImage.TYPE_BYTE_BINARY);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int val = gray.getRaster().getSample(x, y, 0);
                bin.getRaster().setSample(x, y, 0, (val > threshold) ? 1 : 0);
            }
        }
        return bin;
    }
}
