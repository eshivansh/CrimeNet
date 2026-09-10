package com.crimenet.documents;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OcrService {

    /**
     * Mock OCR extraction.
     * In a real app, this would use Tesseract or cloud Vision API.
     */
    public String extractText(byte[] content, String mimeType) {
        log.info("Running mock OCR on document of type {}", mimeType);
        
        // Simulating some processing time
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return "This is a mock extracted text from the document. " +
               "It contains dummy legal terminology like affidavit, jurisdiction, and subpoena. " +
               "The quick brown fox jumps over the lazy dog.";
    }
}
