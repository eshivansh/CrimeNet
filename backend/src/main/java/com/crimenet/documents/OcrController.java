package com.crimenet.documents;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/documents")
@RequiredArgsConstructor
public class OcrController {

    private final OcrService ocrService;
    private final ImagePreprocessor imagePreprocessor;

    /**
     * Analyze and extract text and structured legal entities from an uploaded document (PDF/Image)
     * with optional adaptive scan preprocessing.
     */
    @PostMapping(value = "/ocr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<OcrService.ExtractedDocumentData>> processOcr(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "filterMode", required = false, defaultValue = "AUTO_ENHANCE") String filterModeStr) throws IOException {
        
        ScanFilterMode filterMode = ScanFilterMode.AUTO_ENHANCE;
        try {
            if (filterModeStr != null) {
                filterMode = ScanFilterMode.valueOf(filterModeStr.toUpperCase());
            }
        } catch (IllegalArgumentException ignored) {
            filterMode = ScanFilterMode.AUTO_ENHANCE;
        }

        log.info("Processing OCR request for file: {} ({} bytes, MIME: {}, filterMode: {})",
                file.getOriginalFilename(), file.getSize(), file.getContentType(), filterMode);

        byte[] rawContent = file.getBytes();
        String filename = file.getOriginalFilename();
        String mimeType = file.getContentType();

        // If file is an image, pass through image preprocessor
        byte[] effectiveContent = rawContent;
        if (mimeType != null && mimeType.startsWith("image/")) {
            effectiveContent = imagePreprocessor.preprocess(rawContent, filterMode);
            log.info("Preprocessed image: original {} bytes -> enhanced {} bytes", rawContent.length, effectiveContent.length);
        }

        OcrService.ExtractedDocumentData result = ocrService.analyzeDocument(effectiveContent, filename, mimeType);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /**
     * Health/Capability check for Document OCR Service.
     */
    @GetMapping("/ocr/status")
    public ResponseEntity<ApiResponse<Object>> getOcrStatus() {
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "status", "ACTIVE",
                "engine", "CrimeNet Adaptive Preprocessor + PDFBox Legal Entity Extractor",
                "supportedFilterModes", List.of("AUTO_ENHANCE", "GRAYSCALE", "BLACK_AND_WHITE", "COLOR_ORIGINAL"),
                "supportedFormats", List.of("application/pdf", "image/jpeg", "image/png", "text/plain"),
                "statutoryCompliance", "BSA 2023 §65B Admissible"
        )));
    }
}
