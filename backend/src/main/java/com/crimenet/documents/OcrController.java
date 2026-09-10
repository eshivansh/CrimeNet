package com.crimenet.documents;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Slf4j
@RestController
@RequestMapping("/api/v1/documents")
@RequiredArgsConstructor
public class OcrController {

    private final OcrService ocrService;

    /**
     * Analyze and extract text and structured legal entities from an uploaded document (PDF/Image).
     */
    @PostMapping(value = "/ocr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<OcrService.ExtractedDocumentData>> processOcr(
            @RequestParam("file") MultipartFile file) throws IOException {
        log.info("Processing OCR request for file: {} ({} bytes, MIME: {})",
                file.getOriginalFilename(), file.getSize(), file.getContentType());

        byte[] content = file.getBytes();
        String filename = file.getOriginalFilename();
        String mimeType = file.getContentType();

        OcrService.ExtractedDocumentData result = ocrService.analyzeDocument(content, filename, mimeType);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /**
     * Health/Capability check for Document OCR Service.
     */
    @GetMapping("/ocr/status")
    public ResponseEntity<ApiResponse<Object>> getOcrStatus() {
        return ResponseEntity.ok(ApiResponse.ok(java.util.Map.of(
                "status", "ACTIVE",
                "engine", "Apache PDFBox + Rule-Based Legal Entity Extractor",
                "supportedFormats", java.util.List.of("application/pdf", "image/jpeg", "image/png", "text/plain"),
                "statutoryCompliance", "BSA 2023 §65B Admissible"
        )));
    }
}
