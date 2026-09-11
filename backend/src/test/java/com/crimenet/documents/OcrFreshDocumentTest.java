package com.crimenet.documents;

import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class OcrFreshDocumentTest {

    @Test
    public void testOcrWithFreshSampleDocument() throws Exception {
        // Create a brand new fresh sample legal notice PDF
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document pdfDoc = new Document();
        PdfWriter.getInstance(pdfDoc, baos);
        pdfDoc.open();
        pdfDoc.add(new Paragraph("SPECIAL INVESTIGATION TEAM (SIT) NOTICE"));
        pdfDoc.add(new Paragraph("Notice No: SIT-NOTICE-2026-9912"));
        pdfDoc.add(new Paragraph("Date of Issue: 11 September 2026"));
        pdfDoc.add(new Paragraph("Subject: Production of digital evidence under Section 94 BNSS"));
        pdfDoc.add(new Paragraph("Investigating Agency: Uttar Pradesh Cyber Crime Directorate"));
        pdfDoc.add(new Paragraph("Suspect Account: ACC-99410-CYBER"));
        pdfDoc.close();

        byte[] pdfBytes = baos.toByteArray();
        assertTrue(pdfBytes.length > 0, "PDF bytes should not be empty");

        // Run OCR text extraction
        OcrService ocrService = new OcrService();
        OcrService.ExtractedDocumentData result = ocrService.analyzeDocument(pdfBytes, "SIT_Notice_Sample.pdf", "application/pdf");

        assertNotNull(result, "OCR result must not be null");
        assertNotNull(result.getRawText(), "Raw text must not be null");
        assertTrue(result.getRawText().contains("SPECIAL INVESTIGATION TEAM"), "Must extract header");
        assertTrue(result.getRawText().contains("SIT-NOTICE-2026-9912"), "Must extract notice ID");
        assertTrue(result.getRawText().contains("Section 94 BNSS"), "Must extract statutory section");
        assertNotNull(result.getSha256Hash(), "Must compute SHA-256 hash");

        System.out.println("FRESH OCR TEST PASSED:");
        System.out.println("Extracted text snippet:\n" + result.getRawText().trim());
        System.out.println("Document Hash: " + result.getSha256Hash());
    }
}
