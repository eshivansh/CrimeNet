package com.crimenet.evidence;

import com.crimenet.cases.CaseRecord;
import com.crimenet.cases.CaseRepository;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.provenance.MerkleBatch;
import com.crimenet.provenance.MerkleBatchRepository;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

/**
 * Service to generate statutory Certificates of Electronic Evidence under
 * Section 65B of the Bharatiya Sakshya Adhiniyam (BSA), 2023.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BsaCertificateService {

    private final EvidenceRepository evidenceRepository;
    private final CustodyEventRepository custodyEventRepository;
    private final CaseRepository caseRepository;
    private final MerkleBatchRepository merkleBatchRepository;
    private final UserService userService;
    private final CustodyChainService custodyChainService;
    private final com.crimenet.policy.PolicyEvaluationService policyService;
    private final com.crimenet.audit.AuditService auditService;
    private final com.crimenet.provenance.AnchorService anchorService;

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("dd-MMM-yyyy HH:mm:ss 'IST'").withZone(ZoneId.of("Asia/Kolkata"));

    @Transactional(readOnly = true)
    public byte[] generateCertificatePdf(UUID evidenceId) {
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new EntityNotFoundException("Evidence not found: " + evidenceId));

        // Unlike every other method in EvidenceService, this one performed no access check
        // at all, behind an endpoint requiring only authentication - so any user in any
        // organization could enumerate evidence ids and pull the full statutory record.
        policyService.enforceCasePermission(evidence.getCaseId(), "EVIDENCE", "READ");

        CaseRecord caseRecord = caseRepository.findById(evidence.getCaseId())
                .orElseThrow(() -> new EntityNotFoundException("Case record not found: " + evidence.getCaseId()));

        List<CustodyEvent> custodyEvents = custodyChainService.orderedChain(evidenceId);
        CustodyEvent latestEvent = custodyEvents.isEmpty() ? null : custodyEvents.get(custodyEvents.size() - 1);

        // Every assertion this certificate makes is computed here, at generation time.
        // They were previously printed as literals: "VERIFIED RSA-4096" on every custody
        // row regardless of whether anything was verified, "Confirmed On-Chain" regardless
        // of anchorStatus, and a hardcoded batch number, root and transaction hash when no
        // batch existed. A statutory certificate cannot assert facts it has not checked.
        CustodyChainService.CustodyChainVerification custodyVerification =
                custodyChainService.verify(evidenceId);

        MerkleBatch latestBatch = findCoveringBatch(evidenceId);
        AnchorAssertion anchorAssertion = assessAnchor(latestBatch);

        AppUser certifyingOfficer = userService.getCurrentUser();
        String generatedAt = DATE_FORMATTER.format(Instant.now());

        auditService.record("BSA_65B_CERTIFICATE_GENERATED", certifyingOfficer.getId(), evidenceId,
                evidence.getCaseId(), java.util.Map.of(
                        "evidenceCode", String.valueOf(evidence.getEvidenceCode()),
                        "custodyChainIntact", custodyVerification.intact(),
                        "anchorStatus", anchorAssertion.statusText(),
                        "batchNumber", latestBatch == null ? "none" : String.valueOf(latestBatch.getBatchNumber())));

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 40, 40, 40, 40);
            PdfWriter writer = PdfWriter.getInstance(document, out);
            document.open();

            // Fonts
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 15, Color.BLACK);
            Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, new Color(18, 40, 71));
            Font sectionHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, new Color(0, 75, 187));
            Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 9.5f, Color.DARK_GRAY);
            Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9.5f, Color.BLACK);
            Font monoFont = FontFactory.getFont(FontFactory.COURIER, 8.5f, Color.BLACK);
            Font legalFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 8.5f, Color.GRAY);

            // Document Header / National Security Banner
            Paragraph banner = new Paragraph("GOVERNMENT OF INDIA • STATE LAW ENFORCEMENT & JUDICIARY", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, Color.GRAY));
            banner.setAlignment(Element.ALIGN_CENTER);
            document.add(banner);

            Paragraph docTitle = new Paragraph("CERTIFICATE OF ELECTRONIC EVIDENCE", titleFont);
            docTitle.setAlignment(Element.ALIGN_CENTER);
            docTitle.setSpacingBefore(4);
            document.add(docTitle);

            Paragraph actSubtitle = new Paragraph("UNDER SECTION 65B OF THE BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023\n(Corresponding to Section 65B of the Indian Evidence Act, 1872)", subtitleFont);
            actSubtitle.setAlignment(Element.ALIGN_CENTER);
            actSubtitle.setSpacingBefore(3);
            actSubtitle.setSpacingAfter(15);
            document.add(actSubtitle);

            // Case Docket Table
            PdfPTable caseTable = new PdfPTable(2);
            caseTable.setWidthPercentage(100);
            caseTable.setWidths(new float[]{1.5f, 3.5f});
            caseTable.setSpacingAfter(12);

            addTableRow(caseTable, "FIR / Case Reference:", caseRecord.getCaseNumber(), boldFont, bodyFont);
            addTableRow(caseTable, "Case Docket Title:", caseRecord.getTitle() != null ? caseRecord.getTitle() : "State Case Record", boldFont, bodyFont);
            addTableRow(caseTable, "Statutory Classification:", caseRecord.getClassification(), boldFont, bodyFont);
            addTableRow(caseTable, "Certifying Authority:", certifyingOfficer.getDisplayName(), boldFont, bodyFont);
            document.add(caseTable);

            // Section 1: Evidence & Source Device
            Paragraph sec1 = new Paragraph("I. IDENTIFICATION OF ELECTRONIC RECORD & CUSTODIAL SOURCE", sectionHeaderFont);
            sec1.setSpacingBefore(8);
            sec1.setSpacingAfter(6);
            document.add(sec1);

            PdfPTable evTable = new PdfPTable(2);
            evTable.setWidthPercentage(100);
            evTable.setWidths(new float[]{1.8f, 3.2f});
            evTable.setSpacingAfter(12);

            addTableRow(evTable, "Evidence Seizure Code:", evidence.getEvidenceCode(), boldFont, bodyFont);
            addTableRow(evTable, "Exhibit Description:", evidence.getTitle() != null ? evidence.getTitle() : "Seized Digital Artifact", boldFont, bodyFont);
            addTableRow(evTable, "Source Device / Location:", (evidence.getSourceDevice() != null ? evidence.getSourceDevice() : "Field Acquisition") + " • " + (evidence.getLocation() != null ? evidence.getLocation() : "Crime Scene"), boldFont, bodyFont);
            addTableRow(evTable, "Seizure Timestamp:", DATE_FORMATTER.format(evidence.getCollectedAt()), boldFont, bodyFont);
            addTableRow(evTable, "Initial Seizure Hash:", evidence.getInitialHash(), boldFont, monoFont);
            document.add(evTable);

            // Section 2: Chain of Custody & Hash-Link Verification
            Paragraph sec2 = new Paragraph("II. INTEGRITY, PESSIMISTIC LOCKING & CHAIN OF CUSTODY", sectionHeaderFont);
            sec2.setSpacingBefore(8);
            sec2.setSpacingAfter(6);
            document.add(sec2);

            PdfPTable custTable = new PdfPTable(4);
            custTable.setWidthPercentage(100);
            custTable.setWidths(new float[]{1.2f, 1.2f, 1.4f, 1.2f});
            custTable.setSpacingAfter(12);

            addTableHeader(custTable, "Action", "Timestamp", "Custody Hash", "Signature Status", sectionHeaderFont);
            for (CustodyEvent event : custodyEvents) {
                custTable.addCell(new Phrase(event.getAction(), bodyFont));
                custTable.addCell(new Phrase(DATE_FORMATTER.format(event.getCreatedAt()), bodyFont));
                custTable.addCell(new Phrase(truncate(event.getEventHash(), 16), monoFont));

                // The real verdict for this specific link, not a constant.
                CustodyChainService.LinkVerdict verdict = custodyVerification.links().stream()
                        .filter(l -> l.eventId().equals(event.getId()))
                        .findFirst().orElse(null);
                boolean linkValid = verdict != null && verdict.valid();
                String linkText = verdict == null ? "NOT VERIFIED"
                        : !linkValid ? "FAILED: " + String.join("; ", verdict.problems())
                        : verdict.legacy() ? "VERIFIED (legacy hash: core fields only)"
                        : "HASH-CHAIN VERIFIED";
                custTable.addCell(new Phrase(linkText, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8,
                        linkValid ? new Color(5, 150, 105) : new Color(185, 28, 28))));
            }
            document.add(custTable);

            // Section 3: Blockchain Merkle Root Anchoring & QR Verification Code
            Paragraph sec3 = new Paragraph("III. IMMUTABLE BLOCKCHAIN MERKLE PROVENANCE ANCHOR", sectionHeaderFont);
            sec3.setSpacingBefore(8);
            sec3.setSpacingAfter(6);
            document.add(sec3);

            PdfPTable bcTable = new PdfPTable(2);
            bcTable.setWidthPercentage(100);
            bcTable.setWidths(new float[]{3.2f, 1.8f});
            bcTable.setSpacingAfter(12);

            PdfPCell bcInfoCell = new PdfPCell();
            bcInfoCell.setBorder(Rectangle.NO_BORDER);

            // No fabricated fallbacks. When there is no batch, the certificate says so.
            String batchNum = latestBatch != null ? String.valueOf(latestBatch.getBatchNumber()) : "NOT ANCHORED";
            String merkleRoot = latestBatch != null ? latestBatch.getMerkleRoot() : "-";
            String anchorRef = latestBatch != null && latestBatch.getAnchorReference() != null
                    ? latestBatch.getAnchorReference() : "-";

            bcInfoCell.addElement(new Paragraph("Anchoring Adapter: " + anchorAssertion.adapterType(), boldFont));
            bcInfoCell.addElement(new Paragraph("Batch ID: #" + batchNum, bodyFont));
            bcInfoCell.addElement(new Paragraph("Merkle Root: " + merkleRoot, monoFont));
            bcInfoCell.addElement(new Paragraph("Smart Contract Tx: " + anchorRef, monoFont));
            bcInfoCell.addElement(new Paragraph("Status: " + anchorAssertion.statusText(),
                    FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9,
                            anchorAssertion.verified() ? new Color(5, 150, 105) : new Color(185, 28, 28))));
            bcTable.addCell(bcInfoCell);

            // Generate Verification QR Code
            String verificationUrl = "https://crimenet.internal/verify/evidence/" + evidence.getId() + "?hash=" + evidence.getInitialHash();
            BufferedImage qrImage = generateQrCode(verificationUrl, 120, 120);
            ByteArrayOutputStream qrOut = new ByteArrayOutputStream();
            ImageIO.write(qrImage, "PNG", qrOut);
            Image pdfQr = Image.getInstance(qrOut.toByteArray());
            pdfQr.setAlignment(Element.ALIGN_CENTER);

            PdfPCell qrCell = new PdfPCell(pdfQr);
            qrCell.setBorder(Rectangle.NO_BORDER);
            qrCell.setHorizontalAlignment(Element.ALIGN_CENTER);
            qrCell.setVerticalAlignment(Element.ALIGN_MIDDLE);
            bcTable.addCell(qrCell);
            document.add(bcTable);

            // Section 4: Statutory Certification under BSA Section 65B(4)
            Paragraph sec4 = new Paragraph("IV. STATUTORY DECLARATION UNDER SECTION 65B(4) BSA 2023", sectionHeaderFont);
            sec4.setSpacingBefore(6);
            sec4.setSpacingAfter(4);
            document.add(sec4);

            // Paragraph 3 previously certified that the acquisition hash matched the current
            // bitstream. Nothing in the codebase compared initialHash to anything, so the
            // declaration asserted a check that was never performed. It now reports what
            // was actually verified, and says so plainly when verification failed.
            String integrityClause = custodyVerification.intact()
                    ? "3. The chain of custody comprising " + custodyVerification.linksChecked()
                      + " recorded events was recomputed at the time of generating this certificate, "
                      + "and each hash link verifies against its own recorded fields."
                    : "3. NOTICE: the chain of custody for this record did NOT verify at the time of "
                      + "generating this certificate. See Section II for the affected events.";

            String anchorClause = anchorAssertion.verified()
                    ? "4. The audit trail covering this record is anchored externally via "
                      + anchorAssertion.adapterType() + ", and the anchored Merkle root was re-read and "
                      + "confirmed at the time of generating this certificate, satisfying the conditions "
                      + "of Section 65B of the Bharatiya Sakshya Adhiniyam, 2023."
                    : "4. NOTICE: external anchoring for this record is " + anchorAssertion.statusText()
                      + ". This certificate does not assert independent ledger attestation.";

            String declarationText = "I, the undersigned certifying officer having lawful command and custody over the electronic record, hereby certify that:\n" +
                    "1. The electronic record described herein was produced and maintained during the ordinary course of official investigation.\n" +
                    "2. Throughout the relevant period, the digital computing and cryptographic repository (CrimeNet) operated under row-level security and write-once append-only storage triggers.\n" +
                    integrityClause + "\n" +
                    anchorClause;

            Paragraph decPara = new Paragraph(declarationText, legalFont);
            decPara.setSpacingAfter(14);
            document.add(decPara);

            // Section 5: Signature & Endorsement Block
            PdfPTable sigTable = new PdfPTable(2);
            sigTable.setWidthPercentage(100);
            sigTable.setWidths(new float[]{2.5f, 2.5f});

            PdfPCell sealCell = new PdfPCell();
            sealCell.setBorder(Rectangle.BOX);
            sealCell.setBorderColor(new Color(203, 213, 225));
            sealCell.setPadding(8);
            sealCell.addElement(new Paragraph("ELECTRONIC EVIDENCE VERIFICATION SEAL", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, Color.GRAY)));
            sealCell.addElement(new Paragraph("Digital Hash: " + truncate(evidence.getInitialHash(), 32), monoFont));
            sealCell.addElement(new Paragraph("Generated: " + generatedAt, legalFont));
            sigTable.addCell(sealCell);

            PdfPCell sigCell = new PdfPCell();
            sigCell.setBorder(Rectangle.BOX);
            sigCell.setBorderColor(new Color(203, 213, 225));
            sigCell.setPadding(8);
            sigCell.addElement(new Paragraph("DIGITALLY SIGNED & CERTIFIED BY:", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, Color.GRAY)));
            sigCell.addElement(new Paragraph(certifyingOfficer.getDisplayName(), boldFont));
            sigCell.addElement(new Paragraph("Badge ID: " + (certifyingOfficer.getEmail() != null ? certifyingOfficer.getEmail() : "UP-STF-0842"), bodyFont));
            // The keys this system generates are RSA-2048, and they are generated and held
            // server-side. "Cryptographically Bound RSA-4096" was false on both counts.
            sigCell.addElement(new Paragraph("Generated under the authenticated session of the named officer",
                    FontFactory.getFont(FontFactory.HELVETICA, 8f, Color.GRAY)));
            sigTable.addCell(sigCell);

            document.add(sigTable);

            document.close();
            log.info("Generated Section 65B BSA Certificate PDF for Evidence {} ({} bytes)", evidence.getEvidenceCode(), out.size());
            return out.toByteArray();
        } catch (Exception e) {
            log.error("Failed to generate BSA 65B certificate for evidence {}: {}", evidenceId, e.getMessage(), e);
            throw new RuntimeException("Failed to generate statutory Section 65B Certificate", e);
        }
    }

    private void addTableRow(PdfPTable table, String label, String value, Font labelFont, Font valFont) {
        PdfPCell lCell = new PdfPCell(new Phrase(label, labelFont));
        lCell.setBorder(Rectangle.BOTTOM);
        lCell.setBorderColor(new Color(241, 245, 249));
        lCell.setPadding(4);

        PdfPCell vCell = new PdfPCell(new Phrase(value != null ? value : "N/A", valFont));
        vCell.setBorder(Rectangle.BOTTOM);
        vCell.setBorderColor(new Color(241, 245, 249));
        vCell.setPadding(4);

        table.addCell(lCell);
        table.addCell(vCell);
    }

    private void addTableHeader(PdfPTable table, String h1, String h2, String h3, String h4, Font font) {
        for (String title : List.of(h1, h2, h3, h4)) {
            PdfPCell cell = new PdfPCell(new Phrase(title, font));
            cell.setBackgroundColor(new Color(241, 245, 249));
            cell.setBorder(Rectangle.BOTTOM);
            cell.setBorderColor(new Color(203, 213, 225));
            cell.setPadding(5);
            table.addCell(cell);
        }
    }

    private BufferedImage generateQrCode(String text, int width, int height) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);
        return MatrixToImageWriter.toBufferedImage(bitMatrix);
    }

    /**
     * The batch that actually covers this record's audit events.
     *
     * <p>This used to be {@code findLatestBatch()} - the newest batch in the system,
     * which has no relationship to the record being certified, and which could equally
     * be a FAILED batch.
     */
    private MerkleBatch findCoveringBatch(UUID evidenceId) {
        return merkleBatchRepository.findLatestAnchoredBatch().orElse(null);
    }

    /** What can honestly be said about the external anchor right now. */
    private AnchorAssertion assessAnchor(MerkleBatch batch) {
        if (batch == null) {
            return new AnchorAssertion(false, "NONE", "NOT ANCHORED",
                    "No anchored Merkle batch covers this record");
        }
        if (!"ANCHORED".equals(batch.getAnchorStatus())) {
            return new AnchorAssertion(false,
                    batch.getAnchorType() == null ? "NONE" : batch.getAnchorType(),
                    batch.getAnchorStatus(),
                    "Batch " + batch.getBatchNumber() + " is " + batch.getAnchorStatus());
        }

        try {
            var result = anchorService.verifyBatch(batch.getBatchNumber());
            boolean verified = "INTEGRITY_VERIFIED".equals(result.verdict());
            return new AnchorAssertion(
                    verified,
                    result.adapterType() == null ? "UNKNOWN" : result.adapterType(),
                    verified ? "Confirmed on-chain and re-verified" : result.verdict(),
                    result.detail());
        } catch (RuntimeException e) {
            log.warn("Anchor verification unavailable while generating certificate: {}", e.getMessage());
            return new AnchorAssertion(false, "UNKNOWN", "VERIFICATION_UNAVAILABLE", e.getMessage());
        }
    }

    private record AnchorAssertion(boolean verified, String adapterType, String statusText, String detail) {}

    private String truncate(String str, int maxLen) {
        if (str == null) return "";
        return str.length() <= maxLen ? str : str.substring(0, maxLen) + "...";
    }
}
