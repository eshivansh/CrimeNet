package com.crimenet.search;

import java.util.UUID;

public record SearchResponseDto(
        UUID documentId,
        UUID caseId,
        String hash,
        float score
) {}
