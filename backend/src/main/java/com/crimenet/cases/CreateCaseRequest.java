package com.crimenet.cases;

import jakarta.validation.constraints.NotBlank;

public record CreateCaseRequest(
        @NotBlank(message = "Title is required")
        String title,
        String description,
        String firId,
        String classification
) {}
