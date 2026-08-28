SUCCESS_MARKERS = (
    "root:x:", "uid=", "command output", "internal metadata", "169.254.169.254",
    "private key", "password hash", "shell executed", "file read",
)


def classify_success(
    malicious: bool,
    status_code: int | None,
    response_size: int | None = None,
    explicit_ground_truth: bool = False,
    response_body: str | None = None,
    follow_up_evidence: list[str] | None = None,
) -> tuple[str, str]:
    if not malicious:
        return "BENIGN", "No sufficiently strong suspicious indicators were found."
    if explicit_ground_truth:
        return "CONFIRMED_SUCCESS", "The imported record contains explicit ground-truth success evidence."
    if status_code in {401, 403, 407, 429}:
        return "ATTEMPT", f"The suspicious request was blocked or rejected with HTTP {status_code}."
    body = str(response_body or "").lower()
    markers = [marker for marker in SUCCESS_MARKERS if marker in body]
    follow_up = [str(item) for item in (follow_up_evidence or []) if str(item).strip()]
    if markers or follow_up:
        evidence = ", ".join(markers or follow_up[:2])
        return "CONFIRMED_SUCCESS", f"Corroborating post-request evidence was observed: {evidence}."
    # Success is only probable when response characteristics add evidence; 200 alone is never enough.
    if status_code in {200, 201, 202} and response_size is not None and response_size > 75000:
        return "PROBABLE_SUCCESS", "The suspicious request received an unusually large successful response; this is suggestive, not proof."
    return "ATTEMPT", "Suspicious traffic was detected, but the response does not prove that exploitation succeeded."
