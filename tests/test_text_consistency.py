from app.services.text_consistency import TextConsistencyChecker


def test_strong_match() -> None:
    result = TextConsistencyChecker().compare(
        "BitCheck Certificate of Completion issued to Ada Lovelace",
        "bitcheck certificate of completion issued to ada lovelace",
    )

    assert result.status == "strong_match"
    assert result.similarity_score >= 0.85
    assert result.risk_score == 0.05


def test_partial_match() -> None:
    result = TextConsistencyChecker().compare(
        "BitCheck certificate issued to Ada Lovelace for document verification",
        "BitCheck certificate issued to Grace Hopper for document review",
    )

    assert result.status == "partial_match"
    assert 0.60 <= result.similarity_score < 0.85
    assert result.risk_score == 0.35


def test_low_match() -> None:
    result = TextConsistencyChecker().compare(
        "University transcript for Ada Lovelace",
        "Invoice payment receipt for office furniture",
    )

    assert result.status == "low_match"
    assert result.similarity_score < 0.60
    assert result.risk_score == 0.70


def test_no_text_to_compare() -> None:
    result = TextConsistencyChecker().compare("", "visible text")

    assert result.status == "no_text_to_compare"
    assert result.similarity_score == 0.0
    assert result.risk_score == 0.0
