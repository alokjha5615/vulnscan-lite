def calculate_final_score(modules: list) -> dict:
    """
    Combine module score deltas into a final 0-100 score.
    """
    base_score = 50
    total_delta = sum(module.get("score_delta", 0) for module in modules)
    final_score = max(0, min(100, base_score + total_delta))

    if final_score >= 90:
        grade = "A+"
    elif final_score >= 80:
        grade = "A"
    elif final_score >= 70:
        grade = "B+"
    elif final_score >= 60:
        grade = "B"
    elif final_score >= 50:
        grade = "C"
    elif final_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": final_score,
        "grade": grade
    }