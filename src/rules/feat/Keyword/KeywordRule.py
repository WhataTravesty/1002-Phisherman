from dataclasses import dataclass

@dataclass(frozen=True)
class KeywordRule:
    word: str
    base_weight: int