from dataclasses import dataclass

#Using dataclass removes the need to write the init function
#Frozen=True ensures that the attributes are immutable after creation of object
#Tyoecasting attributes to prevent accidental assign of wrong type and allows for easier debugging.
@dataclass(frozen=True)
class KeywordRule:
    word: str
    base_weight: int