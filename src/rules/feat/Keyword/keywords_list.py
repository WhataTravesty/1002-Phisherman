from .KeywordRule import KeywordRule

#To make the variable accessable even if inside a function, no need to load and unload Ruleset during batch processing
global KEYWORDS

#Each word stores its own object containing its word and its weightage.
KEYWORDS = {
"password": KeywordRule("password", 3),
"urgent": KeywordRule("urgent", 2),
"bank": KeywordRule("bank", 4),
"verify": KeywordRule("verify", 2),
"click": KeywordRule("click", 1),}