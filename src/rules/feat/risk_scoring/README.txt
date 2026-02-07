Please add an __init__.py file in each of the function folders. E.g. src/rules/feat/Keyword/__init__.py
inside this file, write the final functions that you want to import to be used inside the risk_scoring python file.
For example, my (analyze_email, boolean_result) functions will be used to return the output to store in the data frame, so i will import it in the format from .keywordDetection import analyze_email, boolean_result
This is so that you can import these functions in sister or parent directories.
in the risk_scoring_column_dictionary.py file, import the same functions.
Then, follow the given template to add your stuff into COLUMN_DICTIONARY