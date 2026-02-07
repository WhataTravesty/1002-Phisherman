import pandas as pd
from .risk_scoring_column_dictionary import COLUMN_DICTIONARY

#Takes an existing DataFrame, and adds new columns and corresponding data, according to the COLUMN_DICTIONARY set in risk_scoring_column_dictionary.py
def append_results_to_dataframe(df: pd.DataFrame, columns: dict = COLUMN_DICTIONARY):
    for column in columns.items():
        df[column[0]]=df[column[1][0]].apply(column[1][1])
    return df