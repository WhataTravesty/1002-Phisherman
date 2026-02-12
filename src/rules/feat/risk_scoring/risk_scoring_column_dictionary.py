from src.rules.feat.Keyword import analyze_email, boolean_result

#This dictionary is a template for the function to one shot append all the functions' output into the dataframe
#It is structured as Column Name(key):[Reference Column, Function to run]
#Feel Free to add in your own functions and columns according to the template
#remember to import your functions first.
COLUMN_DICTIONARY = {
    "Keyword Score":["email",analyze_email],
    "Keyword Boolean":["Keyword Score",boolean_result]
    }