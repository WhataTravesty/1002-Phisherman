import csv

#Takes in a list of dictionaries and writes in string to a txt file
def outputScoring(result, filename):
    fieldnames = result[0].keys()
    with open(filename,"w") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        # Create a DictWriter object
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        # Write the header row
        writer.writeheader()

        # Write the data rows
        writer.writerows(result)