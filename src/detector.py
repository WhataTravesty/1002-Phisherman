from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import pandas as pd

app = Flask(__name__)
app.config["INPUT_FOLDER"] = "./uploads"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_dataset():
    file = request.files.get("dataset")
    if not file or file.filename.strip() == "":
        return render_template("results.html", error="No file uploaded.")

    if not file.filename.lower().endswith(".csv"):
        return render_template("results.html", error="Only .csv files are supported.")

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["INPUT_FOLDER"], filename)

    try:
        file.save(input_path)
        df = pd.read_csv(input_path)
    except Exception as e:
        return render_template("results.html", error=f"Could not process CSV: {e}")

    # Remove raw columns for now
    df = df.loc[:, [c for c in df.columns if not c.endswith("_raw")]]

    return render_template(
        "results.html",
        input_file=filename,
        row_count=len(df),
        column_count=len(df.columns),
        columns=list(df.columns)
    )
