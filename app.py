from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import os
from werkzeug.utils import secure_filename

from src.dashboard import build_dashboard_data

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB upload limit
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FOLDER = os.path.join(BASE_DIR, "input")
os.makedirs(INPUT_FOLDER, exist_ok=True)
app.config["INPUT_FOLDER"] = INPUT_FOLDER

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    data = build_dashboard_data()
    return render_template("dashboard.html", **data)


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
    df = df.loc[:, [c for c in df.columns if not str(c).endswith("_raw")]]

    return render_template(
        "results.html",
        input_file=filename,
        row_count=len(df),
        column_count=len(df.columns),
        columns=list(df.columns)
    )


if __name__ == "__main__":
    app.run(debug=True)