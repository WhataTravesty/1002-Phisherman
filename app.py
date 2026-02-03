from flask import Flask, render_template
from src.dashboard import build_dashboard_data

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    data = build_dashboard_data()
    return render_template("dashboard.html", **data)

if __name__ == "__main__":
    app.run(debug=True)
