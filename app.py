# from flask import Flask, render_template, request, redirect, url_for
# import os
# import pandas as pd
# from werkzeug.utils import secure_filename

# from src.scoring import score_dataset
# from src.dashboard import build_dashboard_data

# app = Flask(__name__)
# app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# INPUT_FOLDER = os.path.join(BASE_DIR, "input")
# OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
# os.makedirs(INPUT_FOLDER, exist_ok=True)
# os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# app.config["INPUT_FOLDER"] = INPUT_FOLDER
# app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER


# @app.route("/")
# def index():
#     return render_template("index.html", hide_dashboard=True)


# @app.route("/upload", methods=["POST"])
# def upload():
#     f = request.files.get("dataset")
#     if not f or f.filename.strip() == "":
#         return render_template("index.html", error="No file uploaded.")

#     if not f.filename.lower().endswith(".csv"):
#         return render_template("index.html", error="Only CSV files are supported.")

#     filename = secure_filename(f.filename)
#     input_path = os.path.join(app.config["INPUT_FOLDER"], filename)

#     try:
#         f.save(input_path)
#         df = pd.read_csv(input_path)
#     except Exception as e:
#         return render_template("index.html", error=f"Could not read CSV: {e}")

#     scored_df = score_dataset(df)

#     out_path = os.path.join(app.config["OUTPUT_FOLDER"], "latest_scored.csv")
#     scored_df.to_csv(out_path, index=False)

#     return redirect(url_for("dashboard"))


# @app.route("/dashboard")
# def dashboard():
#     path = os.path.join(app.config["OUTPUT_FOLDER"], "latest_scored.csv")
#     if not os.path.exists(path):
#         return render_template("dashboard.html", empty=True)

#     df = pd.read_csv(path)
#     data = build_dashboard_data(df)
#     return render_template("dashboard.html", **data)


# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash
import os
import pandas as pd
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
import os
from dotenv import load_dotenv

load_dotenv()
print(os.getenv("ADMIN_USER"))

from src.scoring import score_dataset
from src.dashboard import build_dashboard_data

app = Flask(__name__)

# IMPORTANT: Needed for sessions (Flask-Login uses sessions)
app.secret_key = os.getenv("SECRET_KEY")

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PW_HASH")

app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_FOLDER = os.path.join(BASE_DIR, "input")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
os.makedirs(INPUT_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config["INPUT_FOLDER"] = INPUT_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER

# -------------------- AUTH SETUP --------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Single-admin credentials
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PW_HASH = os.getenv("ADMIN_PW_HASH")  # using werkzeug hash string


class User(UserMixin):
    def __init__(self, user_id: str):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id: str):
    if user_id == ADMIN_USER:
        return User(user_id)
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in? go home
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not ADMIN_PW_HASH:
            flash("ADMIN_PW_HASH not configured in environment.", "danger")
            return redirect(url_for("login"))

        if username == ADMIN_USER and check_password_hash(ADMIN_PW_HASH, password):
            login_user(User(username))
            return redirect(url_for("index"))

        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -------------------- YOUR ROUTES --------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", hide_dashboard=True)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("dataset")
    if not f or f.filename.strip() == "":
        return render_template("index.html", error="No file uploaded.")

    if not f.filename.lower().endswith(".csv"):
        return render_template("index.html", error="Only CSV files are supported.")

    filename = secure_filename(f.filename)
    input_path = os.path.join(app.config["INPUT_FOLDER"], filename)

    try:
        f.save(input_path)
        df = pd.read_csv(input_path)
    except Exception as e:
        return render_template("index.html", error=f"Could not read CSV: {e}")

    scored_df = score_dataset(df)

    out_path = os.path.join(app.config["OUTPUT_FOLDER"], "latest_scored.csv")
    scored_df.to_csv(out_path, index=False)

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    path = os.path.join(app.config["OUTPUT_FOLDER"], "latest_scored.csv")
    if not os.path.exists(path):
        return render_template("dashboard.html", empty=True)

    df = pd.read_csv(path)
    data = build_dashboard_data(df)
    return render_template("dashboard.html", **data)


if __name__ == "__main__":
    app.run(debug=True)