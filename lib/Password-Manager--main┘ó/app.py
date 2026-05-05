from flask import Flask, render_template, request, redirect, session
import random
import string

from backend.services.auth import AuthService
from backend.services.vault import VaultService
from backend.db.manager import DatabaseManager
from backend.core.crypto import CryptoManager

app = Flask(__name__)
app.secret_key = "secret123"

db = DatabaseManager()
crypto = CryptoManager()
auth = AuthService(db, crypto)
vault = VaultService(db, crypto)

# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = auth.login(email, password)

        if user:
            session["user_id"] = user["id"]
            session["master"] = password
            return redirect("/dashboard")
        else:
            return "Wrong login"

    return render_template("login.html")


# -------------------------
@app.route("/register", methods=["POST"])
def register():
    auth.register(request.form["email"], request.form["password"])
    return redirect("/")


# -------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    data = vault.get_items(session["user_id"], session["master"])
    return render_template("dashboard.html", data=data)


# -------------------------
@app.route("/add", methods=["GET", "POST"])
def add():
    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":
        item = {
            "name": request.form["name"],
            "url": request.form["url"],
            "username": request.form["username"],
            "password": request.form["password"]
        }

        vault.add_item(session["user_id"], session["master"], item)
        return redirect("/dashboard")

    return render_template("add.html")


# -------------------------
@app.route("/generate", methods=["GET", "POST"])
def generate():
    password = None

    if request.method == "POST":
        length = int(request.form["length"])

        chars = ""
        if "upper" in request.form:
            chars += string.ascii_uppercase
        if "lower" in request.form:
            chars += string.ascii_lowercase
        if "numbers" in request.form:
            chars += string.digits
        if "symbols" in request.form:
            chars += "!@#$%"

        if chars == "":
            chars = string.ascii_letters

        password = "".join(random.choice(chars) for _ in range(length))

    return render_template("generate.html", password=password)


# -------------------------
@app.route("/delete/<int:item_id>")
def delete(item_id):
    vault.delete_item(session["user_id"], item_id)
    return redirect("/dashboard")


# -------------------------
@app.route("/settings")
def settings():
    return render_template("settings.html")


# -------------------------
@app.route("/export")
def export():
    data = vault.export_vault(session["user_id"])
    return data


# -------------------------
@app.route("/import", methods=["POST"])
def import_vault():
    file = request.files["file"]
    content = file.read().decode()
    vault.import_vault(session["user_id"], content)
    return redirect("/dashboard")


# -------------------------
if __name__ == "__main__":
    app.run(debug=True)