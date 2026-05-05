from flask import Flask, render_template, request, redirect, session, Response
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
    error = request.args.get("error")
    success = request.args.get("success")
    
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = auth.login(email, password)

        if user:
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["master"] = password
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Wrong email or password.", view="login")

    return render_template("login.html", error=error, success=success, view="login")


# -------------------------
@app.route("/register", methods=["POST"])
def register():
    email = request.form["email"]
    password = request.form["password"]
    
    try:
        auth.register(email, password)
        return redirect("/?success=Registered successfully! Please login.")
    except ValueError as e:
        # Check if it's the "Email already registered" error
        return render_template("login.html", error=str(e), view="register")


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
            "email": request.form["email"],
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
@app.route("/export", methods=["POST"])
def export():
    if "user_id" not in session:
        return redirect("/")
    
    password = request.form["password"]
    fmt = request.form["format"] # "encrypted" or "plain"

    # Verify password
    user_data = auth.login(session["email"], password)
    if not user_data:
        return render_template("settings.html", error="Invalid Master Password. Export denied.")

    if fmt == "plain":
        data = vault.export_vault_plain(session["user_id"], password)
        filename = "vault_plain_text.json"
    else:
        data = vault.export_vault(session["user_id"])
        filename = "vault_encrypted_backup.json"
    
    db.log_security_event(session["user_id"], "export")

    return Response(
        data,
        mimetype="application/json",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )


# -------------------------
@app.route("/import", methods=["POST"])
def import_vault():
    if "user_id" not in session:
        return redirect("/")

    file = request.files["file"]
    if not file.filename.endswith(".json"):
        return render_template("settings.html", error="Only .json files are allowed for import.")

    content = file.read().decode()
    try:
        vault.import_vault(session["user_id"], content)
        return redirect("/dashboard")
    except Exception:
        return render_template("settings.html", error="Import failed. Invalid file format.")


# -------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# -------------------------
if __name__ == "__main__":
    app.run(debug=True)