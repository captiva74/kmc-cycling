import csv
import os
import smtplib
from email.message import EmailMessage
from functools import wraps
from io import BytesIO, StringIO

import gpxpy
import pandas as pd
import sqlite3
from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

# ==============================================================================
# 1. CONFIGURATION & INITIALISATION
# ==============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "votre_cle_secrete_ici")

UPLOAD_FOLDER = "static/uploads"
GPX_UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(GPX_UPLOAD_FOLDER, exist_ok=True)

# Configuration pour les jetons de réinitialisation de mot de passe
serializer = URLSafeTimedSerializer(app.secret_key)

# Paramètres du serveur SMTP
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "captiva74@gmail.com"
SMTP_PASSWORD = "zlmpyrysfszulqrg"

CATEGORIES = [
    "Écoles",
    "Benjamins",
    "Minimes",
    "Cadets",
    "Juniors",
    "U23",
    "Elites",
    "Masters",
]


# ==============================================================================
# 2. BASE DE DONNÉES (GESTION & INITIALISATION)
# ==============================================================================


def get_db_connection():
    conn = sqlite3.connect("cyclisme.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db_connection()

    # 1. Table Utilisateurs
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_blocked INTEGER DEFAULT 0
        )
    """)

    # 2. Table Athlètes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS athletes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            date_naissance TEXT,
            categorie TEXT,
            nom_fichier TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # 3. Table Résultats de courses
    conn.execute("""
        CREATE TABLE IF NOT EXISTS resultats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            athlete_id INTEGER,
            nom_course TEXT NOT NULL,
            date_course TEXT,
            classement INTEGER,
            FOREIGN KEY (athlete_id) REFERENCES athletes (id) ON DELETE CASCADE
        )
    """)

    # 4. Table Activités (GPX)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            athlete_id INTEGER,
            nom TEXT,
            distance REAL,
            duree INTEGER,
            date_activite TEXT,
            frequence_cardiaque_moy REAL,
            FOREIGN KEY (athlete_id) REFERENCES athletes (id) ON DELETE CASCADE
        )
    """)

    # Migrations de sécurité pour bases existantes
    for query in [
        "ALTER TABLE activites ADD COLUMN athlete_id INTEGER;",
        "ALTER TABLE resultats ADD COLUMN athlete_id INTEGER;",
        "ALTER TABLE athletes ADD COLUMN user_id INTEGER;",
    ]:
        try:
            conn.execute(query)
        except sqlite3.OperationalError:
            pass

    # Administrateur par défaut
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", ("admin",)
    ).fetchone()
    if not user:
        hashed_pw = generate_password_hash("admin123")
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hashed_pw, "admin"),
        )
    else:
        conn.execute(
            "UPDATE users SET role = 'admin' WHERE username = 'admin'"
        )

    conn.commit()
    conn.close()


init_db()


# ==============================================================================
# 3. DECORATEURS & MIDDLEWARES & HELPERS
# ==============================================================================


@app.after_request
def add_header(response):
    """Évite l'effet d'écran figé après connexion/déconnexion en désactivant le cache."""
    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Accès réservé exclusivement à l'administrateur.", "erreur")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return decorated_function


def formater_duree(secondes):
    if not secondes:
        return "0min"
    heures = secondes // 3600
    minutes = (secondes % 3600) // 60

    if heures > 0:
        return f"{heures}h:{minutes:02d}mn"
    return f"{minutes}mn"


app.jinja_env.globals.update(formater_duree=formater_duree)


# ==============================================================================
# 4. AUTHENTIFICATION & COMPTE UTILISATEUR
# ==============================================================================


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["is_blocked"] == 1:
                flash(
                    "Votre compte a été bloqué par l'administrateur.", "erreur"
                )
                return render_template("login.html")

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Connexion réussie !", "succes")
            return redirect(url_for("index"))

        flash("Identifiants incorrects.", "erreur")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie.", "succes")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form.get("email")
        password = request.form["password"]

        if not username or not password:
            flash("Veuillez remplir les champs obligatoires.", "erreur")
            return render_template("register.html")

        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_pw),
            )
            conn.commit()
            conn.close()
            flash(
                "Inscription réussie ! Vous pouvez vous connecter.", "succes"
            )
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            conn.close()
            if "email" in str(e).lower():
                flash("Cette adresse email est déjà utilisée.", "erreur")
            else:
                flash("Ce nom d'utilisateur existe déjà.", "erreur")

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user:
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for(
                "reset_with_token", token=token, _external=True
            )

            msg = EmailMessage()
            msg.set_content(
                f"Bonjour {user['username']},\n\nCliquez sur le lien suivant pour réinitialiser votre mot de passe :\n{reset_url}\n\nCe lien expirera dans 15 minutes."
            )
            msg["Subject"] = "Réinitialisation de votre mot de passe - KMC Cycling"
            msg["From"] = SMTP_EMAIL
            msg["To"] = email

            try:
                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_EMAIL, SMTP_PASSWORD)
                    server.send_message(msg)
                flash("Un e-mail de réinitialisation a été envoyé.", "succes")
            except Exception as err:
                print(
                    f"ERREUR SMTP DÉTAILLÉE : {type(err).__name__} - {err}"
                )
                flash(
                    "Erreur lors de l'envoi de l'e-mail de réinitialisation.",
                    "erreur",
                )
        else:
            flash("Si cet e-mail existe, un lien a été envoyé.", "succes")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = serializer.loads(
            token, salt="password-reset-salt", max_age=900
        )
    except Exception:
        flash(
            "Le lien de réinitialisation est invalide ou a expiré.", "erreur"
        )
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        if not new_password:
            flash("Veuillez entrer un nouveau mot de passe.", "erreur")
            return render_template("reset_password.html")

        hashed_pw = generate_password_hash(new_password)

        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email)
        )
        conn.commit()
        conn.close()

        flash("Votre mot de passe a été mis à jour avec succès !", "succes")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/profil", methods=["GET", "POST"])
def profil():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        nouveau_username = request.form["username"]
        nouvel_email = request.form["email"]
        nouveau_mdp = request.form["password"]

        if nouveau_mdp:
            hashed_mdp = generate_password_hash(nouveau_mdp)
            cursor.execute(
                "UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?",
                (
                    nouveau_username,
                    nouvel_email,
                    hashed_mdp,
                    session["user_id"],
                ),
            )
        else:
            cursor.execute(
                "UPDATE users SET username = ?, email = ? WHERE id = ?",
                (nouveau_username, nouvel_email, session["user_id"]),
            )

        conn.commit()
        session["username"] = nouveau_username
        flash("Profil mis à jour avec succès !", "succes")
        conn.close()
        return redirect(url_for("profil"))

    cursor.execute(
        "SELECT username, email FROM users WHERE id = ?", (session["user_id"],)
    )
    utilisateur = cursor.fetchone()

    athletes = conn.execute(
        "SELECT id, nom, prenom FROM athletes ORDER BY nom, prenom"
    ).fetchall()
    conn.close()

    return render_template(
        "profil.html", utilisateur=utilisateur, athletes=athletes
    )


# ==============================================================================
# 5. TABLEAU DE BORD (INDEX)
# ==============================================================================


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    nb_athletes = conn.execute("SELECT COUNT(*) FROM athletes").fetchone()[0]
    nb_courses = conn.execute("SELECT COUNT(*) FROM resultats").fetchone()[0]

    stats_par_athlete = conn.execute("""
        SELECT a.id, a.nom, a.prenom, a.nom_fichier, a.categorie,
               COUNT(r.id) as nb_courses,
               MIN(r.classement) as meilleur,
               MAX(r.classement) as pire,
               ROUND(AVG(r.classement), 1) as moyenne
        FROM athletes a
        LEFT JOIN resultats r ON a.id = r.athlete_id
        GROUP BY a.id
    """).fetchall()

    conn.close()

    stats = {
        "nb_athletes": nb_athletes,
        "nb_courses": nb_courses,
        "par_athlete": stats_par_athlete,
    }
    return render_template("index.html", stats=stats)


# ==============================================================================
# 6. ADMINISTRATION DES UTILISATEURS
# ==============================================================================


@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/user/toggle-block/<int:id>", methods=["POST"])
@admin_required
def toggle_block_user(id):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT is_blocked FROM users WHERE id = ?", (id,)
    ).fetchone()
    if user:
        nouveau_statut = 0 if user["is_blocked"] == 1 else 1
        conn.execute(
            "UPDATE users SET is_blocked = ? WHERE id = ?",
            (nouveau_statut, id),
        )
        conn.commit()
    conn.close()
    flash("Statut de l'utilisateur mis à jour.", "succes")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/delete/<int:id>", methods=["POST"])
@admin_required
def admin_delete_user(id):
    if id == session["user_id"]:
        flash(
            "Vous ne pouvez pas supprimer votre propre compte admin.", "erreur"
        )
        return redirect(url_for("admin_users"))

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Utilisateur supprimé avec succès.", "succes")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/edit/<int:id>", methods=["GET", "POST"])
@admin_required
def admin_edit_user(id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchone()

    if not user:
        conn.close()
        flash("Utilisateur introuvable.", "erreur")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        role = request.form["role"]

        try:
            conn.execute(
                """
                UPDATE users SET username = ?, email = ?, role = ?
                WHERE id = ?
            """,
                (username, email, role, id),
            )
            conn.commit()
            conn.close()
            flash("Utilisateur modifié avec succès !", "succes")
            return redirect(url_for("admin_users"))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Ce nom d'utilisateur est déjà pris.", "erreur")

    conn.close()
    return render_template("admin_edit_user.html", user=user)


# ==============================================================================
# 7. GESTION DES ATHLÈTES & EXPORTS
# ==============================================================================


@app.route("/athletes")
def liste_athletes():
    categorie = request.args.get("categorie", "")
    conn = get_db_connection()

    if categorie:
        athletes = conn.execute(
            "SELECT * FROM athletes WHERE categorie = ?", (categorie,)
        ).fetchall()
    else:
        athletes = conn.execute("SELECT * FROM athletes").fetchall()

    conn.close()
    return render_template(
        "athletes.html",
        athletes=athletes,
        categorie_selectionnee=categorie,
        categories=CATEGORIES,
    )


@app.route("/athlete/<int:id>")
def profil_athlete(id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    athlete = conn.execute(
        "SELECT * FROM athletes WHERE id = ?", (id,)
    ).fetchone()
    if not athlete:
        conn.close()
        flash("Athlète introuvable.", "erreur")
        return redirect(url_for("liste_athletes"))

    resultats = conn.execute(
        "SELECT * FROM resultats WHERE athlete_id = ? ORDER BY date_course DESC",
        (id,),
    ).fetchall()
    conn.close()
    return render_template(
        "profil_athlete.html", athlete=athlete, resultats=resultats
    )


@app.route("/athlete/ajouter", methods=["GET", "POST"])
@admin_required
def ajouter_athlete():
    if request.method == "POST":
        nom = request.form["nom"]
        prenom = request.form["prenom"]
        date_naissance = request.form.get("date_naissance")
        categorie = request.form.get("categorie")

        nom_fichier = None
        file = request.files.get("photo")
        if file and file.filename != "":
            nom_fichier = file.filename
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], nom_fichier))

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO athletes (nom, prenom, date_naissance, categorie, nom_fichier) VALUES (?, ?, ?, ?, ?)",
            (nom, prenom, date_naissance, categorie, nom_fichier),
        )
        conn.commit()
        conn.close()
        flash("Athlète ajouté avec succès !", "succes")
        return redirect(url_for("liste_athletes"))

    return render_template("ajouter_athlete.html", categories=CATEGORIES)


@app.route("/athlete/modifier/<int:id>", methods=["GET", "POST"])
@admin_required
def modifier_athlete(id):
    conn = get_db_connection()
    athlete = conn.execute(
        "SELECT * FROM athletes WHERE id = ?", (id,)
    ).fetchone()

    if not athlete:
        conn.close()
        flash("Athlète introuvable.", "erreur")
        return redirect(url_for("liste_athletes"))

    if request.method == "POST":
        nom = request.form["nom"]
        prenom = request.form["prenom"]
        date_naissance = request.form.get("date_naissance")
        categorie = request.form.get("categorie")

        nom_fichier = athlete["nom_fichier"]
        file = request.files.get("photo")
        if file and file.filename != "":
            nom_fichier = file.filename
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], nom_fichier))

        conn.execute(
            """
            UPDATE athletes SET nom = ?, prenom = ?, date_naissance = ?, categorie = ?, nom_fichier = ?
            WHERE id = ?
        """,
            (nom, prenom, date_naissance, categorie, nom_fichier, id),
        )
        conn.commit()
        conn.close()
        flash("Profil mis à jour avec succès !", "succes")
        return redirect(url_for("profil_athlete", id=id))

    conn.close()
    return render_template(
        "modifier_athlete.html", athlete=athlete, categories=CATEGORIES
    )


@app.route("/athlete/supprimer/<int:id>", methods=["POST"])
@admin_required
def supprimer_athlete(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM athletes WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Athlète supprimé.", "succes")
    return redirect(url_for("liste_athletes"))


@app.route("/athletes/export/csv")
def export_athletes_csv():
    categorie = request.args.get("categorie", "")
    conn = get_db_connection()

    if categorie:
        athletes = conn.execute(
            "SELECT * FROM athletes WHERE categorie = ?", (categorie,)
        ).fetchall()
        filename = f"athletes_{categorie}.csv"
    else:
        athletes = conn.execute("SELECT * FROM athletes").fetchall()
        filename = "tous_les_athletes.csv"

    conn.close()

    si = StringIO()
    writer = csv.writer(si, delimiter=";")
    writer.writerow(["ID", "Nom", "Prenom", "Date de naissance", "Categorie"])

    for a in athletes:
        writer.writerow(
            [a["id"], a["nom"], a["prenom"], a["date_naissance"], a["categorie"]]
        )

    output = make_response(si.getvalue().encode("utf-8-sig"))
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output


@app.route("/athletes/export/excel")
def export_athletes_excel():
    categorie = request.args.get("categorie", "")
    conn = get_db_connection()

    if categorie:
        query = "SELECT id, nom, prenom, date_naissance, categorie FROM athletes WHERE categorie = ?"
        df = pd.read_sql_query(query, conn, params=(categorie,))
        filename = f"athletes_{categorie}.xlsx"
    else:
        query = "SELECT id, nom, prenom, date_naissance, categorie FROM athletes"
        df = pd.read_sql_query(query, conn)
        filename = "tous_les_athletes.xlsx"

    conn.close()

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Athlètes")
    output.seek(0)

    response = make_response(output.read())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-type"] = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    return response


# ==============================================================================
# 8. RÉSULTATS DE COURSES
# ==============================================================================


@app.route("/historique")
def historique():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    resultats = conn.execute("""
        SELECT r.*, a.id as athlete_id, a.nom, a.prenom, a.nom_fichier 
        FROM resultats r
        JOIN athletes a ON r.athlete_id = a.id
        ORDER BY r.date_course DESC
    """).fetchall()
    conn.close()
    return render_template("historique.html", resultats=resultats)


@app.route("/resultat/ajouter", methods=["GET", "POST"])
@admin_required
def ajouter_resultat():
    conn = get_db_connection()

    if request.method == "POST":
        athlete_id = request.form.get("athlete_id")
        nom_course = request.form["course"]
        date_course = request.form["date_course"]
        classement = request.form["classement"]

        if not athlete_id:
            flash("Veuillez sélectionner un athlète.", "erreur")
            athletes = conn.execute(
                "SELECT * FROM athletes ORDER BY nom, prenom"
            ).fetchall()
            conn.close()
            return render_template(
                "ajouter_resultat.html",
                categories=CATEGORIES,
                athletes=athletes,
            )

        conn.execute(
            "INSERT INTO resultats (athlete_id, nom_course, date_course, classement) VALUES (?, ?, ?, ?)",
            (athlete_id, nom_course, date_course, classement),
        )
        conn.commit()
        conn.close()

        flash("Résultat enregistré avec succès !", "succes")
        return redirect(url_for("historique"))

    athletes = conn.execute(
        "SELECT * FROM athletes ORDER BY nom, prenom"
    ).fetchall()
    conn.close()
    return render_template(
        "ajouter_resultat.html", categories=CATEGORIES, athletes=athletes
    )


@app.route("/resultat/modifier/<int:id>", methods=["GET", "POST"])
@admin_required
def modifier_resultat(id):
    conn = get_db_connection()
    resultat = conn.execute(
        "SELECT * FROM resultats WHERE id = ?", (id,)
    ).fetchone()
    if not resultat:
        conn.close()
        flash("Résultat introuvable.", "erreur")
        return redirect(url_for("historique"))

    athletes = conn.execute(
        "SELECT * FROM athletes ORDER BY nom, prenom"
    ).fetchall()

    if request.method == "POST":
        athlete_id = request.form["athlete_id"]
        nom_course = request.form["course"]
        date_course = request.form["date_course"]
        classement = request.form["classement"]

        conn.execute(
            """
            UPDATE resultats 
            SET athlete_id = ?, nom_course = ?, date_course = ?, classement = ?
            WHERE id = ?
        """,
            (athlete_id, nom_course, date_course, classement, id),
        )
        conn.commit()
        conn.close()

        flash("Résultat mis à jour avec succès !", "succes")
        return redirect(url_for("historique"))

    conn.close()
    return render_template(
        "modifier_resultat.html",
        resultat=resultat,
        athletes=athletes,
        categories=CATEGORIES,
    )


@app.route("/resultat/supprimer/<int:id>", methods=["POST"])
@admin_required
def supprimer_resultat(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM resultats WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Résultat supprimé avec succès.", "succes")
    return redirect(url_for("historique"))


# ==============================================================================
# 9. ACTIVITÉS GPX
# ==============================================================================


@app.route("/activites")
def liste_activites():
    if "user_id" not in session or session.get("role") != "admin":
        flash("Accès réservé exclusivement à l'administrateur.", "erreur")
        return redirect(url_for("index"))

    conn = get_db_connection()
    activites = conn.execute("""
        SELECT act.*, a.nom as athlete_nom, a.prenom as athlete_prenom 
        FROM activites act
        LEFT JOIN athletes a ON act.athlete_id = a.id
        ORDER BY act.date_activite DESC
    """).fetchall()

    # Récupérer tous les athlètes pour alimenter le <select> GPX
    athletes = conn.execute("SELECT id, nom, prenom FROM athletes ORDER BY nom, prenom").fetchall()
    conn.close()

    return render_template("activites_strava.html", activites=activites, athletes=athletes)


@app.route("/activites/importer", methods=["POST"])
def importer_gpx():
    if session.get("role") != "admin":
        flash("Accès réservé à l'administrateur.", "erreur")
        return redirect(url_for("profil"))

    athlete_id = request.form.get("athlete_id")
    if not athlete_id:
        flash(
            "Veuillez sélectionner un athlète pour ces fichiers GPX.", "erreur"
        )
        return redirect(url_for("profil"))

    if "fichier_gpx" not in request.files:
        flash("Aucun fichier sélectionné.", "erreur")
        return redirect(url_for("profil"))

    fichiers = request.files.getlist("fichier_gpx")
    nb_importes = 0

    conn = get_db_connection()

    for fichier in fichiers:
        if fichier and fichier.filename.endswith(".gpx"):
            chemin_fichier = os.path.join(
                GPX_UPLOAD_FOLDER, fichier.filename
            )
            fichier.save(chemin_fichier)

            try:
                with open(chemin_fichier, "r", encoding="utf-8") as gpx_file:
                    gpx = gpxpy.parse(gpx_file)

                    distance_metres = (
                        gpx.length_3d() or gpx.length_2d() or 0
                    )
                    distance_km = distance_metres / 1000.0

                    duree_sec = 0
                    date_activite = None

                    duration = gpx.get_duration()
                    if duration:
                        duree_sec = int(duration)

                    for track in gpx.tracks:
                        for segment in track.segments:
                            for point in segment.points:
                                if point.time:
                                    date_activite = point.time.strftime(
                                        "%Y-%m-%d %H:%M:%S"
                                    )
                                    break
                            if date_activite:
                                break
                        if date_activite:
                            break

                    nom_activite = fichier.filename.rsplit(".", 1)[0]

                    conn.execute(
                        """
                        INSERT INTO activites (athlete_id, nom, distance, duree, date_activite, frequence_cardiaque_moy)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (
                            athlete_id,
                            nom_activite,
                            distance_km,
                            duree_sec,
                            date_activite,
                            None,
                        ),
                    )

                    nb_importes += 1

            except Exception as e:
                print(
                    f"Erreur lors de la lecture du fichier {fichier.filename}: {e}"
                )

            if os.path.exists(chemin_fichier):
                os.remove(chemin_fichier)

    conn.commit()
    conn.close()

    flash(
        f"{nb_importes} fichier(s) GPX importé(s) avec succès !", "succes"
    )
    return redirect(url_for("profil"))


@app.route("/activites/supprimer/<int:id>", methods=["POST"])
@admin_required
def supprimer_activite(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM activites WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Activité supprimée avec succès.", "succes")
    return redirect(url_for("liste_activites"))


# ==============================================================================
# 10. LANCEMENT DE L'APPLICATION
# ==============================================================================

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5005)