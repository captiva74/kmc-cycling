import os
import smtplib
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "votre_cle_secrete_ici"
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configuration pour les jetons de réinitialisation de mot de passe
s = URLSafeTimedSerializer(app.secret_key)

# Paramètres du serveur SMTP (Modifiez avec vos vrais identifiants ou un mot de passe d'application)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "captiva74@gmail.com"
SMTP_PASSWORD = "zlmpyrysfszulqrg"

def get_db_connection():
    conn = sqlite3.connect('cyclisme.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Table des utilisateurs (Login / Register)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_blocked INTEGER DEFAULT 0
        )
    ''')
    # Table des athlètes
    conn.execute('''
        CREATE TABLE IF NOT EXISTS athletes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            date_naissance TEXT,
            categorie TEXT,
            nom_fichier TEXT
        )
    ''')
    # Table des résultats de courses (Historique)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS resultats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            athlete_id INTEGER,
            nom_course TEXT NOT NULL,
            date_course TEXT,
            classement INTEGER,
            FOREIGN KEY (athlete_id) REFERENCES athletes (id) ON DELETE CASCADE
        )
    ''')
    
    # Créer ou mettre à jour l'administrateur par défaut avec le rôle 'admin'
    user = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not user:
        hashed_pw = generate_password_hash('admin123')
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
            ('admin', hashed_pw, 'admin')
        )
    else:
        conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        
    conn.commit()
    conn.close()

init_db()

CATEGORIES = ['École', 'Benjamin', 'Minime', 'Cadet', 'Junior', 'Espoir', 'Senior', 'Master']

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            if user['is_blocked'] == 1:
                flash("Votre compte a été bloqué par l'administrateur.", "erreur")
                return render_template('login.html')
                
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Connexion réussie !")
            return redirect(url_for('index'))
        else:
            flash("Identifiants incorrects.", "erreur")
            
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_with_token', token=token, _external=True)
            
            msg = EmailMessage()
            msg.set_content(f"Bonjour {user['username']},\n\nCliquez sur le lien suivant pour réinitialiser votre mot de passe :\n{reset_url}\n\nCe lien expirera dans 15 minutes.")
            msg['Subject'] = "Réinitialisation de votre mot de passe - CycloStats"
            msg['From'] = SMTP_EMAIL
            msg['To'] = email
            
            try:
                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_EMAIL, SMTP_PASSWORD)
                    server.send_message(msg)
                flash("Un e-mail de réinitialisation a été envoyé.", "succes")
            except Exception as err:
                print(f"ERREUR SMTP DÉTAILLÉE : {type(err).__name__} - {err}")
                flash("Erreur lors de l'envoi de l'e-mail de réinitialisation.", "erreur")
        else:
            flash("Si cet e-mail existe, un lien a été envoyé.", "succes")
            
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=900)
    except Exception:
        flash("Le lien de réinitialisation est invalide ou a expiré.", "erreur")
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash("Veuillez entrer un nouveau mot de passe.", "erreur")
            return render_template('reset_password.html')
            
        hashed_pw = generate_password_hash(new_password)
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_pw, email))
        conn.commit()
        conn.close()
        
        flash("Votre mot de passe a été mis à jour avec succès !", "succes")
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form.get('email')
        password = request.form['password']
        
        if not username or not password:
            flash("Veuillez remplir les champs obligatoires.", "erreur")
            return render_template('register.html')
            
        hashed_pw = generate_password_hash(password)
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_pw))
            conn.commit()
            conn.close()
            flash("Inscription réussie ! Vous pouvez vous connecter.", "succes")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Ce nom d'utilisateur existe déjà.", "erreur")
            
    return render_template('register.html')

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Accès non autorisé.", "erreur")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/toggle-block/<int:id>', methods=['POST'])
def toggle_block_user(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    user = conn.execute('SELECT is_blocked FROM users WHERE id = ?', (id,)).fetchone()
    if user:
        nouveau_statut = 0 if user['is_blocked'] == 1 else 1
        conn.execute('UPDATE users SET is_blocked = ? WHERE id = ?', (nouveau_statut, id))
        conn.commit()
    conn.close()
    flash("Statut de l'utilisateur mis à jour.")
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:id>', methods=['POST'])
def admin_delete_user(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
        
    if id == session['user_id']:
        flash("Vous ne pouvez pas supprimer votre propre compte admin.", "erreur")
        return redirect(url_for('admin_users'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash("Utilisateur supprimé avec succès.")
    return redirect(url_for('admin_users'))

@app.route('/admin/user/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_user(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Accès non autorisé.", "erreur")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    
    if not user:
        conn.close()
        flash("Utilisateur introuvable.", "erreur")
        return redirect(url_for('admin_users'))
        
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        
        try:
            conn.execute('''
                UPDATE users SET username = ?, email = ?, role = ?
                WHERE id = ?
            ''', (username, email, role, id))
            conn.commit()
            conn.close()
            flash("Utilisateur modifié avec succès !")
            return redirect(url_for('admin_users'))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Ce nom d'utilisateur est déjà pris.", "erreur")
            
    conn.close()
    return render_template('admin_edit_user.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash("Déconnexion réussie.")
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    nb_athletes = conn.execute('SELECT COUNT(*) FROM athletes').fetchone()[0]
    nb_courses = conn.execute('SELECT COUNT(*) FROM resultats').fetchone()[0]
    
    stats_par_athlete = conn.execute('''
        SELECT a.id, a.nom, a.prenom, a.nom_fichier, a.categorie,
               COUNT(r.id) as nb_courses,
               MIN(r.classement) as meilleur,
               MAX(r.classement) as pire,
               ROUND(AVG(r.classement), 1) as moyenne
        FROM athletes a
        LEFT JOIN resultats r ON a.id = r.athlete_id
        GROUP BY a.id
    ''').fetchall()
    
    conn.close()
    
    stats = {
        "nb_athletes": nb_athletes,
        "nb_courses": nb_courses,
        "par_athlete": stats_par_athlete
    }
    return render_template('index.html', stats=stats)

@app.route('/profil', methods=['GET', 'POST'])
def profil():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        nouveau_username = request.form['username']
        nouvel_email = request.form['email']
        nouveau_mdp = request.form['password']
        
        if nouveau_mdp:
            hashed_mdp = generate_password_hash(nouveau_mdp)
            cursor.execute(
                'UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?',
                (nouveau_username, nouvel_email, hashed_mdp, session['user_id'])
            )
        else:
            cursor.execute(
                'UPDATE users SET username = ?, email = ? WHERE id = ?',
                (nouveau_username, nouvel_email, session['user_id'])
            )
        
        conn.commit()
        conn.close()
        session['username'] = nouveau_username
        flash('Profil mis à jour avec succès !', 'succes')
        return redirect(url_for('profil'))
        
    cursor.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],))
    utilisateur = cursor.fetchone()
    conn.close()
    
    return render_template('profil.html', utilisateur=utilisateur)

@app.route('/historique')
def historique():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    resultats = conn.execute('''
        SELECT r.*, a.id as athlete_id, a.nom, a.prenom, a.nom_fichier 
        FROM resultats r
        JOIN athletes a ON r.athlete_id = a.id
        ORDER BY r.date_course DESC
    ''').fetchall()
    conn.close()
    return render_template('historique.html', resultats=resultats)

@app.route('/resultat/modifier/<int:id>', methods=['GET', 'POST'])
def modifier_resultat(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    resultat = conn.execute('SELECT * FROM resultats WHERE id = ?', (id,)).fetchone()
    if not resultat:
        conn.close()
        flash("Résultat introuvable.", "erreur")
        return redirect(url_for('historique'))
        
    athletes = conn.execute('SELECT * FROM athletes ORDER BY nom, prenom').fetchall()
    
    if request.method == 'POST':
        athlete_id = request.form['athlete_id']
        nom_course = request.form['course']
        date_course = request.form['date_course']
        classement = request.form['classement']
        
        conn.execute('''
            UPDATE resultats 
            SET athlete_id = ?, nom_course = ?, date_course = ?, classement = ?
            WHERE id = ?
        ''', (athlete_id, nom_course, date_course, classement, id))
        conn.commit()
        conn.close()
        
        flash("Résultat mis à jour avec succès !")
        return redirect(url_for('historique'))
        
    conn.close()
    return render_template('modifier_resultat.html', resultat=resultat, athletes=athletes, categories=CATEGORIES)

@app.route('/resultat/supprimer/<int:id>', methods=['POST'])
def supprimer_resultat(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM resultats WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Résultat supprimé avec succès.")
    return redirect(url_for('historique'))

@app.route('/athletes')
def liste_athletes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    athletes = conn.execute('SELECT * FROM athletes').fetchall()
    conn.close()
    return render_template('liste_athletes.html', athletes=athletes)

@app.route('/athlete/ajouter', methods=['GET', 'POST'])
def ajouter_athlete():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        date_naissance = request.form.get('date_naissance')
        categorie = request.form.get('categorie')
        
        nom_fichier = None
        file = request.files.get('photo')
        if file and file.filename != '':
            nom_fichier = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], nom_fichier))
            
        conn = get_db_connection()
        conn.execute('INSERT INTO athletes (nom, prenom, date_naissance, categorie, nom_fichier) VALUES (?, ?, ?, ?, ?)',
                     (nom, prenom, date_naissance, categorie, nom_fichier))
        conn.commit()
        conn.close()
        flash("Athlète ajouté avec succès !")
        return redirect(url_for('liste_athletes'))
        
    return render_template('ajouter_athlete.html', categories=CATEGORIES)

@app.route('/athlete/<int:id>')
def profil_athlete(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    athlete = conn.execute('SELECT * FROM athletes WHERE id = ?', (id,)).fetchone()
    if not athlete:
        conn.close()
        flash("Athlète introuvable.", "erreur")
        return redirect(url_for('liste_athletes'))
        
    resultats = conn.execute('SELECT * FROM resultats WHERE athlete_id = ? ORDER BY date_course DESC', (id,)).fetchall()
    conn.close()
    return render_template('profil_athlete.html', athlete=athlete, resultats=resultats)

@app.route('/athlete/modifier/<int:id>', methods=['GET', 'POST'])
def modifier_athlete(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    athlete = conn.execute('SELECT * FROM athletes WHERE id = ?', (id,)).fetchone()
    
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        date_naissance = request.form.get('date_naissance')
        categorie = request.form.get('categorie')
        
        nom_fichier = athlete['nom_fichier']
        file = request.files.get('photo')
        if file and file.filename != '':
            nom_fichier = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], nom_fichier))
            
        conn.execute('''
            UPDATE athletes SET nom = ?, prenom = ?, date_naissance = ?, categorie = ?, nom_fichier = ?
            WHERE id = ?
        ''', (nom, prenom, date_naissance, categorie, nom_fichier, id))
        conn.commit()
        conn.close()
        flash("Profil mis à jour avec succès !")
        return redirect(url_for('profil_athlete', id=id))
        
    conn.close()
    return render_template('modifier_athlete.html', athlete=athlete, categories=CATEGORIES)

@app.route('/athlete/supprimer/<int:id>', methods=['POST'])
def supprimer_athlete(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute('DELETE FROM athletes WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash("Athlète supprimé.")
    return redirect(url_for('liste_athletes'))

@app.route('/resultat/ajouter', methods=['GET', 'POST'])
def ajouter_resultat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    if request.method == 'POST':
        athlete_id = request.form.get('athlete_id')
        nom_course = request.form['course']
        date_course = request.form['date_course']
        classement = request.form['classement']
        
        if not athlete_id:
            flash("Veuillez sélectionner un athlète.", "erreur")
            athletes = conn.execute('SELECT * FROM athletes ORDER BY nom, prenom').fetchall()
            conn.close()
            return render_template('ajouter_resultat.html', categories=CATEGORIES, athletes=athletes)
            
        conn.execute(
            'INSERT INTO resultats (athlete_id, nom_course, date_course, classement) VALUES (?, ?, ?, ?)',
            (athlete_id, nom_course, date_course, classement)
        )
        conn.commit()
        conn.close()
        
        flash("Résultat enregistré avec succès !")
        return redirect(url_for('historique'))
        
    athletes = conn.execute('SELECT * FROM athletes ORDER BY nom, prenom').fetchall()
    conn.close()
    return render_template('ajouter_resultat.html', categories=CATEGORIES, athletes=athletes)

if __name__ == '__main__':
    app.run(debug=True)