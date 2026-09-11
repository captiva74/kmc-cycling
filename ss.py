
import smtplib
from email.message import EmailMessage

# Remplacez par vos vrais identifiants
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "captiva74@gmail.com"
SMTP_PASSWORD = "zlmpyrysfszulqrg"

msg = EmailMessage()
msg.set_content("Ceci est un test de configuration SMTP pour CycloStats.")
msg['Subject'] = "Test Connexion SMTP"
msg['From'] = SMTP_EMAIL
msg['To'] = SMTP_EMAIL  # S'envoyer l'e-mail à soi-même

try:
    print("Connexion au serveur SMTP...")
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        print("Authentification en cours...")
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        print("Envoi de l'e-mail de test...")
        server.send_message(msg)
    print("Succès : L'e-mail a été envoyé et le SMTP_PASSWORD fonctionne parfaitement !")
except Exception as e:
    print(f"Erreur : Échec de la connexion ou de l'envoi -> {e}")