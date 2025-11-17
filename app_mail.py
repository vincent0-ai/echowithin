from flask import Flask, render_template
from flask_mail import Mail, Message
import random
import secrets

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'echowithin@echowithin.xyz'
app.config['MAIL_PASSWORD'] = 'EchoWithin..2025'  # Move to .env in production

mail = Mail(app)


@app.route("/verify/<email>")
def send_code(email):
    # generate 6-digit confirmation code
    code = str(secrets.randbelow(10**6)).zfill(6)

    msg = Message(
        subject="Your EchoWithin Verification Code",
        sender='echowithin@echowithin.xyz',
        recipients=[email]
    )

    # Render HTML template and pass the code
    msg.html = render_template("verify.html", code=code)
    
    mail.send(msg)

    return f"Verification code sent to {email}. Code = {code}"


if __name__ == "__main__":
    app.run(debug=True)
