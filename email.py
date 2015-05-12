from flask.ext.mail import  Message
from app import mail,app
from itsdangerous import URLSafeTimedSerializer
def confirm_email(recipients,action):
    code=encode(recipients)
    print code
    msg = Message(subject="Email Verification", sender='nithintech91@gmail.com',recipients=[recipients])
    msg.body = "verify your email by clicking the link below"
    msg.html = "http://127.0.0.1:5000/"+action+"/"+code
    with app.app_context():
        mail.send(msg)
        
def encode(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def decode(token,expiration=60):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],max_age=expiration
        )
    except:
        return False
    return email

