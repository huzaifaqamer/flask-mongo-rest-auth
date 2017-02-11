from app import app, db
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

class User(db.Document):
    username = db.StringField(required=True, max_length=120, unique=True)
    password = db.StringField(required=True, max_length=120)

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self, expiration = 3600):
        print app.config['SECRET_KEY']
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': str(self.id) })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.objects(id=data['id']).first()
        return user