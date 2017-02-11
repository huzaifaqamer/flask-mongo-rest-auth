import os

from flask import Flask, jsonify, redirect, request, abort, url_for, g
from flask_mongoengine import MongoEngine, MongoEngineSessionInterface
from mongoengine.errors import NotUniqueError
from flask_restful import Api, Resource
from flask_httpauth import HTTPBasicAuth

import models

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {'HOST':os.environ.get('FMRA_MONGO_URI'), 'DB': 'fmra_auth'}
app.config['SECRET_KEY'] = os.environ.get('FMRA_SECRET_KEY')
app.debug = True

db = MongoEngine(app) # connect MongoEngine with Flask App
app.session_interface = MongoEngineSessionInterface(db) # sessions w/ mongoengine

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = models.User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = models.User.objects(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

class Register(Resource):

    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        if username is None or password is None:
            abort(400) # missing arguments
        try:
            user = models.User(username=username)
            user.hash_password(password)
            user.save()
        except NotUniqueError:
            abort(400) # username exists

        return jsonify({ 'username': user.username })

class Login(Resource):

    @auth.login_required
    def get(self):
        token = g.user.generate_auth_token()
        return jsonify({ 'token': token.decode('ascii') })

    @auth.login_required    
    def post(self):
    	# TODO: Make token invalid
    	return jsonify({'response': 'Logged Out'})

api = Api(app)
api.add_resource(Register, '/auth/register/', endpoint='register')
api.add_resource(Login, '/auth/login/', endpoint='login')
api.add_resource(Login, '/auth/logout/', endpoint='logout')

if __name__ == "__main__":
    app.run(debug=True)