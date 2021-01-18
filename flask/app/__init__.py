from flask import Flask
from flask_wtf.csrf import CSRFProtect

from . import config
from .models import UsersModel, db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_CONNECTION_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.secret_key = config.SECRET_KEY
app.permanent_session_lifetime = config.SESSION_LIFETIME
app.app_context().push()
csrf = CSRFProtect(app)
db.init_app(app)
db.drop_all()
db.create_all()

# Honeypot account
db.session.add(UsersModel("admin1", "password123"))
db.session.commit()

from app import views