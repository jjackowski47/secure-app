from flask import Flask
import flask_sqlalchemy

from . import config
from .models import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_CONNECTION_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.app_context().push()
app.secret_key = 'iyzTwzU8LMmHCVyb_L515CXZAaRtx8il'
db.init_app(app)
db.create_all()

from app import views