import os

user = os.environ['POSTGRES_USER']
password = os.environ['POSTGRES_PASSWORD']
host = os.environ['POSTGRES_HOST']
database = os.environ['POSTGRES_DB']
port = os.environ['POSTGRES_PORT']

DATABASE_CONNECTION_URI = f'postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}'

SQLALCHEMY_TRACK_MODIFICATIONS = False
UPLOAD_FOLDER = "app/upload_files"
SESSION_LIFETIME = 300
SECRET_KEY = os.environ['SECRET_KEY']