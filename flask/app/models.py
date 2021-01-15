import flask_sqlalchemy

db = flask_sqlalchemy.SQLAlchemy()


class UsersModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30))
    password = db.Column(db.String())

    def __init__(self, username, password):
        self.username = username
        self.password = password
    
    def __repr__(self):
        return f"<User {self.username}>"