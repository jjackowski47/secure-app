import flask_sqlalchemy

db = flask_sqlalchemy.SQLAlchemy()


class UsersModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(30), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password
    
    def __repr__(self):
        return f"<User {self.username}>"

class PrivNotesModel(db.Model):
    __tablename__ = 'priv_notes'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, content, user_id):
        self.content = content
        self.user_id = user_id
    
    def __repr__(self):
        return f"<PrivNote {self.id}>"

class PublicNotesModel(db.Model):
    __tablename__ = 'public_notes'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)

    def __init__(self, content):
        self.content = content
    
    def __repr__(self):
        return f"<PublicNote {self.id}>"

class SharedNotesModel(db.Model):
    __tablename__ = 'shared_notes'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reciepment_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, content, author_id, reciepment_id):
        self.content = content
        self.author_id = author_id
        self.reciepment_id = reciepment_id
    
    def __repr__(self):
        return f"<SharedNote {self.id}>"

class FilesModel(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    file_uid = db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, file_uid, user_id):
        self.file_uid = file_uid
        self.user_id = user_id
    
    def __repr__(self):
        return f"<File {self.file_uid}>"

class KnownDevicesModel(db.Model):
    __tablename__ = 'known_devices'

    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, device_ip, user_id):
        self.device_ip = device_ip
        self.user_id = user_id
    
    def __repr__(self):
        return f"<KnownDevice {self.device_ip}>"

class BlockedDevicesModel(db.Model):
    __tablename__ = 'blocked_devices'

    id = db.Column(db.Integer, primary_key=True)
    device_ip = db.Column(db.String(), nullable=False)
    tries = db.Column(db.Integer)
    ban_exp_time = db.Column(db.DateTime)

    def __init__(self, device_ip):
        self.device_ip = device_ip
        self.tries = 1
    
    def __repr__(self):
        return f"<BlockedDevice {self.device_ip}>"