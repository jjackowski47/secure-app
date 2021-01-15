from app import app, db
from flask import render_template, request, session, redirect, url_for
from .models import UsersModel
import re
import crypt
from hmac import compare_digest
import json

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            user = UsersModel.query.filter_by(username=username).all()
            if user:
                if compare_digest(crypt.crypt(password, user[0].password), user[0].password):
                    session["username"] = username
                    return redirect(url_for("dashboard"))
                else:
                    return render_template("index.html", status="failed")
            else:
                return render_template("index.html", status="failed")
        else:
            return render_template("index.html", status="failed")
    else:
        return render_template("index.html")
    
@app.route("/registration", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            db.session.add(UsersModel(username, crypt.crypt(password)))
            db.session.commit()
            return render_template("register.html", status="success")
        else:
            return render_template("register.html", status="failed")
    else:
        return render_template("register.html")


@app.route("/dashboard", methods=['GET'])
def dashboard():
    if 'username' in session:
        notes = ['test1', 'test2', "test3"]
        return render_template("dashboard.html", notes=notes)
    return redirect(url_for("index", status="not logged"))