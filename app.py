import time
from flask import Flask, session, redirect, render_template, request, jsonify, flash
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from werkzeug.security import check_password_hash, generate_password_hash

import requests
from threading import Thread
from help import login_required
import json

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

engine = create_engine('postgres://xleyamymtmttse:6dc415794969d9ea7f3dd850dfa9e5542f22f58a9c4264ca37733ab37849f3d5@ec2-34-236-215-156.compute-1.amazonaws.com:5432/dbn3qo8davlg6q')

db = scoped_session(sessionmaker(bind=engine))


@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    username = request.form.get("email")
    if request.method == "POST":
        if not request.form.get("email"):
            return render_template("login.html", message="must provide email")
        elif not request.form.get("password"):
            return render_template("login.html", message="must provide password")
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                            {"username": username})
        result = rows.fetchone()
        if result == None or not check_password_hash(result[2], request.form.get("password")):
            return render_template("login.html", message="invalid username and/or password")
        session["user_id"] = result[0]
        session["user_name"] = result[1]
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":
        if not request.form.get("email"):
            return render_template("register.html", message="must provide email")
        userCheck = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username":request.form.get("email")}).fetchone()
        if userCheck:
            return render_template("register.html", message="email already exist")
        elif not request.form.get("first_name"):
            return render_template("register.html", message="must provide first name")
        elif not request.form.get("last_name"):
            return render_template("register.html", message="must provide last name")
        elif not request.form.get("password"):
            return render_template("register.html", message="must provide password")
        elif not request.form.get("confirmation"):
            return render_template("register.html", message="must confirm password")
        elif not request.form.get("password") == request.form.get("confirmation"):
            return render_template("register.html", message="passwords didn't match")
        hashedPassword = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, password) VALUES (:username, :password)",
                            {"username":request.form.get("email"),
                             "password":hashedPassword})
        db.commit()
        flash('Account created', 'info')
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/change", methods=["GET", "POST"])
def change():
    session.clear()
    if request.method == "POST":
        if not request.form.get("email"):
            return render_template("change.html", message="must provide email")
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                            {"username":request.form.get("email")})
        result = rows.fetchone()
        if result == None or not check_password_hash(result[2], request.form.get("password")):
            return render_template("change.html", message="invalid username and/or password")
        hashedPassword = generate_password_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET password = :hashedPassword WHERE username = :username", {"hashedPassword": hashedPassword, "username":request.form.get("email")})
        db.commit()
        return redirect("/login")
    else:
        return render_template("change.html")
