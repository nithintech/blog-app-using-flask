from flask import Flask
from flask.ext.login import LoginManager
import sqlite3,os
from flask.ext.mail import Mail
c=sqlite3.connect('test.db')
try:
        c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,email TEXT,password TEXT,confirm BOOLEAN,registered_on TEXT,UNIQUE (username,email))")

     	c.execute("CREATE TABLE posts(id INTEGER PRIMARY KEY,username TEXT,title TEXT,body TEXT,date TEXT)")
	c.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY,username TEXT,postid INTEGER,comment TEXT)")
	c.commit()
except:
        None
app=Flask(__name__)
app.config.from_object('config')
mail=Mail()
lm=LoginManager()
lm.init_app(app)
lm.login_view = '/login'
lm.login_message = u'Log in here!'
mail.init_app(app)
from app import views,models
