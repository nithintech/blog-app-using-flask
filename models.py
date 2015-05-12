from datetime import datetime
import sqlite3
c=sqlite3.connect('test.db')
class User():
    def __init__(self , username , email,password,confirm):
        self.username = username
        self.password = password
        self.email = email
	self.confirm=confirm
        self.registered_on = datetime.utcnow()
    def __repr__(self):
        return '<User %r>' % (self.nickname)
    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
	h=sqlite3.connect('test.db')
        c=h.execute('SELECT id from users where username=(?)',[self.username])
 	id=c.fetchone()
	return unicode(int(id[0]))
    def add(self):
	c=sqlite3.connect('test.db')
	c.execute('INSERT INTO users(username,email,password,confirm,registered_on)VALUES(?,?,?,?,?)',[self.username,self.email,self.password,self.confirm,self.registered_on])
	c.commit()
    def __repr__(self):
        return '<User %r>' % (self.username)
