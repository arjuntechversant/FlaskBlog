from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


app.config['SECURITY_POST_LOGIN'] = '/profile'

# facebook config
app.config['SOCIAL_FACEBOOK'] = {
    'consumer_key': '1050441568455413',
    'consumer_secret': 'e8868bcf35763bb3713d087624222205'
}


db = SQLAlchemy(app)
bcrpyt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# app.config.from_object('config')

from flaskblog import routes
