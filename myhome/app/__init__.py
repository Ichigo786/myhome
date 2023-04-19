from flask import Flask
from .routes import routes
from .extensions import db, login_manager, mail
from .models import User, Home, Vendor, Service, Promotion, Quote, Contract
from .calculator import calculator
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'mysecretkey'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config.from_pyfile('../instance/config.py')
    app.config.from_object('instance.config.Config')
    
    # Initialize Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your mail server
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'your-email@example.com'  # Replace with your email
    app.config['MAIL_PASSWORD'] = 'your-password'  # Replace with your email password
    
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app) 
    csrf = CSRFProtect(app)


    app.register_blueprint(routes)
    app.register_blueprint(calculator)

    return app
