import os
import click
from flask import Flask
from flask_login import LoginManager
from app.routes import routes
from app.extensions import db, login_manager
from flask_migrate import Migrate  # Import Migrate
from flask_wtf.csrf import CSRFProtect


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'myhome.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    csrf.init_app(app)
    
    db.init_app(app)
    app.register_blueprint(routes)

    login_manager.init_app(app)
    login_manager.login_view = 'routes.login'

    migrate = Migrate(app, db)  # Initialize Migrate

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    @app.cli.command("init-db")
    def init_db_command():
        db.create_all()  # Replace this line
        print("Initialized the database.")

    return app

app = create_app()
