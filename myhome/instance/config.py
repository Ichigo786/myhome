import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///myhome.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


# Flask-Mail configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('sharmabivek.18@gmail.com')
    MAIL_PASSWORD = os.environ.get('B1v3k@5harma')
    MAIL_DEFAULT_SENDER = ('Your App Name', 'noreply@example.com')
