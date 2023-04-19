from app import create_app
from app.extensions import db
from app.models import User, Home, Vendor, Service, Promotion, Quote, Contract, Product, Offer

app = create_app()

with app.app_context():
    db.create_all()
