import bcrypt


from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db
from sqlalchemy.orm import relationship

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey  # Add this line


from sqlalchemy.orm import relationship



home_services = db.Table('home_services',
    db.Column('home_id', db.Integer, db.ForeignKey('home.id'), primary_key=True),
    db.Column('service_id', db.Integer, db.ForeignKey('service.id'), primary_key=True)
)






class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)  # Changed this line
    homes = db.relationship('Home', backref='owner', lazy=True)
    contracts = db.relationship('Contract', backref='user', lazy=True)
    vendors = relationship('Vendor', back_populates='user')

    def set_password(self, password):
        # Set the password hash using bcrypt
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, password):
        # Check if the hashed password matches the stored hash using bcrypt
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())



class Home(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    construction_type = db.Column(db.String(50), nullable=False)
    num_bedrooms = db.Column(db.Integer, nullable=False)
    num_bathrooms = db.Column(db.Integer, nullable=False)
    floor_space = db.Column(db.Integer, nullable=False)
    num_floors = db.Column(db.Integer, nullable=False)
    heating_time = db.Column(db.String(255), nullable=False)
    roof_type = db.Column(db.String(255), nullable=False)
    available_utilities = db.Column(db.Text, nullable=False)
    services = db.relationship("Service", secondary=home_services, back_populates='homes')


class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = relationship('User', back_populates='vendors')
    services = db.relationship('Service', backref='vendor', lazy=True)  # Add this line

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    quotes = db.relationship('Quote', backref='service', lazy=True)
    homes = db.relationship('Home', secondary=home_services, back_populates='services')
    other_services = db.relationship("Home", secondary=home_services, backref=db.backref("associated_homes_2", overlaps="services,homes"), overlaps="services,homes")
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=True)

class Promotion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=False)

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=False)

class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), index=True)
    price = db.Column(db.Float)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))

class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Float)
    request_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    status = db.Column(db.String(64), default='pending')
    penalty_fee = db.Column(db.Float, nullable=True)
    negotiation = db.Column(db.String(255), nullable=True)
    penalty_fee = db.Column(db.Float, nullable=True)
    service = db.relationship('Service', backref='offers')
    vendor = db.relationship('Vendor', backref='offers')
    vendor = db.relationship('Vendor', backref='products')
