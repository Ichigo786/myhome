from flask_wtf import FlaskForm
from wtforms import StringField, FileField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField, FloatField, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange

from app.models import User, Vendor




class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    user_role = RadioField("Register as:", choices=[("user", "User"), ("vendor", "Vendor")], default="user", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("That username is already taken. Please choose a different one.")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("That email is already taken. Please choose a different one.")

class HomeForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired()])
    construction_type = StringField('Construction Type', validators=[DataRequired()])
    num_bedrooms = IntegerField('Number of Bedrooms', validators=[DataRequired(), NumberRange(min=1)])
    num_bathrooms = IntegerField('Number of Bathrooms', validators=[DataRequired(), NumberRange(min=1)])
    floor_space = IntegerField('Floor Space (sq ft)', validators=[DataRequired(), NumberRange(min=1)])
    num_floors = IntegerField('Number of Floors', validators=[DataRequired(), NumberRange(min=1)])
    heating_time = StringField('Heating Time', validators=[DataRequired()])
    roof_type = StringField('Roof Type', validators=[DataRequired()])
    available_utilities = TextAreaField('Available Utilities', validators=[DataRequired()])
    submit = SubmitField('Submit Home')

class ServiceRequestForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Request Service')

class VendorRegistrationForm(FlaskForm):
    name = StringField('Vendor Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    submit = SubmitField('Register Vendor')

    def validate_email(self, email):
        vendor = Vendor.query.filter_by(email=email.data).first()
        if vendor:
            raise ValidationError('Email is already taken.')

class QuoteForm(FlaskForm):
    price = FloatField('Price', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit Quote')



class RegisterProductForm(FlaskForm):
    product_name = StringField("Product Name", validators=[DataRequired()])
    product_price = FloatField("Price", validators=[DataRequired()])
    submit_product = SubmitField("Add Product")

class UpdatePenaltyFeeForm(FlaskForm):
    penalty_fee = FloatField("Penalty Fee", validators=[DataRequired()])
    submit_penalty_fee = SubmitField("Update Penalty Fee")


class DiscoverClientsForm(FlaskForm):
    min_price = FloatField("Min Price", validators=[DataRequired()])
    max_price = FloatField("Max Price", validators=[DataRequired()])
    submit_discover = SubmitField("Discover Clients")

class ServiceQuoteForm(FlaskForm):
    price = FloatField("Price", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    submit_quote = SubmitField("Submit Quote")

class OfferResponseForm(FlaskForm):
    offer_id = IntegerField("Offer ID", validators=[DataRequired()])
    response = RadioField("Response", choices=[("accept", "Accept"), ("reject", "Reject")], validators=[DataRequired()])
    submit_response = SubmitField("Submit Response")



class UploadProductForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired()])
    product_image = FileField('Product Image', validators=[DataRequired()])
    submit = SubmitField('Upload')




class ServiceCalculatorForm(FlaskForm):
    phone_cell = FloatField('Phone/Cell', validators=[DataRequired()])
    internet = FloatField('Internet', validators=[DataRequired()])
    cable_tv = FloatField('Cable/TV', validators=[DataRequired()])
    water = FloatField('Water', validators=[DataRequired()])
    sewage = FloatField('Sewage', validators=[DataRequired()])
    gas = FloatField('Gas', validators=[DataRequired()])
    electricity = FloatField('Electricity', validators=[DataRequired()])
    home_cleaning = FloatField('Home Cleaning', validators=[DataRequired()])
    lawncare = FloatField('Lawncare', validators=[DataRequired()])
    babysitting = FloatField('Babysitting', validators=[DataRequired()])
    elderly_care = FloatField('Elderly Care', validators=[DataRequired()])
    transportation = FloatField('Transportation', validators=[DataRequired()])
    mortgage_insurance = FloatField('Mortgage Insurance', validators=[DataRequired()])
    homeowners_insurance = FloatField('Homeowners Insurance', validators=[DataRequired()])
    life_insurance = FloatField('Life Insurance', validators=[DataRequired()])
    auto_insurance = FloatField('Auto Insurance', validators=[DataRequired()])
    health_insurance = FloatField('Health Insurance', validators=[DataRequired()])
    device_insurance = FloatField('Device Insurance', validators=[DataRequired()])
    submit = SubmitField('Calculate')


class AffordabilityCalculatorForm(FlaskForm):
    family_income = FloatField('Family Income', validators=[DataRequired()])
    existing_costs = FloatField('Existing Family Costs', validators=[DataRequired()])
    new_service_cost = FloatField('New Service or Upgrade Cost', validators=[DataRequired()])
    submit = SubmitField('Check Affordability')


# Other imports ...

class RegisterServiceForm(FlaskForm):
    service_name = StringField("Service Name", validators=[DataRequired()])
    service_description = TextAreaField("Description", validators=[DataRequired()])
    submit_service = SubmitField("Add Service")
