import bcrypt

from flask import request, jsonify
from datetime import datetime, timedelta
from flask import flash
from flask_session import Session

from bcrypt import checkpw


from flask_login import login_required, current_user, login_user
from flask import Blueprint, render_template
from .extensions import login_manager, mail  # Add the 'mail' import here
from .models import User, Home, Vendor, Service, Promotion, Quote, Contract, Offer, Product

from .forms import UploadProductForm, ServiceQuoteForm, OfferResponseForm, LoginForm, RegistrationForm, HomeForm, ServiceRequestForm, VendorRegistrationForm, QuoteForm, ServiceCalculatorForm

from flask import url_for, current_app
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message

from .extensions import db
from flask import render_template, url_for, flash, redirect

from flask import request
from urllib.parse import urljoin

from werkzeug.security import generate_password_hash, check_password_hash


from .forms import ServiceCalculatorForm, AffordabilityCalculatorForm

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect




routes = Blueprint('routes', __name__)


# Error handling code
@routes.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@routes.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))

@routes.route('/')
@routes.route('/home')
def home():
    print("Rendering main page...")
    form = LoginForm()
    return render_template('main.html', form = form)




@routes.route('/user_login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user:
            flash('Email is not registered. Please register first.', 'danger')
            return redirect(url_for('register'))

        # Check if the hashed password matches the stored hash
        if user and bcrypt.checkpw(form.password.data.encode(), user.password_hash.encode()):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('routes.dashboard'))

        else:
            flash('Login Unsuccessful. Please check your email and password.', 'danger')
    return render_template('user_login.html', title='Login', form=form)




@routes.route("/register", methods=["GET", "POST"])
def register():


    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt())
        hashed_password = hashed_password.decode('utf-8')  # Add this line to convert it to a string

        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        user_role = request.form.get('user_role')  # Get the user_role value from the form

        if user_role == "vendor":
            vendor = Vendor(name=form.username.data, email=form.email.data, phone="0000000000", user_id=user.id)
            db.session.add(vendor)
            db.session.commit()
        else:  # Assuming the user_role is "user"
            # Change the code here to store the available_utilities as a comma-separated string
            available_utilities = ",".join([form.phone_cell.data, form.internet.data])
            home = Home(user_id=user.id, available_utilities=available_utilities)
            db.session.add(home)
            db.session.commit()

        flash("Your account has been created. You can now log in.", "success")
        print("Registration successful, redirecting to main page...")
        return redirect(url_for("routes.home"))

    return render_template("register.html", title="Register", form=form)


@routes.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@routes.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('vendor_dashboard.html')

@routes.route('/vendor/register', methods=['GET', 'POST'])

def vendor_register():
    form = VendorRegistrationForm()
    if form.validate_on_submit():
        vendor = Vendor(name=form.name.data, email=form.email.data, phone=form.phone.data, user_id=current_user.id)
        db.session.add(vendor)
        db.session.commit()
        flash('Your vendor account has been created! You can now log in.', 'success')
        return redirect(url_for('routes.login'))
    return render_template('vendor_register.html', title='Vendor Register', form=form)


@routes.route('/vendor')
def vendors():
    vendors_list = Vendor.query.all()
    return render_template('vendors.html', vendors=vendors_list)



@routes.route('/service/request', methods=['GET', 'POST'])
@login_required
def service_request():
    form = ServiceRequestForm()
    if form.validate_on_submit():
        service = Service(name=form.name.data, category=form.category.data, description=form.description.data)
        db.session.add(service)
        db.session.commit()
        flash('Your service request has been submitted.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('service_request.html', title='Service Request', form=form)

@routes.route('/quote/<int:request_id>', methods=['GET', 'POST'])
@login_required
def submit_quote(request_id):
    service = Service.query.get_or_404(request_id)
    form = QuoteForm()
    if form.validate_on_submit():
        quote = Quote(price=form.price.data, description=form.description.data, service_id=service.id, vendor_id=current_user.id)
        db.session.add(quote)
        db.session.commit()
        flash('Your quote has been submitted.', 'success')
        return redirect(url_for('vendor_dashboard'))
    return render_template('submit_quote.html', title='Submit Quote', form=form, service=service)

@routes.route('/accept_quote/<int:quote_id>')
@login_required
def accept_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    contract = Contract(user_id=current_user.id, service_id=quote.service_id, price=quote.price, description=quote.description, start_date=datetime.utcnow(), end_date=datetime.utcnow() + timedelta(days=365))
    db.session.add(contract)
    db.session.commit()
    flash('The quote has been accepted and a contract has been created.', 'success')
    return redirect(url_for('dashboard'))

@routes.route('/vendor_welcome', methods=['POST'])
def vendor_welcome():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    if user is None:
        flash('Email is not registered. Please register first.', 'error')
        return redirect(url_for('routes.home'))
    else:
        # Perform password validation and log in the user
        if checkpw(password.encode(), user.password_hash):  # Use bcrypt's checkpw method

            # Log in the user
            login_user(user)
            return redirect(url_for('routes.vendor_dashboard'))
        else:
            flash('Incorrect password.', 'error')
            return redirect(url_for('routes.main'))


def send_reset_email(user):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(user.email, salt='password-reset')
    reset_url = urljoin(request.url_root, url_for('routes.reset_password', token=token))

    msg = Message('Password Reset Request',
                  sender=current_app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, then ignore this email.
'''
    mail.send(msg)

@routes.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')

@routes.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=1800)  # token valid for 30 minutes
    except:
        flash('The password reset link is invalid or has expired.', 'warning')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'warning')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password == confirm_password:
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match. Please try again.', 'danger')

    return render_template('reset_password.html')


@routes.route('/handle_product_upload', methods=['POST'])
def handle_product_upload():
    # Add the logic for handling product upload here
    # Store the uploaded data into the database, for example
    pass


@routes.route('/vendor/dashboard', methods=['GET', 'POST'])
@login_required
def vendor_dashboard():
    vendor_id = current_user.id

    upload_product_form = UploadProductForm()
    service_quote_form = ServiceQuoteForm()
    offer_response_form = OfferResponseForm()
    service_calculator_form = ServiceCalculatorForm()  # Add this line
    affordability_calculator_form = AffordabilityCalculatorForm()  # Add this line




    if upload_product_form.validate_on_submit() and upload_product_form.upload.data:
        product_name = upload_product_form.name.data
        product_price = upload_product_form.price.data

        product = Product(name=product_name, price=product_price, vendor_id=vendor_id)
        db.session.add(product)
        db.session.commit()

    if service_quote_form.validate_on_submit() and service_quote_form.submit_quote.data:
        quote_price = service_quote_form.price.data
        quote_description = service_quote_form.description.data
        service_id = 1  # You need to set the service_id for which the quote is being submitted

        quote = Quote(price=quote_price, description=quote_description, service_id=service_id, vendor_id=vendor_id)
        db.session.add(quote)
        db.session.commit()

    if offer_response_form.validate_on_submit() and offer_response_form.submit_response.data:
        offer_id = offer_response_form.offer_id.data
        response = offer_response_form.response.data

        # Update the offer status based on the response
        offer = Offer.query.get(offer_id)
        if offer and offer.vendor_id == vendor_id:
            offer.status = response
            db.session.commit()

    offers = (
    Offer.query
    .with_entities(
        Offer.id, Offer.price, Offer.request_id, Offer.vendor_id, Offer.status, Offer.negotiation
    )
    .filter_by(vendor_id=vendor_id)
    .all()
    )
    products = Product.query.filter_by(vendor_id=vendor_id).all()
    return render_template('vendor_dashboard.html', upload_product_form=upload_product_form, service_quote_form=service_quote_form, offer_response_form=offer_response_form, offers=offers, service_calculator_form=service_calculator_form, affordability_calculator_form=affordability_calculator_form, products=products)



@routes.route('/update_offer_status', methods=['POST'])
@login_required
def update_offer_status():
    offer_id = request.form['offer_id']
    new_status = request.form['new_status']
    offer = Offer.query.get(offer_id)

    if offer:
        offer.status = new_status
        db.commit()
        return jsonify({'result': 'success'})
    else:
        return jsonify({'result': 'error'})



#this is just for testing
@routes.route('/api/add_numbers', methods=['POST'])
def add_numbers():
    data = request.json

    # Extract the numbers from the request data
    number1 = data.get('number1', 0)
    number2 = data.get('number2', 0)

    # Calculate the sum
    result = number1 + number2

    return jsonify({"result": result})



@routes.route('/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    operator = data.get('operator')
    number1 = data.get('number1')
    number2 = data.get('number2')

    try:
        result = perform_operation(operator, number1, number2)
        return jsonify({'result': result, 'error': None})
    except Exception as e:
        return jsonify({'result': None, 'error': str(e)})



@routes.route('/vendor/discover_clients', methods=['POST'])
@login_required
def discover_clients():
    form = ServiceCalculatorForm()
    vendor_id = request.json.get('vendor_id')  # Add this line to get vendor_id from the request body

    if form.validate_on_submit():
        # Extract form values
        phone_cell = form.phone_cell.data
        internet = form.internet.data
        # Add more fields as required

        # Perform client discovery logic using `like()` function
        phone_cell_query = Home.query.filter(Home.available_utilities.like(f"%{phone_cell}%"))
        internet_query = Home.query.filter(Home.available_utilities.like(f"%{internet}%"))
        # Add more queries as required

        # Combine results and remove duplicates
        potential_clients = set(phone_cell_query.union(internet_query))
        
        # Redirect to a new route to show the potential clients
        # Or, you can pass the potential_clients list to the template and display it there
        return render_template('potential_clients.html', potential_clients=potential_clients)

    return redirect(url_for('vendor_dashboard'))

@routes.route('/add_product', methods=['POST'])
@login_required
def add_product():
    data = request.get_json()

    if data:
        product_name = data.get('product_name')
        product_price = data.get('product_price')
        vendor_id = current_user.id

        product = Product(name=product_name, price=product_price, vendor_id=vendor_id)
        db.session.add(product)
        db.session.commit()
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "message": "There was an error adding your product. Please check the form and try again."})


@routes.route('/get_products', methods=['POST'])
def get_products():
    data = request.get_json()
    vendor_id = data['vendor_id']
    products = Product.query.filter_by(vendor_id=vendor_id).all()
    products_data = [{'id': p.id, 'name': p.name, 'price': p.price} for p in products]
    return jsonify(products=products_data)

