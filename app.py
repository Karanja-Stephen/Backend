from flask import Flask, jsonify, request, url_for, redirect, make_response, render_template
from flask_restx import Api, Resource, fields, reqparse, marshal_with
from datetime import timedelta, datetime
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, decode_token
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash, check_password_hash
# from passlib.hash import pbkdf2_sha256
from secrets import token_urlsafe
from itsdangerous import URLSafeTimedSerializer
from flask_cors import CORS
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url
import cloudinary.uploader
import secrets
import requests
import base64
from requests.auth import HTTPBasicAuth
from datetime import datetime
import json
import logging
import africastalking

import pymysql
pymysql.install_as_MySQLdb()

from dotenv import load_dotenv
import os
from DirectPayOnline import DPO

# Load environment variables
load_dotenv()

# Initialize DPO gateway
gateway = DPO()

# CIG Producer Table Models
from models import db, User, Hub, KeyContact, BuyingCenter, CIG, Member, CustomUser, HQUser, HubUser, ProcessingUser, IndividualLogisticianUser, Car, OrganisationLogisticianUser, IndividualCustomerUser, Product, OrganisationCustomerUser, ProducerBiodata, MarketProduce, CommercialProduce, DomesticProduce, FarmerFieldRegistration, CIGProducerBiodata, CIGFarmerFieldRegistration, SeasonPlanning, PlanNutrition, PreventativeDisease, PreventativePest, ScoutingStation, PlanIrrigation, ExtensionService, ExtScoutingStation, PesticideUsed, FertilizerUsed, ForecastYield, Training, Attendance, FarmerPriceDistribution, CustomerPriceDistribution, BuyingFarmer, Quarantine, BuyingCustomer, PaymentFarmer, PaymentCustomer, PlanJourney, DispatchInput, Loading, Offloading, RuralWorker, InputFinance, Processing, Input, ProductMix, AddProduct

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
CORS(app)
app.config.from_object('config.Config')
db.init_app(app)
migrate = Migrate(app, db)
# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_EXPIRATION_DELTA'] = timedelta(days=7)
jwt = JWTManager(app)

# Flask-Mail configuration
# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# debugging on the email verification
app.config['MAIL_DEBUG'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

def send_verification_email(user):
    token = token_urlsafe(16)
    user.verification_token = token
    db.session.commit()

    verification_link = url_for('verify_email', token=token, _external=True)
    message_body = f"Click the following link to verify your email: {verification_link}"

    msg = Message("Email Verification", recipients=[user.email], body=message_body)
    mail.send(msg)

# Define API and models
api = Api(app, version='1.0', title='Farm Data Pod APIs', description='Traceability system')

user_model = api.model('User', {
    'id': fields.Integer,
    'last_name': fields.String,
    'other_name': fields.String,
    'user_type': fields.String,
    'role': fields.String,
    'email': fields.String,
})

user_parser = reqparse.RequestParser()
user_parser.add_argument('last_name', type=str, required=True, help='First name')
user_parser.add_argument('other_name', type=str, required=True, help='Last name')
user_parser.add_argument('role', type=str, required=True, help='User role')
user_parser.add_argument('email', type=str, required=True, help='User email')
user_parser.add_argument('password', type=str, required=True, help='User password')

def send_verification_email(user):
    # Generate a verification token
    verification_token = token_urlsafe(16)
    user.verification_token = verification_token
    db.session.commit()

    # Generate the verification link
    verification_link = api.url_for(EmailVerificationResource, token=verification_token, _external=True)

    # Generate an additional link token with user email
    additional_link_token = token_urlsafe(16)
    additional_link = api.url_for(AdditionalLinkResource, token=additional_link_token, email=user.email, _external=True)

    # Compose the email message
    message_body = f"Click the following link to verify your email: {verification_link}\n"
    message_body += f"Click this to reset your Password: {additional_link}"

    # Send the email
    msg = Message("Email Verification", recipients=[user.email], body=message_body)
    mail.send(msg)

class AdditionalLinkResource(Resource):
    def get(self, token):
        # Extract email from URL parameters
        email = request.args.get('email')

        # Handle additional link logic
        html_content = render_template('reset_password.html', email=email, token=token)
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        return response
api.add_resource(AdditionalLinkResource, '/additional_link_route/<token>')

# Cloudinary endpoint
@app.route('/upload-to-cloudinary', methods=['POST'])
def upload_to_cloudinary():
    try:
        file = request.files['file']
        # Upload file to Cloudinary
        upload_result = cloudinary.uploader.upload(file)

        return jsonify({'secure_url': upload_result['secure_url']}), 200

    except Exception as e:
        return jsonify({'error': 'An internal server error occurred during file upload'}), 500

# Email verification
class EmailVerificationResource(Resource):
    def get(self, token):
        user = User.query.filter_by(verification_token=token).first()

        if user:
            user.email_verified = True
            user.verification_token = None
            db.session.commit()
            html_content = render_template('email_success.html')
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            return response

        html_content = render_template('email_success.html')
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        return response

class VerificationSuccessResource(Resource):
    def get(self):
        app.logger.info('Email verification successful')
        return {'message': 'Email verified successfully'}, 200

api.add_resource(EmailVerificationResource, '/verify_email/<string:token>')
api.add_resource(VerificationSuccessResource, '/verification-success')

# User routes
class UserResource(Resource):
    def get(self):
        users = User.query.all()
        user_list = [user.to_dict() for user in users]
        return jsonify(users=user_list)

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('last_name', type=str, required=True)
        parser.add_argument('other_name', type=str, required=True)
        parser.add_argument('role', type=str, required=True)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        data = parser.parse_args()

        # Check if the email already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return {'error': 'Email already exists'}, 400

        # Determine user_type based on email domain
        user_type = 'admin' if data['email'].endswith('@reactcertafrica.com') else 'user'

        # Create user
        new_user = User(
            last_name=data['last_name'],
            other_name=data['other_name'],
            user_type=user_type,
            role=data['role'],
            email=data['email'],
            # password=pbkdf2_sha256.hash(data['password'])
            password=generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            # Create and return JWT token for immediate login after registration
            access_token = create_access_token(identity=new_user.id, expires_delta=False)
            return {
                'access_token': access_token,
                'user': new_user.to_dict()
            }, 201  

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

api.add_resource(UserResource, '/users')

# User by id endpoint
class UserByIdResource(Resource):
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        return user.to_dict()

    def patch(self, user_id):
        user = User.query.get_or_404(user_id)

        parser = reqparse.RequestParser()
        parser.add_argument('last_name', type=str)
        parser.add_argument('other_name', type=str)
        parser.add_argument('role', type=str)
        parser.add_argument('email', type=str)
        parser.add_argument('password', type=str)
        data = parser.parse_args()

        try:
            # Check if a new password is provided and update it
            new_password = data.get('password')
            if new_password:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)

            # Update specific attributes if they are present in the payload
            if 'last_name' in data and data['last_name'] is not None:
                user.last_name = data['last_name']

            if 'other_name' in data and data['other_name'] is not None:
                user.other_name = data['other_name']

            if 'email' in data and data['email'] is not None:
                user.email = data['email']

            if 'role' in data and data['role'] is not None:
                user.role = data['role']

            db.session.commit()
            return user.to_dict()

        except IntegrityError as e:
            db.session.rollback()
            return {'error': f'Error updating user: {str(e)}'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': f'Error updating user: {str(e)}'}, 500

    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully'}

api.add_resource(UserByIdResource, '/users/<string:user_id>')

# Login endpoint
class LoginResource(Resource):
    """
    User login endpoint.

    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: LoginRequest
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: User's email
            password:
              type: string
              description: User's password
    responses:
      200:
        description: Successfully logged in
        schema:
          id: LoginResponse
          properties:
            access_token:
              type: string
              description: JWT access token
            user_id:
              type: integer
              description: ID of the logged-in user
      401:
        description: Invalid email or password
      500:
        description: Internal server error
    """
    @api.expect(user_parser)

    def post(self):
        data = request.get_json()

        # Check if email and password are provided
        if 'email' not in data or 'password' not in data:
            return {'error': 'Email and password are required'}, 400

        # Retrieve user by email
        user = User.query.filter_by(email=data['email']).first()

        # Check if user exists and if the password is correct
        if user and check_password_hash(user.password, data['password']):
            if not user.email_verified:
                return {'error': 'Email not verified'}, 401

            # Create access token and refresh token
            access_token = create_access_token(identity=user.id, expires_delta=False)
            refresh_token = create_refresh_token(identity=user.id, expires_delta=False)

            return {'access_token': access_token, 'refresh_token': refresh_token, 'user_id': user.id}, 200

        return {'error': 'Invalid email or password'}, 401

    # def post(self):
        data = request.get_json()

        # Check if email and password are provided
        if 'email' not in data or 'password' not in data:
            return {'error': 'Email and password are required'}, 400

        # Retrieve user by email
        user = User.query.filter_by(email=data['email']).first()

        # Check if user exists and if the password is correct
        if user and pbkdf2_sha256.verify(data['password'], user.password):
            if not user.email_verified:
                return {'error': 'Email not verified'}, 401

            # Create access token and refresh token
            access_token = create_access_token(identity=user.id, expires_delta=False)
            refresh_token = create_refresh_token(identity=user.id, expires_delta=False)

            return {'access_token': access_token, 'refresh_token': refresh_token, 'user_id': user.id}, 200

        return {'error': 'Invalid email or password'}, 401
# Add the LoginResource to the API
api.add_resource(LoginResource, '/login')

# Refresh token endpoint
class RefreshResource(Resource):
    def post(self):
        refresh_token = request.json.get('refresh_token')

        if not refresh_token:
            return {'error': 'Refresh token is missing'}, 400

        try:
            # Decode the refresh token to verify its validity
            decoded_token = decode_token(refresh_token)

            # Check if the token has expired
            if datetime.utcfromtimestamp(decoded_token['exp']) < datetime.utcnow():
                return {'error': 'Refresh token has expired'}, 401

            # Get user identity from the token
            user_id = decoded_token['identity']

            # Generate a new access token
            access_token = create_access_token(identity=user_id, expires_delta=False)

            return {'access_token': access_token}, 200
        except Exception as e:
            return {'error': 'Invalid refresh token'}, 401

api.add_resource(RefreshResource, '/refresh')

# Hub Registration endpoint
class HubResource(Resource):
    @jwt_required()
    @api.expect(api.model('Hub', {
        'region': fields.String,
        'hub_name': fields.String,
        'hub_code': fields.String,
        'address': fields.String,
        'year_established': fields.String,
        'ownership': fields.String,
        'floor_size': fields.String,
        'facilities': fields.String,
        'input_center': fields.String,
        'type_of_building': fields.String,
        'latitude': fields.String,
        'longitude': fields.String,
    }))

    @jwt_required()

    def get(self):
        try:
            forms_list = Hub.query.all()
            forms_dict_list = [form.to_dict() for form in forms_list]
            return {'forms': forms_dict_list}, 200

        except Exception as e:
            print(f"Error during retrieving hub registrations: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
        

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            current_user_id = get_jwt_identity()

            new_form = Hub(
                region=data['region'],
                hub_name=data['hub_name'],
                hub_code=data['hub_code'],
                address=data['address'],
                year_established=data['year_established'],
                ownership=data['ownership'],
                floor_size=data['floor_size'],
                facilities=data['facilities'],
                input_center=data['input_center'],
                type_of_building=data['type_of_building'],
                latitude=data['latitude'],
                longitude=data['longitude'],
                user_id=current_user_id
            )

            # Add key contacts
            def parse_date(date_str):
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            if 'key_contacts' in data:
                for key_contact_data in data['key_contacts']:
                    new_key_contact = KeyContact(
                        last_name=key_contact_data['last_name'],
                        other_name=key_contact_data['other_name'],
                        id_number=key_contact_data['id_number'],
                        gender=key_contact_data['gender'],
                        role=key_contact_data['role'],
                        date_of_birth=parse_date(key_contact_data['date_of_birth']),
                        email=key_contact_data['email'],
                        phone_number=key_contact_data['phone_number'],
                    )
                    new_form.key_contacts.append(new_key_contact)

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
   
# Add the HubResource to the API
api.add_resource(HubResource, '/hubs')

# Hub by Id
class HubByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = Hub.query.get_or_404(form_id)
            return form.to_dict(), 200
        except OperationalError as e:
            print(f"OperationalError: {str(e)}")
            return {'error': 'Database operation failed, please try again later.'}, 500
        except Exception as e:
            print(f"Error during retrieving hub registration by ID: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = Hub.query.get_or_404(form_id)
            data = request.get_json()

            form.region = data.get('region', form.region)
            form.hub_name = data.get('hub_name', form.hub_name)
            form.hub_code = data.get('hub_code', form.hub_code)
            form.address = data.get('address', form.address)
            form.ownership = data.get('ownership', form.ownership)
            form.floor_size = data.get('floor_size', form.floor_size)
            form.facilities = data.get('facilities', form.facilities)
            form.input_center = data.get('input_center', form.input_center)
            form.latitude = data.get('latitude', form.latitude)
            form.longitude = data.get('longitude', form.longitude)
            form.year_established = data.get('year_established', form.year_established)

            def parse_date(date_str):
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            if 'key_contacts' in data:
                form.key_contacts[:] = []  # Clear existing key contacts
                for key_contact_data in data['key_contacts']:
                    new_key_contact = KeyContact(
                        last_name=key_contact_data['last_name'],
                        other_name=key_contact_data['other_name'],
                        id_number=key_contact_data['id_number'],
                        gender=key_contact_data['gender'],
                        role=key_contact_data['role'],
                        date_of_birth=parse_date(key_contact_data['date_of_birth']),
                        email=key_contact_data['email'],
                        phone_number=key_contact_data['phone_number'],
                    )
                    form.key_contacts.append(new_key_contact)

            db.session.commit()
            return form.to_dict(), 200

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {str(e)}")
            return {'error': 'Kindly correctly fill the form'}, 400
        except NoResultFound as e:
            db.session.rollback()
            print(f"NoResultFound: {str(e)}")
            return {'error': 'Hub registration not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Exception: {str(e)}")
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = Hub.query.get_or_404(form_id)
            db.session.delete(form)
            db.session.commit()
            return {'message': 'Form deleted successfully'}, 200

        except NoResultFound as e:
            db.session.rollback()
            print(f"NoResultFound: {str(e)}")
            return {'error': 'Hub registration not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Exception: {str(e)}")
            return {'error': str(e)}, 500

api.add_resource(HubByIdResource, '/hubs/<int:form_id>')

# Buying Center Endpoints
class BuyingCentersResource(Resource):
    @jwt_required()
    @api.expect(api.model('BuyingCenterRegistration', {
        'hub': fields.String,
        'county': fields.String,
        'buying_center_name': fields.String,
        'buying_center_code': fields.String,
        'address': fields.String,
        'year_established': fields.String,
        'ownership': fields.String,
        'floor_size': fields.String,
        'facilities': fields.String,
        'input_center': fields.String,
        'type_of_building': fields.String,
        'location': fields.String,
    }))
    @jwt_required()

    def get(self):
        try:
            forms_list = BuyingCenter.query.all()
            forms_dict_list = [form.to_dict() for form in forms_list]
            return {'forms': forms_dict_list}, 200

        except Exception as e:
            print(f"Error during retrieving buying center registrations: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
        
    @jwt_required()

    def post(self):
        try:
            data = request.get_json()
            current_user_id = get_jwt_identity()

            new_form = BuyingCenter(
                hub=data['hub'],
                county=data['county'],
                sub_county=data['sub_county'],
                ward=data['ward'],
                village=data['village'],
                buying_center_name=data['buying_center_name'],
                buying_center_code=data['buying_center_code'],
                address=data['address'],
                year_established=data['year_established'],
                ownership=data['ownership'],
                floor_size=data['floor_size'],
                facilities=data['facilities'],
                input_center=data['input_center'],
                type_of_building=data['type_of_building'],
                location=data['location'],
                user_id=current_user_id
            )

            # Add key contacts
            def parse_date(date_str):
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            if 'key_contacts' in data:
                for key_contact_data in data['key_contacts']:
                    new_key_contact = KeyContact(
                        last_name=key_contact_data['last_name'],
                        other_name=key_contact_data['other_name'],
                        id_number=key_contact_data['id_number'],
                        gender=key_contact_data['gender'],
                        role=key_contact_data['role'],
                        date_of_birth=parse_date(key_contact_data['date_of_birth']),
                        email=key_contact_data['email'],
                        phone_number=key_contact_data['phone_number'],
                    )
                    new_form.key_contacts.append(new_key_contact)

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add the BuyingCentersResource to the API
api.add_resource(BuyingCentersResource, '/buying-centers')

# Aggregation Buying Center by Id
class BuyingCenterByIdResource(Resource):
    @jwt_required()

    def get(self, buyingcenter_id):
        try:
            buying_center = BuyingCenter.query.get(buyingcenter_id)
            if buying_center:
                return buying_center.to_dict(), 200
            else:
                return {'error': 'Buying center not found'}, 404

        except Exception as e:
            print(f"Error during retrieving buying center by ID: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def patch(self, buyingcenter_id):
        try:
            form = BuyingCenter.query.get_or_404(buyingcenter_id)
            data = request.get_json()

            # Validate required fields
            required_fields = ['hub', 'county', 'sub_county', 'ward', 'village', 'buying_center_name', 'buying_center_code', 'address', 'ownership', 'floor_size', 'facilities', 'input_center', 'location']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Update form fields
            form.hub = data['hub']
            form.county = data['county']
            form.sub_county = data['sub_county']
            form.ward = data['ward']
            form.village = data['village']
            form.buying_center_name = data['buying_center_name']
            form.buying_center_code = data['buying_center_code']
            form.address = data['address']
            form.ownership = data['ownership']
            form.floor_size = data['floor_size']
            form.facilities = data['facilities']
            form.input_center = data['input_center']
            form.location = data['location']
            form.year_established = datetime.strptime(data.get('year_established', form.year_established), '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d')

            # Update key contacts if provided
            def parse_date(date_str):
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                
            if 'key_contacts' in data:
                form.key_contacts[:] = []  # Clear existing key contacts
                for key_contact_data in data['key_contacts']:
                    new_key_contact = KeyContact(
                        last_name=key_contact_data['last_name'],
                        other_name=key_contact_data['other_name'],
                        id_number=key_contact_data['id_number'],
                        gender=key_contact_data['gender'],
                        role=key_contact_data['role'],
                        date_of_birth=parse_date(key_contact_data['date_of_birth']),
                        email=key_contact_data['email'],
                        phone_number=key_contact_data['phone_number'],
                    )
                    form.key_contacts.append(new_key_contact)

            db.session.commit()
            return form.to_dict(), 200

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Kindly correctly fill the form'}, 400

        except NoResultFound:
            db.session.rollback()
            return {'error': 'Buying Center registration not found'}, 404

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()

    def delete(self, buyingcenter_id):
        try:
            form = BuyingCenter.query.get_or_404(buyingcenter_id)
            db.session.delete(form)
            db.session.commit()
            return {'message': 'Form deleted successfully'}, 200

        except NoResultFound:
            db.session.rollback()
            return {'error': 'Buying Center registration not found'}, 404

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Add the BuyingCenterByIdResource to the API
api.add_resource(BuyingCenterByIdResource, '/buying-centers/<int:buyingcenter_id>')


# Define a model for members
member_model = api.model('Member', {
    'other_name': fields.String(required=True, description='other mane'),
    'last_name': fields.String(required=True, description='member position'),
    'date_of_birth': fields.String(required=True, description='member dob'),
    'id_number': fields.String(required=True, description='member id number'),
    'email': fields.String(required=True, description='member email'),
    'phone_number': fields.String(required=True, description='member phone number'),
    'gender': fields.String(required=True, description='member gender'),
    'product_involved': fields.String(required=True, description='member product'),
    'hectorage_registered_under_cig': fields.String(required=True, description='member hectorage')
})

class CIGResource(Resource):
    @jwt_required()
    @api.expect(api.model('CIGRegistration', {
        "cig_name": fields.String(required=True, description='CIG name'),
        "hub": fields.String(required=True, description='Hub'),
        "date_established": fields.String(required=True, description='Date of establishment'),
        "no_of_members": fields.String(required=True, description='Number of members'),
        "constitution": fields.String(required=True, description='Constitution details'),
        "registration": fields.String(required=True, description='Registration details'),
        "elections_held": fields.String(required=True, description='Elections held details'),
        "date_of_last_elections": fields.String(required=True, description='Date of last elections'),
        "meeting_venue": fields.String(required=True, description='Meeting venue details'),
        "frequency": fields.String(required=True, description='Frequency details'),
        "scheduled_meeting_day": fields.String(required=True, description='Scheduled meeting day'),
        "scheduled_meeting_time": fields.String(required=True, description='Scheduled meeting time'),
        "members": fields.List(fields.Nested(member_model), required=True, description='List of members')
    }))
    @jwt_required()
    def get(self):
        forms_list = CIG.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            user_id = get_jwt_identity()

            args = api.payload 

            def parse_date(date_str):
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            cig_data = {
                'hub': args['hub'],
                'cig_name': args['cig_name'],
                'date_established': parse_date(args['date_established']),
                'no_of_members': args['no_of_members'],
                'constitution': args['constitution'],
                'registration': args['registration'],
                'elections_held': args['elections_held'],
                'date_of_last_elections': parse_date(args['date_of_last_elections']),
                'meeting_venue': args['meeting_venue'],
                'frequency': args['frequency'],
                'scheduled_meeting_day': args['scheduled_meeting_day'],
                'scheduled_meeting_time': args['scheduled_meeting_time'],
            }

            new_form = CIG(**cig_data)
            user = User.query.get(user_id)
            new_form.user = user

            db.session.add(new_form)
            db.session.commit()

            def parse_date(date_string):
                # Parse the date using the specified format
                return datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S')

            # Inside your loop
            for member_data in args['members']:
                new_member = Member(
                    last_name=member_data['last_name'],
                    other_name=member_data['other_name'],
                    gender=member_data['gender'],
                    date_of_birth=member_data['date_of_birth'],
                    email=member_data['email'],
                    phone_number=member_data['phone_number'],
                    id_number=member_data['id_number'],
                    product_involved=member_data['product_involved'],
                    hectorage_registered_under_cig=member_data['hectorage_registered_under_cig']
                )

                new_form.members.append(new_member)

            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGResource, '/cigs')

# CIG by Id endpoint
class CIGResource(Resource):
    @jwt_required()

    def get(self, form_id):
        try:
            form = CIG.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def patch(self, form_id):
        try:
            form = CIG.query.get(form_id)

            if form:
                data = request.get_json()

                form.date_established = datetime.strptime(data.get('date_established'), "%Y-%m-%dT%H:%M:%S")
                form.date_of_last_elections = datetime.strptime(data.get('date_of_last_elections'), "%Y-%m-%dT%H:%M:%S")

                form.cig_name = data.get('cig_name', form.cig_name)
                form.hub = data.get('hub', form.hub)
                form.constitution = data.get('constitution', form.constitution)
                form.registration = data.get('registration', form.registration)
                form.elections_held = data.get('elections_held', form.elections_held)
                form.meeting_venue = data.get('meeting_venue', form.meeting_venue)
                form.frequency = data.get('frequency', form.frequency)
                form.scheduled_meeting_day = data.get('scheduled_meeting_day', form.scheduled_meeting_day)
                form.scheduled_meeting_time = data.get('scheduled_meeting_time', form.scheduled_meeting_time)
                form.no_of_members = data.get('no_of_members', form.no_of_members)

                form.members = [Member(**member) for member in data.get('members', form.members)]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def delete(self, form_id):
        try:
            form = CIG.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGResource, '/cigs/<int:form_id>')

# Users Endpoints
# Custom Users
custom_users_fields = {
    'id': fields.Integer,
    'other_name': fields.String,
    'last_name': fields.String,
    'staff_code': fields.String,
    'id_number': fields.String,
    'gender': fields.String,
    'role': fields.String,
    'date_of_birth': fields.String,
    'email': fields.String,
    'phone_number': fields.String,
    'education_level': fields.String,
    'reporting_to': fields.String,
    'user_id': fields.String,
}

class CustomUsersResource(Resource):

    @jwt_required()
    def options(self):
        return {}, 200

    @jwt_required()
    @marshal_with(custom_users_fields)
    def get(self):
        forms_list = CustomUser.query.all()
        return forms_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            current_user_id = get_jwt_identity()

            # Check if the email already exists in the User table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Create corresponding User in the users table
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='Custom User',
                role=data['role'],
                email=data['email'],
                password=generate_password_hash('Password@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            # Log the newly created user details
            print(f"New User created: {new_user.to_dict()}")

            # Create corresponding CustomUser
            new_form = CustomUser(
                other_name=data['other_name'],
                last_name=data['last_name'],
                staff_code=data['staff_code'],
                role=data['role'],
                reporting_to=data['reporting_to'],
                id_number=data['id_number'],
                gender=data['gender'],
                date_of_birth=data['date_of_birth'],
                email=data['email'],
                phone_number=data['phone_number'],
                education_level=data['education_level'],
                user_id=new_user.id
            )

            db.session.add(new_form)
            db.session.commit()

            # return new_form, 201
            response_dict = new_form.to_dict()
            return response_dict, 201

        except KeyError as e:
            db.session.rollback()
            return {'error': f'Missing required field: {e.args[0]}'}, 400

        except IntegrityError as e:
            db.session.rollback()
            return {'error': 'Email or HQ code already exists'}, 400

        except Exception as e:
            db.session.rollback()
            print(f'An unexpected error occurred: {str(e)}')
            return {'error': 'An unexpected error occurred'}, 500

api.add_resource(CustomUsersResource, '/custom-users')

# Custom Users by Id
class CustomUsersByIdResource(Resource):
    @jwt_required()
    @marshal_with(custom_users_fields)
    def get(self, form_id):
        form = CustomUser.query.get_or_404(form_id)
        return form

    @jwt_required()
    @marshal_with(custom_users_fields)
    def patch(self, form_id):
        form = CustomUser.query.get_or_404(form_id)

        try:
            data = request.get_json()

            # Validate required fields
            required_fields = ['other_name', 'last_name', 'staff_code', 'id_number', 'gender', 'date_of_birth', 'email', 'phone_number', 'education_level', 'role', 'reporting_to']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Update form fields
            for key, value in data.items():
                setattr(form, key, value)

            db.session.commit()
            return form

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Kindly correctly fill the form'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = CustomUser.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(CustomUsersByIdResource, '/custom-users/<int:form_id>')


# HQ Users
hq_users_fields = {
    'id': fields.Integer,
    'other_name': fields.String,
    'last_name': fields.String,
    'staff_code': fields.String,
    'id_number': fields.String,
    'gender': fields.String,
    'date_of_birth': fields.String,
    'email': fields.String,
    'phone_number': fields.String,
    'education_level': fields.String,
    'role': fields.String,
    'reporting_to': fields.String,
    'related_roles': fields.String,
    'department': fields.String,
    'user_id': fields.String,
}

class HQUsersResource(Resource):

    @jwt_required()
    def options(self):
        return {}, 200

    @jwt_required()
    @marshal_with(hq_users_fields)
    def get(self):
        try:
            forms_list = HQUser.query.all()
            return forms_list, 200
        except Exception as e:
            return {'error': str(e)}, 500

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            current_user_id = get_jwt_identity()

            # Validate input data
            required_fields = ['last_name', 'other_name', 'staff_code', 'role', 'email']
            if not all(key in data for key in required_fields):
                return {'error': 'Missing required fields'}, 400

            # Check if the email already exists
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Check if the ID number already exists
            existing_hq_user = HQUser.query.filter_by(id_number=data.get('id_number')).first()
            if existing_hq_user:
                return {'error': 'ID number already exists'}, 400

            # Parse date_of_birth to ensure it's a date object
            try:
                date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%dT%H:%M:%S') if data.get('date_of_birth') else None
            except (ValueError, TypeError):
                return {'error': 'Invalid date format for date_of_birth'}, 400

            # Create new user
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='HQ User',
                role=data['role'],
                email=data['email'],
                password=generate_password_hash('Password@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            # Log the newly created user details
            logging.info(f"New User created: {new_user.to_dict()}")

            # Create corresponding HQUser
            new_form = HQUser(
                other_name=data['other_name'],
                last_name=data['last_name'],
                staff_code=data['staff_code'],
                role=data['role'],
                department=data.get('department'),
                related_roles=data.get('related_roles'),
                reporting_to=data.get('reporting_to'),
                id_number=data.get('id_number'),
                gender=data.get('gender'),
                date_of_birth=date_of_birth,
                email=data['email'],
                phone_number=data.get('phone_number'),
                education_level=data.get('education_level'),
                user_id=new_user.id
            )

            db.session.add(new_form)
            db.session.commit()

            # Prepare response data and ensure all datetime objects are serialized
            response_dict = {
                'other_name': new_form.other_name,
                'last_name': new_form.last_name,
                'staff_code': new_form.staff_code,
                'role': new_form.role,
                'department': new_form.department,
                'related_roles': new_form.related_roles,
                'reporting_to': new_form.reporting_to,
                'id_number': new_form.id_number,
                'gender': new_form.gender,
                'date_of_birth': new_form.date_of_birth.strftime('%Y-%m-%dT%H:%M:%S') if new_form.date_of_birth else None,
                'email': new_form.email,
                'phone_number': new_form.phone_number,
                'education_level': new_form.education_level,
                'user_id': new_form.user_id
            }

            return response_dict, 201

        except KeyError as e:
            db.session.rollback()
            return {'error': f'Missing required field: {e.args[0]}'}, 400

        except IntegrityError as e:
            db.session.rollback()
            if 'email' in str(e.orig):
                return {'error': 'Email already exists'}, 400
            if 'id_number' in str(e.orig):
                return {'error': 'ID number already exists'}, 400
            return {'error': 'Integrity error'}, 400

        except Exception as e:
            db.session.rollback()
            logging.error(f'An unexpected error occurred: {str(e)}')
            return {'error': 'An unexpected error occurred'}, 500
    
api.add_resource(HQUsersResource, '/hq-users')

# HQ Users by Id
class HQUsersByIdResource(Resource):
    @jwt_required()
    @marshal_with(hq_users_fields)
    def get(self, form_id):
        form = HQUser.query.get_or_404(form_id)
        return form

    @jwt_required()
    @marshal_with(hq_users_fields)
    def patch(self, form_id):
        form = HQUser.query.get_or_404(form_id)

        try:
            data = request.get_json()

            # Validate required fields
            required_fields = ['other_name', 'last_name', 'staff_code', 'id_number', 'gender', 'date_of_birth', 'email', 'phone_number', 'education_level', 'role', 'related_roles', 'department']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Update form fields
            for key, value in data.items():
                setattr(form, key, value)

            db.session.commit()
            return form

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Kindly correctly fill the form'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = HQUser.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(HQUsersByIdResource, '/hq-users/<int:form_id>')

# Hub Attendant Users Resource

parser = reqparse.RequestParser()

hub_users_fields = {
    'id': fields.Integer,
    'other_name': fields.String,
    'last_name': fields.String,
    'code': fields.String,
    'id_number': fields.String,
    'gender': fields.String,
    'date_of_birth': fields.String,
    'email': fields.String,
    'phone_number': fields.String,
    'education_level': fields.String,
    'role': fields.String,
    'county': fields.String,
    'sub_county': fields.String,
    'ward': fields.String,
    'village': fields.String,
    'hub': fields.String,
    'buying_center': fields.String,
    'user_id': fields.String,
}
class HubUsersResource(Resource):

    @jwt_required()
    def options(self):
        return {}, 200

    @jwt_required()
    @marshal_with(hub_users_fields)
    def get(self):
        try:
            forms_list = HubUser.query.all()
            return forms_list, 200
        except Exception as e:
            return {'error': str(e)}, 500

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            current_user_id = get_jwt_identity()

            # Validate input data
            required_fields = ['last_name', 'other_name', 'code', 'role', 'email']
            if not all(key in data for key in required_fields):
                return {'error': 'Missing required fields'}, 400

            # Check if the email already exists
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Check if the ID number already exists
            existing_hub_user = HubUser.query.filter_by(id_number=data.get('id_number')).first()
            if existing_hub_user:
                return {'error': 'ID number already exists'}, 400

            # Parse date_of_birth to ensure it's a date object
            try:
                date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%dT%H:%M:%S')
            except (ValueError, TypeError):
                return {'error': 'Invalid date format for date_of_birth'}, 400

            # Create new user
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='Hub User',
                role=data['role'],
                email=data['email'],
                password=generate_password_hash('Password@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            # Log the newly created user details
            app.logger.info(f"New User created: {new_user.to_dict()}")

            # Create corresponding HubUser
            new_form = HubUser(
                other_name=data['other_name'],
                last_name=data['last_name'],
                code=data['code'],
                role=data['role'],
                county=data.get('county'),
                sub_county=data.get('sub_county'),
                ward=data.get('ward'),
                village=data.get('village'),
                id_number=data.get('id_number'),
                gender=data.get('gender'),
                date_of_birth=date_of_birth,
                hub=data.get('hub'),
                buying_center=data.get('buying_center'),
                email=data['email'],
                phone_number=data.get('phone_number'),
                education_level=data.get('education_level'),
                user_id=new_user.id
            )

            db.session.add(new_form)
            db.session.commit()

            # Convert date_of_birth to string format for JSON response
            response_dict = new_form.to_dict()
            if 'date_of_birth' in response_dict:
                response_dict['date_of_birth'] = response_dict['date_of_birth'].strftime('%Y-%m-%dT%H:%M:%S')

            return response_dict, 201

        except KeyError as e:
            db.session.rollback()
            return {'error': f'Missing required field: {e.args[0]}'}, 400

        except IntegrityError as e:
            db.session.rollback()
            if 'email' in str(e.orig):
                return {'error': 'Email already exists'}, 400
            if 'id_number' in str(e.orig):
                return {'error': 'ID number already exists'}, 400
            return {'error': 'Integrity error'}, 400

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'An unexpected error occurred: {str(e)}')
            return {'error': 'An unexpected error occurred'}, 500
        
api.add_resource(HubUsersResource, '/hub-users')

# Hub Attendant Users by ID Resource
class HubUsersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = HubUser.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        form = HubUser.query.get_or_404(form_id)

        try:
            parser.add_argument('other_name', type=str, required=True)
            parser.add_argument('last_name', type=str, required=True)
            parser.add_argument('code', type=str, required=True)
            parser.add_argument('role', type=str, required=True)
            parser.add_argument('id_number', type=str, required=True)
            parser.add_argument('gender', type=str, required=True)
            parser.add_argument('date_of_birth', type=str, required=True)
            parser.add_argument('email', type=str, required=True)
            parser.add_argument('phone_number', type=str, required=True)
            parser.add_argument('education_level', type=str, required=True)
            parser.add_argument('hub', type=str, required=True)
            parser.add_argument('county', type=str, required=True)
            parser.add_argument('sub_county', type=str, required=True)
            parser.add_argument('ward', type=str, required=True)
            parser.add_argument('village', type=str, required=True)
            parser.add_argument('role', type=str, required=True)

            data = parser.parse_args()

            # Validate required fields
            required_fields = ['other_name', 'last_name', 'code', 'role', 'id_number', 'gender', 'date_of_birth', 'email', 'phone_number', 'education_level', 'hub', 'county', 'sub_county', 'ward', 'village']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Update form fields
            for key, value in data.items():
                setattr(form, key, value)

            db.session.commit()
            return form.to_dict()

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Kindly correctly fill the form'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = HubUser.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(HubUsersByIdResource, '/hub-users/<int:form_id>')

# Processing Users Resource
class ProcessingUsersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = ProcessingUser.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if the email already exists in the users table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400
            current_user_id = get_jwt_identity()

            # Create a corresponding User in the users table
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='Processing User',
                role='Processing User',
                email=data['email'],
                password=generate_password_hash('YourDefaultPassword', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            # Create corresponding ProcessingAssistantUser
            new_form = ProcessingUser(
                other_name=data['other_name'],
                last_name=data['last_name'],
                processor_code=data['processor_code'],
                processing_plant=data['processing_plant'],
                id_number=data['id_number'],
                gender=data['gender'],
                date_of_birth=data['date_of_birth'],
                email=data['email'],
                phone_number=data['phone_number'],
                education_level=data['education_level'],
                hub=data['hub'],
                buying_center=data['buying_center'],
                county=data['county'],
                sub_county=data['sub_county'],
                ward=data['ward'],
                village=data['village'],
                user_id=new_user.id
            )

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except IntegrityError as e:
            db.session.rollback()
            return {'error': 'Email or Staff code already exists'}, 400

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(ProcessingUsersResource, '/processing-users')

class ProcessingUsersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        # Retrieve a processing user by ID
        form = ProcessingUser.query.get_or_404(form_id)
        return form.to_dict(), 200

    @jwt_required()
    def patch(self, form_id):
        # Update an existing processing user by ID
        form = ProcessingUser.query.get_or_404(form_id)

        try:
            data = request.get_json()

            # Validate required fields
            required_fields = [
                'other_name', 'last_name', 'processor_code', 'processing_plant',
                'id_number', 'gender', 'date_of_birth', 'email', 'phone_number',
                'education_level', 'hub', 'buying_center', 'county', 'sub_county',
                'ward', 'village'
            ]
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Validate date_of_birth format
            try:
                date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                return {'error': 'Invalid date_of_birth format. Use %Y-%m-%dT%H:%M:%S.'}, 400

            # Update form fields
            form.other_name = data['other_name']
            form.last_name = data['last_name']
            form.processor_code = data['processor_code']
            form.processing_plant = data['processing_plant']
            form.id_number = data['id_number']
            form.gender = data['gender']
            form.date_of_birth = date_of_birth
            form.email = data['email']
            form.phone_number = data['phone_number']
            form.education_level = data['education_level']
            form.hub = data['hub']
            form.buying_center = data['buying_center']
            form.county = data['county']
            form.sub_county = data['sub_county']
            form.ward = data['ward']
            form.village = data['village']

            db.session.commit()
            return form.to_dict(), 200

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Integrity error occurred. Check your inputs.'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        # Delete a processing user by ID
        form = ProcessingUser.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Processing user deleted successfully'}, 200
    
api.add_resource(ProcessingUsersByIdResource, '/processing-users/<int:form_id>')

# Logistician Endpoints
# Individual Logistician Resource
class IndividualLogisticianResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = IndividualLogisticianUser.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if the email already exists in the users table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Extract Individual logistician's data
            individual_logistician_data = {
                'other_name': data['other_name'],
                'date_of_birth': datetime.strptime(data['date_of_birth'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'last_name': data['last_name'],
                'logistician_code': data['logistician_code'],
                'id_number': data['id_number'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'address': data['address'],
                'hub': data['hub'],
                'region': data['region'],
            }

            # Create a new Individual Logistician User instance
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='Individual Logistician',
                role='Individual Logistician',
                email=data['email'],
                password=generate_password_hash('YourIndividualLogisticianDe@faultPassword', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            new_form = IndividualLogisticianUser(**individual_logistician_data)
            new_form.user = new_user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract cars data
            cars_data = data.get('cars', [])
            for car_data in cars_data:
                new_car = Car(**car_data)
                new_form.cars.append(new_car)

            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add your resource to the API
api.add_resource(IndividualLogisticianResource, '/individual-logistician-users')

class IndividualLogisticianByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = IndividualLogisticianUser.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = IndividualLogisticianUser.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                date_of_birth_str = data.get('date_of_birth')
                form.date_of_birth = datetime.strptime(date_of_birth_str, "%m/%d/%Y %I:%M %p") if date_of_birth_str else form.date_of_birth

                form.other_name = data.get('other_name', form.other_name)
                form.last_name = data.get('last_name', form.last_name)
                form.logistician_code = data.get('logistician_code', form.logistician_code)
                form.id_number = data.get('id_number', form.id_number)
                form.email = data.get('email', form.email)
                form.phone_number = data.get('phone_number', form.phone_number)
                form.address = data.get('address', form.address)
                form.hub = data.get('hub', form.hub)
                form.region = data.get('region', form.region)
                
                form.cars = [Car(**car) for car in data.get('cars', form.cars)]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = IndividualLogisticianUser.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(IndividualLogisticianByIdResource, '/individual-logistician-users/<int:form_id>')

# Organisation Logistician Endpoints
class OrganisationLogisticianResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = OrganisationLogisticianUser.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if the email already exists in the users table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Extract company logistician's data
            company_logistician_data = {
                'name': data['name'],
                'date_of_registration': datetime.strptime(data['date_of_registration'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'logistician_code': data['logistician_code'],
                'registration_number': data['registration_number'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'address': data['address'],
                'hub': data['hub'],
                'region': data['region'],
            }

            # Create a new Organisation Logistician User instance
            new_user = User(
                last_name=data['name'], 
                other_name=data['name'], 
                user_type='Organisation Logistician',
                role='Organisation Logistician',
                email=data['email'],
                password=generate_password_hash('YourCompanyLogisticianDefaultPassword@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            new_form = OrganisationLogisticianUser(**company_logistician_data)
            new_form.user = new_user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract cars data
            cars_data = data.get('cars', [])
            for car_data in cars_data:
                new_car = Car(**car_data)
                new_form.cars.append(new_car)

            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add your resource to the API
api.add_resource(OrganisationLogisticianResource, '/organisation-logistician-users')
class OrganisationLogisticianByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = OrganisationLogisticianUser.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = OrganisationLogisticianUser.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                date_of_registration_str = data.get('date_of_registration')
                form.date_of_registration = datetime.strptime(date_of_registration_str, "%m/%d/%Y %I:%M %p") if date_of_registration_str else form.date_of_registration

                form.name = data.get('name', form.name)
                form.logistician_code = data.get('logistician_code', form.logistician_code)
                form.registration_number = data.get('registration_number', form.registration_number)
                form.email = data.get('email', form.email)
                form.phone_number = data.get('phone_number', form.phone_number)
                form.address = data.get('address', form.address)
                form.hub = data.get('hub', form.hub)
                form.region = data.get('region', form.region)

                form.cars = [Car(**car) for car in data.get('cars', form.cars)]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = OrganisationLogisticianUser.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(OrganisationLogisticianByIdResource, '/organisation-logistician-users/<int:form_id>')

# Customer Users Endpoints
# Individual Customer Resource
class IndividualCustomerResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = IndividualCustomerUser.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if the email already exists in the users table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Extract Individual customer's data
            individual_customer_data = {
                'other_name': data['other_name'],
                'date_of_birth': datetime.strptime(data['date_of_birth'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'last_name': data['last_name'],
                'customer_code': data['customer_code'],
                'gender': data['gender'],
                'id_number': data['id_number'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'county': data['county'],
                'sub_county': data['sub_county'],
                'ward': data['ward'],
                'village': data['village']
            }

            # Create a new Individual Customer User instance
            new_user = User(
                last_name=data['last_name'],
                other_name=data['other_name'],
                user_type='Individual Customer',
                role='Individual Customer',
                email=data['email'],
                password=generate_password_hash('YourIndividualCust@omerDefaultPass#word@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            new_form = IndividualCustomerUser(**individual_customer_data)
            new_form.user = new_user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract products data
            products_data = data.get('products', [])
            for product_data in products_data:
                new_product = Product(**product_data)
                new_form.products.append(new_product)

            db.session.commit()

            # Send email to admin for authorization
            send_authorisation_email(new_form)

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add your resource to the API
api.add_resource(IndividualCustomerResource, '/individual-customer-users')

def send_authorisation_email(user):
    try:
        # Generate a token for authorisation
        token = serializer.dumps(user.id, salt='authorisation')

        # Build the authorisation link
        authorisation_link = url_for('authorize_user_resource', token=token, _external=True)

        # Send the email to the admin
        admin_email = 'skaranja654@gmail.com'
        msg = Message('Authorisation Request', sender='sakakeja.ke@gmail.com', recipients=[admin_email])
        msg.body = f"A new user has registered. Click the link to authorise: {authorisation_link}"
        mail.send(msg)

    except Exception as e:
        app.logger.error(f"Error sending authorisation email: {str(e)}")
        raise

class AuthorizeUserResource(Resource):
    def get(self, token):
        try:
            user_id = serializer.loads(token, salt='authorisation', max_age=84600)
            user = IndividualCustomerUser.query.get(user_id)

            if user:
                user.user_authorised = True
                db.session.commit()
                html_content = render_template('authorisation_success.html')
                response = make_response(html_content)
                response.headers['Content-Type'] = 'text/html'
                return response 

            html_content = render_template('authorisation_success.html')
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            return response 

        except Exception as e:
            print(f'authorisation_success: {token}')
            return {'message': 'authorisation_success'}, 200

api.add_resource(AuthorizeUserResource, '/authorise_user/<token>')

class IndividualCustomerByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = IndividualCustomerUser.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = IndividualCustomerUser.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.date_of_birth = datetime.strptime(data.get('date_of_birth'), "%m/%d/%Y %I:%M %p")

                form.other_name = data.get('other_name', form.other_name)
                form.last_name = data.get('last_name', form.last_name)
                form.customer_code = data.get('customer_code', form.customer_code)
                form.id_number = data.get('id_number', form.id_number)
                form.email = data.get('email', form.email)
                form.phone_number = data.get('phone_number', form.phone_number)
                form.county = data.get('county', form.county)
                form.sub_county = data.get('sub_county', form.sub_county)
                form.ward = data.get('ward', form.ward)
                form.village = data.get('village', form.village)

                form.products = [Product(**product) for product in data.get('products', form.products)]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = IndividualCustomerUser.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(IndividualCustomerByIdResource, '/individual-customer-users/<int:form_id>')

# Organisation customer
# Organisation Customer Resource
class OrganisationCustomerResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('company_name', type=str, required=True)
    parser.add_argument('date_of_registration', type=str, required=True)
    parser.add_argument('customer_code', type=str, required=True)
    parser.add_argument('registration_number', type=str, required=True)
    parser.add_argument('sector', type=str, required=True)
    parser.add_argument('email', type=str, required=True)
    parser.add_argument('phone_number', type=str, required=True)
    parser.add_argument('county', type=str, required=True)
    parser.add_argument('sub_county', type=str, required=True)
    parser.add_argument('ward', type=str, required=True)
    parser.add_argument('village', type=str, required=True)
    parser.add_argument('other_name1', type=str, required=True)
    parser.add_argument('last_name1', type=str, required=True)
    parser.add_argument('id_number1', type=str, required=True)
    parser.add_argument('gender1', type=str, required=True)
    parser.add_argument('email1', type=str, required=True)
    parser.add_argument('phone_number1', type=str, required=True)
    parser.add_argument('date_of_birth1', type=str, required=True)
    parser.add_argument('other_name2', type=str, required=True)
    parser.add_argument('last_name2', type=str, required=True)
    parser.add_argument('id_number2', type=str, required=True)
    parser.add_argument('gender2', type=str, required=True)
    parser.add_argument('email2', type=str, required=True)
    parser.add_argument('phone_number2', type=str, required=True)
    parser.add_argument('date_of_birth2', type=str, required=True)
    parser.add_argument('other_name3', type=str, required=True)
    parser.add_argument('last_name3', type=str, required=True)
    parser.add_argument('id_number3', type=str, required=True)
    parser.add_argument('gender3', type=str, required=True)
    parser.add_argument('email3', type=str, required=True)
    parser.add_argument('phone_number3', type=str, required=True)
    parser.add_argument('date_of_birth3', type=str, required=True)

    # Add a parser argument for 'products'
    parser.add_argument('products', type=list, required=True, location='json')

    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return '', 200

    @jwt_required()
    def get(self):
        forms_list = OrganisationCustomerUser.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = self.parser.parse_args()

            # Check if the email already exists in the users table
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'Email already exists'}, 400

            # Extract company customer's data
            company_customer_data = {
                'company_name': data['company_name'],
                'date_of_registration': datetime.strptime(data['date_of_registration'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'customer_code': data['customer_code'],
                'registration_number': data['registration_number'],
                'sector': data['sector'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'county': data['county'],
                'sub_county': data['sub_county'],
                'ward': data['ward'],
                'village': data['village'],
                'other_name1': data['other_name1'],
                'last_name1': data['last_name1'],
                'id_number1': data['id_number1'],
                'gender1': data['gender1'],
                'email1': data['email1'],
                'phone_number1': data['phone_number1'],
                'date_of_birth1': datetime.strptime(data['date_of_birth1'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'other_name2': data['other_name2'],
                'last_name2': data['last_name2'],
                'id_number2': data['id_number2'],
                'gender2': data['gender2'],
                'email2': data['email2'],
                'phone_number2': data['phone_number2'],
                'date_of_birth2': datetime.strptime(data['date_of_birth2'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'other_name3': data['other_name3'],
                'last_name3': data['last_name3'],
                'id_number3': data['id_number3'],
                'gender3': data['gender3'],
                'email3': data['email3'],
                'phone_number3': data['phone_number3'],
                'date_of_birth3': datetime.strptime(data['date_of_birth3'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
            }

            # Create a new Company Customer User instance
            new_user = User(
                last_name='Organisation Customer',
                other_name=data['company_name'],
                user_type='Company Customer',
                role='Company Customer',
                email=data['email'],
                password=generate_password_hash('YourCompanyCustomerDefaultPassword@1234', method='pbkdf2:sha256', salt_length=8)
            )

            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(new_user)

            new_form = OrganisationCustomerUser(**company_customer_data)
            new_form.user = new_user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract product data
            products_data = data.get('products', [])
            for product_data in products_data:
                new_product = Product(**product_data)
                new_form.products.append(new_product)

            db.session.commit()

            # Send email to admin for authorization
            send_customer_authorisation_email(new_form)

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add your resource to the API
api.add_resource(OrganisationCustomerResource, '/organisation-customer-users')

def send_customer_authorisation_email(user):
    try:
        # Generate a token for authorisation
        token = serializer.dumps(user.id, salt='authorisation')

        # Build the authorisation link
        # authorisation_link = url_for('authorise_company_user', token=token, _external=True)
        authorisation_link = url_for('authorize_company_user_resource', token=token, _external=True)

        # Send the email to the admin
        admin_email = 'skaranja654@gmail.com'
        msg = Message('Authorisation Request', sender='sakakeja.ke@gmail.com', recipients=[admin_email])
        msg.body = f"A new user has registered. Click the link to authorise: {authorisation_link}"
        mail.send(msg)

    except Exception as e:
        app.logger.error(f"Error sending authorisation email: {str(e)}")
        raise
class AuthorizeCompanyUserResource(Resource):
    def get(self, token):
        try:
            user_id = serializer.loads(token, salt='authorisation', max_age=84600)
            user = OrganisationCustomerUser.query.get(user_id)

            if user:
                user.user_authorised = True
                db.session.commit()
                html_content = render_template('authorisation_success.html')
                response = make_response(html_content)
                response.headers['Content-Type'] = 'text/html'
                return response 

            html_content = render_template('authorisation_success.html')
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            return response 

        except Exception as e:
            print(f'authorisation_success: {token}')
            return {'message': 'authorisation_success'}, 200

# Add the resource to the API
api.add_resource(AuthorizeCompanyUserResource, '/authorise_company_user/<token>')

class OrganisationCustomerByIdResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('company_name', type=str, required=True)
    parser.add_argument('date_of_registration', type=str, required=True)
    parser.add_argument('customer_code', type=str, required=True)
    parser.add_argument('registration_number', type=str, required=True)
    parser.add_argument('sector', type=str, required=True)
    parser.add_argument('email', type=str, required=True)
    parser.add_argument('phone_number', type=str, required=True)
    parser.add_argument('county', type=str, required=True)
    parser.add_argument('sub_county', type=str, required=True)
    parser.add_argument('ward', type=str, required=True)
    parser.add_argument('village', type=str, required=True)
    parser.add_argument('other_name1', type=str, required=True)
    parser.add_argument('last_name1', type=str, required=True)
    parser.add_argument('id_number1', type=str, required=True)
    parser.add_argument('gender1', type=str, required=True)
    parser.add_argument('email1', type=str, required=True)
    parser.add_argument('phone_number1', type=str, required=True)
    parser.add_argument('date_of_birth1', type=str, required=True)
    parser.add_argument('other_name2', type=str, required=True)
    parser.add_argument('last_name2', type=str, required=True)
    parser.add_argument('id_number2', type=str, required=True)
    parser.add_argument('gender2', type=str, required=True)
    parser.add_argument('email2', type=str, required=True)
    parser.add_argument('phone_number2', type=str, required=True)
    parser.add_argument('date_of_birth2', type=str, required=True)
    parser.add_argument('other_name3', type=str, required=True)
    parser.add_argument('last_name3', type=str, required=True)
    parser.add_argument('id_number3', type=str, required=True)
    parser.add_argument('gender3', type=str, required=True)
    parser.add_argument('email3', type=str, required=True)
    parser.add_argument('phone_number3', type=str, required=True)
    parser.add_argument('date_of_birth3', type=str, required=True)

    @jwt_required()
    def get(self, form_id):
        try:
            form = OrganisationCustomerUser.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    
    @jwt_required()
    def patch(self, form_id):
        try:
            form = OrganisationCustomerUser.query.get(form_id)

            if form:
                # Get and parse request data
                data = request.get_json()

                # Update attributes
                form.date_of_registration = datetime.strptime(data.get('date_of_registration'), "%m/%d/%Y %I:%M %p")
                form.date_of_birth1 = datetime.strptime(data.get('date_of_birth1'), "%m/%d/%Y %I:%M %p")
                form.date_of_birth2 = datetime.strptime(data.get('date_of_birth2'), "%m/%d/%Y %I:%M %p")
                form.date_of_birth3 = datetime.strptime(data.get('date_of_birth3'), "%m/%d/%Y %I:%M %p")
                form.company_name = data.get('company_name', form.company_name)
                form.customer_code = data.get('customer_code', form.customer_code)
                form.registration_number = int(data.get('registration_number', form.registration_number))
                form.sector = data.get('sector', form.sector)
                form.email = data.get('email', form.email)
                form.phone_number = int(data.get('phone_number', form.phone_number))
                form.county = data.get('county', form.county)
                form.sub_county = data.get('sub_county', form.sub_county)
                form.ward = data.get('ward', form.ward)
                form.village = data.get('village', form.village)
                form.other_name1 = data.get('other_name1', form.other_name1)
                form.last_name1 = data.get('last_name1', form.last_name1)
                form.id_number1 = int(data.get('id_number1', form.id_number1))
                form.gender1 = data.get('gender1', form.gender1)
                form.email1 = data.get('email1', form.email1)
                form.phone_number1 = int(data.get('phone_number1', form.phone_number1))
                form.other_name2 = data.get('other_name2', form.other_name2)
                form.last_name2 = data.get('last_name2', form.last_name2)
                form.id_number2 = int(data.get('id_number2', form.id_number2))
                form.gender2 = data.get('gender2', form.gender2)
                form.email2 = data.get('email2', form.email2)
                form.phone_number2 = int(data.get('phone_number2', form.phone_number2))
                form.other_name3 = data.get('other_name3', form.other_name3)
                form.last_name3 = data.get('last_name3', form.last_name3)
                form.id_number3 = int(data.get('id_number3', form.id_number3))
                form.gender3 = data.get('gender3', form.gender3)
                form.email3 = data.get('email3', form.email3)
                form.phone_number3 = int(data.get('phone_number3', form.phone_number3))

                # Clear existing products
                form.products = []

                # Update products
                products_data = data.get('products', [])
                for product_data in products_data:
                    product = Product(
                        category=product_data.get('category'),
                        products_interested_in=product_data.get('products_interested_in'),
                        volume_in_kgs=product_data.get('volume_in_kgs'),
                        packaging=product_data.get('packaging'),
                        quality=product_data.get('quality'),
                        frequency=product_data.get('frequency'),
                        organisation_customer_id=form.id  # Associate with the current form
                    )
                    db.session.add(product)

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError during PATCH request: {str(e)}")
            return {'error': 'Data integrity issue occurred'}, 400
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = OrganisationCustomerUser.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add the resource to the API
api.add_resource(OrganisationCustomerByIdResource, '/organisation-customer-users/<int:form_id>')

# Producer Endpoints
class producersBiodataResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = ProducerBiodata.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            existing_farmer = ProducerBiodata.query.filter_by(id_number=data['id_number']).first()

            if existing_farmer:
                return {'error': 'A farmer with the same id_number already exists'}, 400

            primary_producer_data = data.get('primary_producer', {})
            
            farmer_biodata_data = {
                'other_name': data['other_name'],
                'last_name': data['last_name'],
                'date_of_birth': data['date_of_birth'],
                'farmer_code': data['farmer_code'],
                'id_number': data['id_number'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'hub': data['hub'],
                'buying_center': data['buying_center'],
                'education_level': data['education_level'],
                'county': data['county'],
                'sub_county': data['sub_county'],
                'gender': data['gender'],
                'ward': data['ward'],
                'village': data['village'],
                'primary_producer_data': primary_producer_data,
                'total_land_size': data['total_land_size'],
                'cultivate_land_size': data['cultivate_land_size'],
                'homestead_size': data['homestead_size'],
                'uncultivated_land_size': data['uncultivated_land_size'],
                'farm_accessibility': data['farm_accessibility'],
                'number_of_family_workers': data['number_of_family_workers'],
                'number_of_hired_workers': data['number_of_hired_workers'],
                'farmer_interest_in_extension': data['farmer_interest_in_extension'],
                'access_to_irrigation': data['access_to_irrigation'],
                'crop_list': data['crop_list'],
                'knowledge_related': data['knowledge_related'],
                'soil_related': data['soil_related'],
                'compost_related': data['compost_related'],
                'nutrition_related': data['nutrition_related'],
                'pests_related': data['pests_related'],
                'disease_related': data['disease_related'],
                'quality_related': data['quality_related'],
                'market_related': data['market_related'],
                'food_loss_related': data['food_loss_related'],
                'finance_related': data['finance_related'],
                'weather_related': data['weather_related'],
                'dairy_cattle': data['dairy_cattle'],
                'beef_cattle': data['beef_cattle'],
                'sheep': data['sheep'],
                'poultry': data['poultry'],
                'pigs': data['pigs'],
                'rabbits': data['rabbits'],
                'beehives': data['beehives'],
                'donkeys': data['donkeys'],
                'goats': data['goats'],
                'aquaculture': data['aquaculture'],
                'camels': data['camels'],
                'housing_type': data['housing_type'],
                'housing_floor': data['housing_floor'],
                'housing_roof': data['housing_roof'],
                'lighting_fuel': data['lighting_fuel'],
                'cooking_fuel': data['cooking_fuel'],
                'water_filter': data['water_filter'],
                'water_tank_greater_than_5000lts': data['water_tank_greater_than_5000lts'],
                'hand_washing_facilities': data['hand_washing_facilities'],
                'ppes': data['ppes'],
                'water_well_or_weir': data['water_well_or_weir'],
                'irrigation_pump': data['irrigation_pump'],
                'harvesting_equipment': data['harvesting_equipment'],
                'transportation_type': data['transportation_type'],
                'toilet_floor': data['toilet_floor'],
            }

            new_form = ProducerBiodata(**farmer_biodata_data)
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            db.session.add(new_form)

            produces_data = data.get('commercialProduces', [])
            for produce_data in produces_data:
                new_produce = CommercialProduce(**produce_data)
                new_form.commercialProduces.append(new_produce)

            produces_data = data.get('domesticProduces', [])
            for produce_data in produces_data:
                new_produce = DomesticProduce(**produce_data)
                new_form.domesticProduces.append(new_produce)

            db.session.commit()

            send_biodata_authorisation_email(new_form)

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
        
api.add_resource(producersBiodataResource, '/producers-biodata')

def send_biodata_authorisation_email(user):
    try:
        payload = {
            'user_id': user.id,
            'county': user.county
        }
        # token = create_access_token(identity=payload)
        token = create_access_token(identity=payload, expires_delta=False)

        # Construct the link with the token
        link = f"https://extension.farmdatapod.com//assign-ta.php?token={token}&id={user.id}&hub={user.county}"

        admin_email = 'skaranja654@gmail.com'
        msg = Message('Authorisation Request', sender='sakakeja.ke@gmail.com', recipients=[admin_email])
        msg.body = f"A new biodata form has registered. Click the link to authorise: {link}"
        mail.send(msg)

    except Exception as e:
        app.logger.error(f"Error sending authorisation email: {str(e)}")
        raise
class AuthorizeBiodataResource(Resource):
    def get(self, token):
        try:
            user_id = serializer.loads(token, salt='authorisation', max_age=84600)
            user = ProducerBiodata.query.get(user_id)

            if user:
                user.user_approved = True
                db.session.commit()
                html_content = render_template('authorisation_success.html')
                response = make_response(html_content)
                response.headers['Content-Type'] = 'text/html'
                return response 

            html_content = render_template('authorisation_success.html')
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            return response

        except Exception as e:
            print(f'Error during user authorisation: {str(e)}')
            return {'error': 'An internal server error occurred'}, 500

# Add the resource to the API
api.add_resource(AuthorizeBiodataResource, '/authorise_biodata/<token>')

# Define the verification success endpoint
@app.route('/biodata_verification_success_resource')
def biodata_verification_success_resource():
    # Your implementation here
    return render_template('biodata_success.html')

# Biodata by Id
import traceback
class ProducerBiodataResourceById(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = ProducerBiodata.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = ProducerBiodata.query.get(form_id)
            if form:
                data = request.get_json()
                
                # Print the data being processed for debugging
                print(f"Received data: {data}")

                if 'user_approved' in data:
                    form.user_approved = data['user_approved']
                
                if 'ta' in data:
                    form.ta = data['ta']

                if 'date_of_birth' in data:
                    form.date_of_birth = datetime.strptime(data.get('date_of_birth'), "%m/%d/%Y %I:%M %p")

                # Update basic fields
                form.other_name = data.get('other_name', form.other_name)
                form.last_name = data.get('last_name', form.last_name)
                form.farmer_code = data.get('farmer_code', form.farmer_code)
                form.id_number = data.get('id_number', form.id_number)
                form.email = data.get('email', form.email)
                form.phone_number = data.get('phone_number', form.phone_number)
                form.gender = data.get('gender', form.gender)
                form.hub = data.get('hub', form.hub)
                form.buying_center = data.get('buying_center', form.buying_center)
                form.education_level = data.get('education_level', form.education_level)
                form.county = data.get('county', form.county)
                form.sub_county = data.get('sub_county', form.sub_county)
                form.ward = data.get('ward', form.ward)
                form.village = data.get('village', form.village)
                form.primary_producer = data.get('primary_producer', form.primary_producer)
                form.total_land_size = data.get('total_land_size', form.total_land_size)
                form.cultivate_land_size = data.get('cultivate_land_size', form.cultivate_land_size)
                form.homestead_size = data.get('homestead_size', form.homestead_size)
                form.uncultivated_land_size = data.get('uncultivated_land_size', form.uncultivated_land_size)
                form.farm_accessibility = data.get('farm_accessibility', form.farm_accessibility)
                form.number_of_family_workers = data.get('number_of_family_workers', form.number_of_family_workers)
                form.number_of_hired_workers = data.get('number_of_hired_workers', form.number_of_hired_workers)
                form.farmer_interest_in_extension = data.get('farmer_interest_in_extension', form.farmer_interest_in_extension)
                form.access_to_irrigation = data.get('access_to_irrigation', form.access_to_irrigation)
                form.crop_list = data.get('crop_list', form.crop_list)
                form.knowledge_related = data.get('knowledge_related', form.knowledge_related)
                form.soil_related = data.get('soil_related', form.soil_related)
                form.compost_related = data.get('compost_related', form.compost_related)
                form.nutrition_related = data.get('nutrition_related', form.nutrition_related)
                form.pests_related = data.get('pests_related', form.pests_related)
                form.disease_related = data.get('disease_related', form.disease_related)
                form.quality_related = data.get('quality_related', form.quality_related)
                form.market_related = data.get('market_related', form.market_related)
                form.food_loss_related = data.get('food_loss_related', form.food_loss_related)
                form.finance_related = data.get('finance_related', form.finance_related)
                form.weather_related = data.get('weather_related', form.weather_related)
                form.dairy_cattle = data.get('dairy_cattle', form.dairy_cattle)
                form.beef_cattle = data.get('beef_cattle', form.beef_cattle)
                form.sheep = data.get('sheep', form.sheep)
                form.poultry = data.get('poultry', form.poultry)
                form.pigs = data.get('pigs', form.pigs)
                form.rabbits = data.get('rabbits', form.rabbits)
                form.beehives = data.get('beehives', form.beehives)
                form.donkeys = data.get('donkeys', form.donkeys)
                form.goats = data.get('goats', form.goats)
                form.aquaculture = data.get('aquaculture', form.aquaculture)
                form.camels = data.get('camels', form.camels)
                form.housing_type = data.get('housing_type', form.housing_type)
                form.housing_floor = data.get('housing_floor', form.housing_floor)
                form.housing_roof = data.get('housing_roof', form.housing_roof)
                form.lighting_fuel = data.get('lighting_fuel', form.lighting_fuel)
                form.cooking_fuel = data.get('cooking_fuel', form.cooking_fuel)
                form.water_filter = data.get('water_filter', form.water_filter)
                form.water_tank_greater_than_5000lts = data.get('water_tank_greater_than_5000lts', form.water_tank_greater_than_5000lts)
                form.hand_washing_facilities = data.get('hand_washing_facilities', form.hand_washing_facilities)
                form.ppes = data.get('ppes', form.ppes)
                form.water_well_or_weir = data.get('water_well_or_weir', form.water_well_or_weir)
                form.irrigation_pump = data.get('irrigation_pump', form.irrigation_pump)
                form.harvesting_equipment = data.get('harvesting_equipment', form.harvesting_equipment)
                form.transportation_type = data.get('transportation_type', form.transportation_type)
                form.toilet_floor = data.get('toilet_floor', form.toilet_floor)

                # Update or clear produce lists
                if 'commercialProduces' in data:
                    form.commercial_produces = []
                    for produce_data in data['commercialProduces']:
                        produce = CommercialProduce(
                            product=produce_data.get('product'),
                            product_category=produce_data.get('product_category'),
                            acerage=produce_data.get('acerage'),
                        )
                        form.commercial_produces.append(produce)

                if 'domesticProduces' in data:
                    form.domestic_produces = []
                    for produce_data in data['domesticProduces']:
                        print(f"Processing domestic produce: {produce_data}")
                        produce = DomesticProduce(
                            product=produce_data.get('product'),
                            product_category=produce_data.get('product_category'),
                            acerage=produce_data.get('acerage'),
                        )
                        form.domestic_produces.append(produce)

                db.session.commit()
                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            print(traceback.format_exc())
            return {'error': 'An internal server error occurred'}, 500
      
    @jwt_required()
    def delete(self, form_id):
        try:
            form = ProducerBiodata.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return jsonify({'message': 'Form deleted successfully'}), 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
        
api.add_resource(ProducerBiodataResourceById, '/producers-biodata/<int:form_id>')

# CIG Producer
class CIGproducersBiodataResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = CIGProducerBiodata.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            
            # Check if a farmer with the same id_number already exists
            existing_farmer = CIGProducerBiodata.query.filter_by(id_number=data['id_number']).first()
            if existing_farmer:
                return {'error': 'A farmer with the same id_number already exists'}, 400

            # Convert primary_producer data to JSON string
            primary_producer_data = data.get('primary_producer', [])
            primary_producer_json = json.dumps(primary_producer_data)

            # Prepare farmer biodata
            farmer_biodata_data = {
                'other_name': data['other_name'],
                'last_name': data['last_name'],
                'date_of_birth': data['date_of_birth'],
                'farmer_code': data['farmer_code'],
                'id_number': data['id_number'],
                'email': data['email'],
                'phone_number': data['phone_number'],
                'hub': data['hub'],
                'buying_center': data['buying_center'],
                'education_level': data['education_level'],
                'county': data['county'],
                'sub_county': data['sub_county'],
                'gender': data['gender'],
                'ward': data['ward'],
                'village': data['village'],
                'primary_producer': primary_producer_json,  # Store as JSON string
                'total_land_size': data['total_land_size'],
                'cultivate_land_size': data['cultivate_land_size'],
                'homestead_size': data['homestead_size'],
                'uncultivated_land_size': data['uncultivated_land_size'],
                'farm_accessibility': data['farm_accessibility'],
                'number_of_family_workers': data['number_of_family_workers'],
                'number_of_hired_workers': data['number_of_hired_workers'],
                'farmer_interest_in_extension': data['farmer_interest_in_extension'],
                'access_to_irrigation': data['access_to_irrigation'],
                'crop_list': data['crop_list'],
                'knowledge_related': data['knowledge_related'],
                'soil_related': data['soil_related'],
                'compost_related': data['compost_related'],
                'nutrition_related': data['nutrition_related'],
                'pests_related': data['pests_related'],
                'disease_related': data['disease_related'],
                'quality_related': data['quality_related'],
                'market_related': data['market_related'],
                'food_loss_related': data['food_loss_related'],
                'finance_related': data['finance_related'],
                'weather_related': data['weather_related'],
                'dairy_cattle': data['dairy_cattle'],
                'beef_cattle': data['beef_cattle'],
                'sheep': data['sheep'],
                'poultry': data['poultry'],
                'pigs': data['pigs'],
                'rabbits': data['rabbits'],
                'beehives': data['beehives'],
                'donkeys': data['donkeys'],
                'goats': data['goats'],
                'camels': data['camels'],
                'aquaculture': data['aquaculture'],
                'housing_type': data['housing_type'],
                'housing_floor': data['housing_floor'],
                'housing_roof': data['housing_roof'],
                'lighting_fuel': data['lighting_fuel'],
                'cooking_fuel': data['cooking_fuel'],
                'water_filter': data['water_filter'],
                'water_tank_greater_than_5000lts': data['water_tank_greater_than_5000lts'],
                'hand_washing_facilities': data['hand_washing_facilities'],
                'ppes': data['ppes'],
                'water_well_or_weir': data['water_well_or_weir'],
                'irrigation_pump': data['irrigation_pump'],
                'harvesting_equipment': data['harvesting_equipment'],
                'transportation_type': data['transportation_type'],
                'toilet_floor': data['toilet_floor'],
            }

            # Create a new CIGProducerBiodata instance
            new_form = CIGProducerBiodata(**farmer_biodata_data)
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            db.session.add(new_form)

            # Handle commercialProduces data
            commercial_produces_data = data.get('commercialProduces', [])
            for produce_data in commercial_produces_data:
                new_produce = CommercialProduce(**produce_data)
                new_form.commercialProduces.append(new_produce)

            # Handle domesticProduces data
            domestic_produces_data = data.get('domesticProduces', [])
            for produce_data in domestic_produces_data:
                new_produce = DomesticProduce(**produce_data)
                new_form.domesticProduces.append(new_produce)

            # Commit all changes to the database
            db.session.commit()

            # Send authorization email
            send_cig_biodata_authorisation_email(new_form)

            # Prepare response
            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGproducersBiodataResource, '/cig-producers-biodata')

def send_cig_biodata_authorisation_email(user):
    try:
        # Generate a token for authorisation
        token = serializer.dumps(user.id, salt='authorisation')

        # Build the authorisation link
        # authorisation_link = url_for('authorize_cig_biodata_resource', token=token, _external=True)
        authorisation_link = url_for('authorize_biodata_resource', token=token, _external=True)

        # Send the email to the admin
        admin_email = 'skaranja654@gmail.com'
        msg = Message('Authorisation Request', sender='sakakeja.ke@gmail.com', recipients=[admin_email])
        msg.body = f"A new biodata form has registered. Click the link to authorise: {authorisation_link}"
        mail.send(msg)

    except Exception as e:
        app.logger.error(f"Error sending authorisation email: {str(e)}")
        raise

class AuthorizeCIGBiodataResource(Resource):
    def get(self, token):
        try:
            user_id = serializer.loads(token, salt='authorisation', max_age=84600)
            user = CIGProducerBiodata.query.get(user_id)

            if user:
                user.user_approved = True
                db.session.commit()
                html_content = render_template('authorisation_success.html')
                response = make_response(html_content)
                response.headers['Content-Type'] = 'text/html'
                return response 

            html_content = render_template('authorisation_success.html')
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            return response

        except Exception as e:
            print(f'Error during user authorisation: {str(e)}')
            return {'error': 'An internal server error occurred'}, 500

# Add the resource to the API
api.add_resource(AuthorizeBiodataResource, '/authorise_cig_biodata/<token>')

# Define the verification success endpoint
@app.route('/cig_biodata_verification_success_resource')
def cig_biodata_verification_success_resource():
    # Your implementation here
    return render_template('biodata_success.html')

# Biodata by Id
class CIGProducerBiodataResourceById(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = CIGProducerBiodata.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = CIGProducerBiodata.query.get(form_id)
            if form:
                data = request.get_json()
                # Update form attributes based on the request data
                form.date_of_birth = datetime.strptime(data.get('date_of_birth'), "%m/%d/%Y %I:%M %p")
                form.other_name = data.get('other_name', form.other_name)
                form.last_name = data.get('last_name', form.last_name)
                form.farmer_code = data.get('farmer_code', form.farmer_code)
                form.id_number = data.get('id_number', form.id_number)
                form.email = data.get('email', form.email)
                form.phone_number = data.get('phone_number', form.phone_number)
                form.gender = data.get('gender', form.gender)
                form.hub = data.get('hub', form.hub)
                form.buying_center = data.get('buying_center', form.buying_center)
                form.education_level = data.get('education_level', form.education_level)
                form.county = data.get('county', form.county)
                form.sub_county = data.get('sub_county', form.sub_county)
                form.ward = data.get('ward', form.ward)
                form.village = data.get('village', form.village)
                form.primary_producer = data.get('primary_producer', form.primary_producer)
                form.total_land_size = data.get('total_land_size', form.total_land_size)
                form.cultivate_land_size = data.get('cultivate_land_size', form.cultivate_land_size)
                form.homestead_size = data.get('homestead_size', form.homestead_size)
                form.uncultivated_land_size = data.get('uncultivated_land_size', form.uncultivated_land_size)
                form.farm_accessibility = data.get('farm_accessibility', form.farm_accessibility)
                form.number_of_family_workers = data.get('number_of_family_workers', form.number_of_family_workers)
                form.number_of_hired_workers = data.get('number_of_hired_workers', form.number_of_hired_workers)
                form.farmer_interest_in_extension = data.get('farmer_interest_in_extension', form.farmer_interest_in_extension)
                form.access_to_irrigation = data.get('access_to_irrigation', form.access_to_irrigation)
                form.crop_list = data.get('crop_list', form.crop_list)
                form.knowledge_related = data.get('knowledge_related', form.knowledge_related)
                form.soil_related = data.get('soil_related', form.soil_related)
                form.compost_related = data.get('compost_related', form.compost_related)
                form.nutrition_related = data.get('nutrition_related', form.nutrition_related)
                form.pests_related = data.get('pests_related', form.pests_related)
                form.disease_related = data.get('disease_related', form.disease_related)
                form.quality_related = data.get('quality_related', form.quality_related)
                form.market_related = data.get('market_related', form.market_related)
                form.food_loss_related = data.get('food_loss_related', form.food_loss_related)
                form.finance_related = data.get('finance_related', form.finance_related)
                form.weather_related = data.get('weather_related', form.weather_related)
                form.dairy_cattle = data.get('dairy_cattle', form.dairy_cattle)
                form.beef_cattle = data.get('beef_cattle', form.beef_cattle)
                form.sheep = data.get('sheep', form.sheep)
                form.poultry = data.get('poultry', form.poultry)
                form.pigs = data.get('pigs', form.pigs)
                form.rabbits = data.get('rabbits', form.rabbits)
                form.beehives = data.get('beehives', form.beehives)
                form.donkeys = data.get('donkeys', form.donkeys)
                form.goats = data.get('goats', form.goats)
                form.camels = data.get('camels', form.camels)
                form.aquaculture = data.get('aquaculture', form.aquaculture)
                form.housing_type = data.get('housing_type', form.housing_type)
                form.housing_floor = data.get('housing_floor', form.housing_floor)
                form.housing_roof = data.get('housing_roof', form.housing_roof)
                form.lighting_fuel = data.get('lighting_fuel', form.lighting_fuel)
                form.cooking_fuel = data.get('cooking_fuel', form.cooking_fuel)
                form.water_filter = data.get('water_filter', form.water_filter)
                form.water_tank_greater_than_5000lts = data.get('water_tank_greater_than_5000lts', form.water_tank_greater_than_5000lts)
                form.hand_washing_facilities = data.get('hand_washing_facilities', form.hand_washing_facilities)
                form.ppes = data.get('ppes', form.ppes)
                form.water_well_or_weir = data.get('water_well_or_weir', form.water_well_or_weir)
                form.irrigation_pump = data.get('irrigation_pump', form.irrigation_pump)
                form.harvesting_equipment = data.get('harvesting_equipment', form.harvesting_equipment)
                form.transportation_type = data.get('transportation_type', form.transportation_type)
                form.toilet_floor = data.get('toilet_floor', form.toilet_floor)

                # Update produce list
                if 'marketProduces' in data:
                    form.produce = []
                    for produce_data in data['marketProduces']:
                        produce = MarketProduce(
                            product=produce_data.get('product'),
                            product_category=produce_data.get('product_category'),
                            acerage=produce_data.get('produce_data'),
                        )
                        form.produce.append(produce)

                db.session.commit()
                if 'domesticProduces' in data:
                    form.produce = []
                    for produce_data in data['domesticProduces']:
                        produce = DomesticProduce(
                            product=produce_data.get('product'),
                            product_category=produce_data.get('product_category'),
                            acerage=produce_data.get('produce_data'),
                        )
                        form.produce.append(produce)

                db.session.commit()
                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = CIGProducerBiodata.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return jsonify({'message': 'Form deleted successfully'}), 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGProducerBiodataResourceById, '/cig-producers-biodata/<int:form_id>')

# Produce Endpoints
class MarketProducesResource(Resource):
    @jwt_required()
    def options(self, form_id=None):
        # Preflight request, respond successfully
        if form_id is not None:
            return {}, 200
        else:
            return {'Allow': 'GET, POST'}, 200

    @jwt_required()
    def get(self, form_id=None):  # Update the method signature
        if form_id is not None:
            form = MarketProduce.query.get(form_id)
            if form:
                return form.to_dict(), 200
            else:
                return {'error': 'Form not found'}, 404
        else:
            forms_list = MarketProduce.query.all()
            forms_dict_list = [form.to_dict() for form in forms_list]
            return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            current_user_id = get_jwt_identity()

            new_form = MarketProduce(
                product=data['product'],
                product_category=data['product_category'],
                acerage=data['acerage'],
            )

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(MarketProducesResource, '/produces', '/produces/<int:form_id>')

class ProduceByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = MarketProduce.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            data = request.get_json()

            # Validate required fields
            required_fields = ['domestic_produce', 'market_produce']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            form = MarketProduce.query.get_or_404(form_id)

            # Update form fields
            form.product = data['product']
            form.product_category = data['product_category']
            form.acerage = data['acerage']
    
            db.session.commit()
            return form.to_dict()

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = MarketProduce.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(ProduceByIdResource, '/produces/<int:form_id>')

# Field registration endpoints
class FarmersFieldRegistrationsResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        response = make_response('', 200)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

    @jwt_required()
    def get(self):
        forms_list = FarmerFieldRegistration.query.all()
        forms_dict_list = []

        for form in forms_list:
            form_dict = form.to_dict()

            # Format date fields only if they are datetime objects
            for field in ['date_planted1', 'date_of_harvest1', 'date_planted2', 'date_of_harvest2']:
                date_value = getattr(form, field)
                if isinstance(date_value, datetime):
                    form_dict[field] = date_value.strftime('%Y-%m-%d %H:%M:%S')

            forms_dict_list.append(form_dict)

        return jsonify(forms_dict_list)

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Get the user_id from the JWT token
            user_id = get_jwt_identity()

            # Query ProducerBiodata based on farmer_code
            producer_biodata = ProducerBiodata.query.filter_by(farmer_code=data['producer']).first()

            if not producer_biodata:
                return {'error': 'ProducerBiodata not found for the given farmer_code'}, 404

            # Extract farmer field registration data
            farmer_field_registration_data = {
                'producer': data['producer'],
                'field_number': data['field_number'],
                'field_size': data['field_size'],
                'crop1': data['crop1'],
                'crop_variety1': data['crop_variety1'],
                'date_planted1': data['date_planted1'],
                'date_of_harvest1': data['date_of_harvest1'],
                'population1': data['population1'],
                'baseline_yield_last_season1': data['baseline_yield_last_season1'],
                'baseline_income_last_season1': data['baseline_income_last_season1'],
                'baseline_cost_of_production_last_season1': data['baseline_cost_of_production_last_season1'],
                'crop2': data['crop2'],
                'crop_variety2': data['crop_variety2'],
                'date_planted2': data['date_planted2'],
                'date_of_harvest2': data['date_of_harvest2'],
                'population2': data['population2'],
                'baseline_yield_last_season2': data['baseline_yield_last_season2'],
                'baseline_income_last_season2': data['baseline_income_last_season2'],
                'baseline_cost_of_production_last_season2': data['baseline_cost_of_production_last_season2'],
                'producer_biodata_id': producer_biodata.id,
                'user_id': user_id,
            }

            # Create a new instance
            new_form = FarmerFieldRegistration(**farmer_field_registration_data)

            # Set the user attribute
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(FarmersFieldRegistrationsResource, '/farmers-field-registrations')

class FarmerFieldRegistrationByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = FarmerFieldRegistration.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            form = FarmerFieldRegistration.query.get_or_404(form_id)

            # Updates form attributes based on the request data
            data = request.get_json()

            form.date_planted1 = datetime.strptime(data.get('date_planted1'), "%m/%d/%Y %I:%M %p")
            form.date_planted2 = datetime.strptime(data.get('date_planted2'), "%m/%d/%Y %I:%M %p")
            form.date_of_harvest1 = datetime.strptime(data.get('date_of_harvest1'), "%m/%d/%Y %I:%M %p")
            form.date_of_harvest2 = datetime.strptime(data.get('date_of_harvest2'), "%m/%d/%Y %I:%M %p")

            form.producer = data.get('producer', form.producer)
            form.field_number = data.get('field_number', form.field_number)
            form.field_size = data.get('field_size', form.field_size)
            form.crop1 = data.get('crop1', form.crop1)
            form.crop_variety1 = data.get('crop_variety1', form.crop_variety1)
            form.population1 = data.get('population1', form.population1)
            form.baseline_yield_last_season1 = data.get('baseline_yield_last_season1', form.baseline_yield_last_season1)
            form.baseline_income_last_season1 = data.get('baseline_income_last_season1', form.baseline_income_last_season1)
            form.baseline_cost_of_production_last_season1 = data.get('baseline_cost_of_production_last_season1', form.baseline_cost_of_production_last_season1)
            form.crop2 = data.get('crop2', form.crop2)
            form.crop_variety2 = data.get('crop_variety2', form.crop_variety2)
            form.population2 = data.get('population2', form.population2)
            form.baseline_yield_last_season2 = data.get('baseline_yield_last_season2', form.baseline_yield_last_season2)
            form.baseline_income_last_season2 = data.get('baseline_income_last_season2', form.baseline_income_last_season2)
            form.baseline_cost_of_production_last_season2 = data.get('baseline_cost_of_production_last_season2', form.baseline_cost_of_production_last_season2)

            db.session.commit()

            response_dict = form.to_dict()
            return response_dict, 200

        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = FarmerFieldRegistration.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(FarmerFieldRegistrationByIdResource, '/farmers-field-registrations', '/farmers-field-registrations/<int:form_id>')

# CIG field registration 
class CIGFarmersFieldRegistrationsResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        response = make_response('', 200)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

    @jwt_required()
    def get(self):
        forms_list = CIGFarmerFieldRegistration.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Get the user_id from the JWT token
            user_id = get_jwt_identity()

            # Query ProducerBiodata based on 
            cig_producer_biodata = CIGProducerBiodata.query.filter_by(farmer_code=data['producer']).first()

            if not cig_producer_biodata:
                return {'error': 'ProducerBiodata not found for the given farmer_code'}, 404

            # Extract farmer field registration data
            farmer_field_registration_data = {
                'producer': data['producer'],
                'field_number': data['field_number'],
                'field_size': data['field_size'],
                'crop1': data['crop1'],
                'crop_variety1': data['crop_variety1'],
                'date_planted1': data['date_planted1'],
                'date_of_harvest1': data['date_of_harvest1'],
                'population1': data['population1'],
                'baseline_yield_last_season1': data['baseline_yield_last_season1'],
                'baseline_income_last_season1': data['baseline_income_last_season1'],
                'baseline_cost_of_production_last_season1': data['baseline_cost_of_production_last_season1'],
                'crop2': data['crop2'],
                'crop_variety2': data['crop_variety2'],
                'date_planted2': data['date_planted2'],
                'date_of_harvest2': data['date_of_harvest2'],
                'population2': data['population2'],
                'baseline_yield_last_season2': data['baseline_yield_last_season2'],
                'baseline_income_last_season2': data['baseline_income_last_season2'],
                'baseline_cost_of_production_last_season2': data['baseline_cost_of_production_last_season2'],
                'cig_producer_biodata_id': cig_producer_biodata.id,
                'user_id': user_id,
            }

            # Create a new instance
            new_form = CIGFarmerFieldRegistration(**farmer_field_registration_data)

            # Set the user attribute
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGFarmersFieldRegistrationsResource, '/cig-farmers-field-registrations')

class CIGFarmerFieldRegistrationByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = CIGFarmerFieldRegistration.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            form = CIGFarmerFieldRegistration.query.get_or_404(form_id)

            # Updates form attributes based on the request data
            data = request.get_json()

            form.date_planted1 = datetime.strptime(data.get('date_planted1'), "%m/%d/%Y %I:%M %p")
            form.date_planted2 = datetime.strptime(data.get('date_planted2'), "%m/%d/%Y %I:%M %p")
            form.date_of_harvest1 = datetime.strptime(data.get('date_of_harvest1'), "%m/%d/%Y %I:%M %p")
            form.date_of_harvest2 = datetime.strptime(data.get('date_of_harvest2'), "%m/%d/%Y %I:%M %p")

            form.field_number = data.get('field_number', form.field_number)
            form.field_size = data.get('field_size', form.field_size)
            form.crop1 = data.get('crop1', form.crop1)
            form.crop_variety1 = data.get('crop_variety1', form.crop_variety1)
            form.population1 = data.get('population1', form.population1)
            form.baseline_yield_last_season1 = data.get('baseline_yield_last_season1', form.baseline_yield_last_season1)
            form.baseline_income_last_season1 = data.get('baseline_income_last_season1', form.baseline_income_last_season1)
            form.baseline_cost_of_production_last_season1 = data.get('baseline_cost_of_production_last_season1', form.baseline_cost_of_production_last_season1)
            form.crop2 = data.get('crop2', form.crop2)
            form.crop_variety2 = data.get('crop_variety2', form.crop_variety2)
            form.population2 = data.get('population2', form.population2)
            form.baseline_yield_last_season2 = data.get('baseline_yield_last_season2', form.baseline_yield_last_season2)
            form.baseline_income_last_season2 = data.get('baseline_income_last_season2', form.baseline_income_last_season2)
            form.baseline_cost_of_production_last_season2 = data.get('baseline_cost_of_production_last_season2', form.baseline_cost_of_production_last_season2)

            db.session.commit()

            response_dict = form.to_dict()
            return response_dict, 200

        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = CIGFarmerFieldRegistration.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(CIGFarmerFieldRegistrationByIdResource, '/cig-farmers-field-registrations', '/farmers-field-registrations/<int:form_id>')
# Seasons
class SeasonsPlanningResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = SeasonPlanning.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Convert date string to datetime object
            planned_date_of_planting = datetime.strptime(data['planned_date_of_planting'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            # Extract season registration data
            season_planning_data = {
                'producer': data['producer'],
                'field': data['field'],
                'planned_date_of_planting': planned_date_of_planting,
                'week_number': data['week_number'],
                'nursery': json.dumps(data.get('nursery', {})),
                'soil_analysis': json.dumps(data.get('soil_analysis', {})),
                'liming': json.dumps(data.get('liming', {})),
                'transplanting': json.dumps(data.get('transplanting', {})),
                'weeding': json.dumps(data.get('weeding', {})),
                'prunning_thinning_desuckering': json.dumps(data.get('prunning_thinning_desuckering', {})),
                'mulching': json.dumps(data.get('mulching', {})),
                'gapping': json.dumps(data.get('gapping', {})),
                'harvesting': json.dumps(data.get('harvesting', {})),
            }

            # Create a new season planning instance
            new_form = SeasonPlanning(**season_planning_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract and handle nested data
            def add_nested_data(nested_data, model, relationship_attr):
                for item in nested_data:
                    obj = model(**item)
                    getattr(new_form, relationship_attr).append(obj)

            # Handle market produces
            add_nested_data(data.get('marketProduces', []), MarketProduce, 'marketProduces')

            # Handle plan nutrition
            add_nested_data(data.get('plan_nutritions', []), PlanNutrition, 'plan_nutritions')

            # Handle preventative diseases
            add_nested_data(data.get('preventative_diseases', []), PreventativeDisease, 'preventative_diseases')

            # Handle preventative pests
            add_nested_data(data.get('preventative_pests', []), PreventativePest, 'preventative_pests')

            # Handle plan irrigations
            add_nested_data(data.get('plan_irrigations', []), PlanIrrigation, 'plan_irrigations')

            # Handle scouting stations
            add_nested_data(data.get('scouting_stations', []), ScoutingStation, 'scouting_stations')

            # Commit all changes to the database
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(SeasonsPlanningResource, '/seasons-planning')

# Season planning by Id endpoints
class SeasonPlanningResourceById(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = SeasonPlanning.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = SeasonPlanning.query.get(form_id)

            if form:
                data = request.get_json()

                form.planned_date_of_planting = datetime.strptime(data.get('planned_date_of_planting'), "%m/%d/%Y %I:%M %p")
                form.producer = data.get('producer', form.producer)
                form.field = data.get('field', form.field)
                form.crop = data.get('crop', form.crop)
                form.week_number = data.get('week_number', form.week_number)
                form.nursery = data.get('nursery', form.nursery)
                form.soil_analysis = data.get('soil_analysis', form.soil_analysis)
                form.liming = data.get('liming', form.liming)
                form.transplanting = data.get('transplanting', form.transplanting)
                form.weeding = data.get('weeding', form.weeding)
                form.prunning_thinning_desuckering = data.get('prunning_thinning_desuckering', form.prunning_thinning_desuckering)
                form.mulching = data.get('mulching', form.mulching)
                form.harvesting = data.get('harvesting', form.harvesting)

                # Update related models
                form.marketProduces = [MarketProduce(**marketProduce) for marketProduce in data.get('marketProduces', [])]
                form.plan_nutritions = [PlanNutrition(**plant_nutrition) for plant_nutrition in data.get('plan_nutritions', [])]
                form.preventative_diseases = [PreventativeDisease(**preventative_disease) for preventative_disease in data.get('preventative_diseases', [])]
                form.preventative_pests = [PreventativePest(**preventative_pest) for preventative_pest in data.get('preventative_pests', [])]
                form.plan_irrigations = [PlanIrrigation(**plan_irrigation) for plan_irrigation in data.get('plan_irrigations', [])]
                form.scouting_stations = [ScoutingStation(**scouting_station) for scouting_station in data.get('scouting_stations', [])]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = SeasonPlanning.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(SeasonPlanningResourceById, '/seasons-planning/<int:form_id>')

# Extension Services Endpoints
class ExtensionServiceResource(Resource):
    @jwt_required()
    def get(self):
        forms_list = ExtensionService.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Convert date string to datetime object
            planned_date_of_planting = datetime.strptime(data['planned_date_of_planting'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            # Extract extension service registration data
            extension_service_data = {
                'producer': data['producer'],
                'field': data['field'],
                'planned_date_of_planting': planned_date_of_planting,
                'week_number': data['week_number'],
                # Serialize JSON fields to string
                'nursery': json.dumps(data.get('nursery', {})),
                'soil_analysis': json.dumps(data.get('soil_analysis', {})),
                'liming': json.dumps(data.get('liming', {})),
                'transplanting': json.dumps(data.get('transplanting', {})),
                'weeding': json.dumps(data.get('weeding', {})),
                'prunning_thinning_desuckering': json.dumps(data.get('prunning_thinning_desuckering', {})),
                'mulching': json.dumps(data.get('mulching', {})),
                'gapping': json.dumps(data.get('gapping', {})),
                'harvesting': json.dumps(data.get('harvesting', {})),
            }

            # Create a new extension service instance
            new_form = ExtensionService(**extension_service_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Extract and handle nested data
            def add_nested_data(nested_data, model, relationship_attr):
                for item in nested_data:
                    obj = model(**item)
                    getattr(new_form, relationship_attr).append(obj)

            # Handle market produces
            add_nested_data(data.get('marketProduces', []), MarketProduce, 'marketProduces')

            # Handle scouting stations
            add_nested_data(data.get('ext_scouting_stations', []), ExtScoutingStation, 'ext_scouting_stations')

            # Handle pesticides used
            add_nested_data(data.get('pesticides_used', []), PesticideUsed, 'pesticides_used')

            # Handle fertilizers/compost used
            add_nested_data(data.get('fertlizers_used', []), FertilizerUsed, 'fertlizers_used')

            # Handle forecast yields
            add_nested_data(data.get('forecast_yields', []), ForecastYield, 'forecast_yields')

            # Commit all changes to the database
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(ExtensionServiceResource, '/extension-services')

# Extension Services by Id
class ExtensionServiceByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = ExtensionService.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = ExtensionService.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.date_of_planting = datetime.strptime(data.get('date_of_planting'), "%m/%d/%Y %I:%M %p")

                form.ta_code = data.get('ta_code', form.ta_code)
                form.farmer_code = data.get('farmer_code', form.farmer_code)
                form.select_field = data.get('select_field', form.select_field)
                form.crop = data.get('crop', form.crop)
                form.week_number = data.get('week_number', form.week_number)
                # plant crop management
                form.nursery = data.get('nursery', form.nursery)
                form.soil_analysis = data.get('soil_analysis', form.soil_analysis)
                form.liming = data.get('liming', form.liming)
                form.transplanting = data.get('transplanting', form.transplanting)
                form.weeding = data.get('weeding', form.weeding)
                form.thinning = data.get('thinning', form.thinning)
                form.mulching = data.get('mulching', form.mulching)
                form.pruning = data.get('pruning', form.pruning)
                form.harvesting = data.get('harvesting', form.harvesting)

                form.marketProduces = [MarketProduce(**marketProduce) for marketProduce in data.get('marketProduces', [])]
                form.scouting_stations = [ScoutingStation(**scouting_station) for scouting_station in data.get('scouting_stations', form.scouting_stations)]
                form.pesticides_used = [PesticideUsed(**pesticide_used) for pesticide_used in data.get('pesticides_used', form.pesticides_used)]
                form.fertlizers_used = [FertilizerUsed(**fertlizer_used) for fertlizer_used in data.get('fertlizers_used', form.fertlizers_used)]
                form.forecast_yields = [ForecastYield(**forecast_yield) for forecast_yield in data.get('forecast_yields', form.forecast_yields)]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = ExtensionService.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(ExtensionServiceByIdResource, '/extension-services/<int:form_id>')

# Training Endpoints
class TrainingsResource(Resource):
    @jwt_required()
    def get(self):
        forms_list = Training.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Extract trainer farmer data
            trainer_farmer_data = {
                'course_name': data['course_name'],
                'course_description': data['course_description'],
                'date_of_training': data['date_of_training'],
                'trainer_name': data['trainer_name'],
                'content_of_training': data['content_of_training'],
                'venue': data['venue'],
                'buying_center': data['buying_center'],
                'participants': json.dumps(data['participants']),
            }

            # Create a new trainer farmer instance
            new_form = Training(**trainer_farmer_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
       
class TrainingsByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = Training.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = Training.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.course_name = data.get('course_name', form.course_name)
                form.course_description = data.get('course_description', form.course_description)
                form.trainer_name = data.get('trainer_name', form.trainer_name)
                form.date_of_training = data.get('date_of_training', form.date_of_training)
                form.content_of_training = data.get('content_of_training', form.content_of_training)
                form.venue = data.get('venue', form.venue)
                form.buying_center = data.get('buying_center', form.buying_center)
                form.participants = data.get('participants', form.participants)

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = Training.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(TrainingsResource, '/trainings')
api.add_resource(TrainingsByIdResource, '/trainings/<int:form_id>')


# Attendance Endpoints
class AttendanceResource(Resource):
    @jwt_required()
    def get(self):
        forms_list = Attendance.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            attendance_data = {
                'attendance': data['attendance'],
                'training_id': data['training_id'],
            }

            # Create a new attendance instance
            new_form = Attendance(**attendance_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class AttendanceByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = Attendance.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = Attendance.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.attendance = data.get('attendance', form.attendance)
                form.training_id = data.get('training_id', form.training_id)
                
                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = Attendance.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(AttendanceResource, '/attendance')
api.add_resource(AttendanceByIdResource, '/attendance/<int:form_id>')

# Price distribution endpoints
# farmer
class FarmerPriceDistributionsResource(Resource):
    @jwt_required()
    def get(self):
        forms_list = FarmerPriceDistribution.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if produce_id already exists
            existing_form = FarmerPriceDistribution.query.filter_by(produce_id=data['produce_id']).first()
            if existing_form:
                return {'error': 'Produce ID already exists'}, 400

            # Extract farmer price distribution data
            farmer_price_distribution_data = {
                'produce_id': data['produce_id'],
                'hub': data['hub'],
                'buying_center': data['buying_center'],
                'unit': data['unit'],
                'date': datetime.strptime(data['date'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'online_price': data['online_price'],
                'comments': data['comments'],
            }

            # Create a new farmer price distribution instance
            new_form = FarmerPriceDistribution(**farmer_price_distribution_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class FarmerPriceDistributionsByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = FarmerPriceDistribution.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = FarmerPriceDistribution.query.get(form_id)

            if form:
                data = request.get_json()

                # Update date if provided
                date_str = data.get('date')
                if date_str:
                    form.date = datetime.strptime(date_str, "%m/%d/%Y %I:%M %p")

                # Update other fields, keeping current value if not provided in request
                form.produce_id = data.get('produce_id', form.produce_id)
                form.hub = data.get('hub', form.hub)
                form.buying_center = data.get('buying_center', form.buying_center)
                form.unit = data.get('unit', form.unit)
                form.online_price = data.get('online_price', form.online_price)
                form.comments = data.get('comments', form.comments)

                # Update the 'sold' field
                if 'sold' in data:
                    form.sold = data['sold']

                # Commit changes to the database
                db.session.commit()

                # Convert the updated form to a dictionary and return the response
                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = FarmerPriceDistribution.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(FarmerPriceDistributionsResource, '/farmer-price-distributions')
api.add_resource(FarmerPriceDistributionsByIdResource, '/farmer-price-distributions/<int:form_id>')

# Customer
class CustomerPriceDistributionsResource(Resource):
    @jwt_required()
    def get(self):
        forms_list = CustomerPriceDistribution.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Check if produce_id already exists
            existing_form = CustomerPriceDistribution.query.filter_by(produce_id=data['produce_id']).first()
            if existing_form:
                return {'error': 'Produce ID already exists'}, 400

            # Extract customer price distribution data
            customer_price_distribution_data = {
                'produce_id': data['produce_id'],
                'hub': data['hub'],
                'buying_center': data['buying_center'],
                'unit': data['unit'],
                'date': datetime.strptime(data['date'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                'online_price': data['online_price'],
                'comments': data['comments'],
            }

            # Create a new customer price distribution instance
            new_form = CustomerPriceDistribution(**customer_price_distribution_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class CustomerPriceDistributionsByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = CustomerPriceDistribution.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = CustomerPriceDistribution.query.get(form_id)

            if form:
                data = request.get_json()

                # Update date if provided
                date_str = data.get('date')
                if date_str:
                    form.date = datetime.strptime(date_str, "%m/%d/%Y %I:%M %p")

                # Update other fields, keeping current value if not provided in request
                form.produce_id = data.get('produce_id', form.produce_id)
                form.hub = data.get('hub', form.hub)
                form.buying_center = data.get('buying_center', form.buying_center)
                form.unit = data.get('unit', form.unit)
                form.online_price = data.get('online_price', form.online_price)
                form.comments = data.get('comments', form.comments)

                # Update the 'sold' field
                if 'sold' in data:
                    form.sold = data['sold']

                # Commit changes to the database
                db.session.commit()

                # Convert the updated form to a dictionary and return the response
                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

        @jwt_required()
        def delete(self, form_id):
            try:
                form = CustomerPriceDistribution.query.get(form_id)
                if form:
                    db.session.delete(form)
                    db.session.commit()
                    return {'message': 'Form deleted successfully'}, 200
                else:
                    return {'error': 'Form not found'}, 404
            except Exception as e:
                db.session.rollback()
                print(f"Error during DELETE request: {str(e)}")
                return {'error': 'An internal server error occurred'}, 500

api.add_resource(CustomerPriceDistributionsResource, '/customer-price-distributions')
api.add_resource(CustomerPriceDistributionsByIdResource, '/customer-price-distributions/<int:form_id>')

# Buying endpoints
# Farmer
class BuyingFarmersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = BuyingFarmer.query.filter_by(loaded=False).all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @app.route('/quarantine.php')
    def quarantine():
        return "Quarantine page content"

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            quality_data = data.get('quality', {})

            # Extract buying farmer data
            buying_farmer_data = {
                'buying_center': data['buying_center'],
                'producer': data['producer'],
                'produce': data['produce'],
                'unit': data['unit'],
                'quality': json.dumps(quality_data),
                'grn_number': data['grn_number'],
                'action': data['action'],
                'weight': data['weight'],
            }

            # Create a new buying farmer instance
            new_form = BuyingFarmer(**buying_farmer_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Include form ID in the response
            form_id = new_form.id

            if data['action'] == "Quarantine":
                # Send email with link to quarantine.php
                msg = Message('Quarantine Approval', recipients=['skaranja654@gmail.com'])
                msg.body = 'Your approval has been requested. Click the link to proceed to quarantine.'
                msg.html = f'<p>Your approval has been requested. Click the link to proceed to quarantine:</p><a href="https://extension.farmdatapod.com/quarantine.php?form=farmer&id={form_id}">Quarantine Link</a>'
                mail.send(msg)

            response_dict = new_form.to_dict()
            response_dict['form_id'] = form_id
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500


class BuyingFarmersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = BuyingFarmer.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    # @jwt_required()
    def patch(self, form_id):
        try:
            form = BuyingFarmer.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.buying_center = data.get('buying_center', form.buying_center)
                form.producer = data.get('producer', form.producer)
                form.produce = data.get('produce', form.produce)
                form.unit = data.get('unit', form.unit)
                form.quality = data.get('quality', form.quality)
                form.action = data.get('action', form.action)
                form.weight = data.get('weight', form.weight)
                form.grn_number = data.get('grn_number', form.grn_number)

                # Update loaded field only if present in request data
                if 'loaded' in data:
                    form.loaded = data['loaded']

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = BuyingFarmer.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(BuyingFarmersResource, '/buying')
api.add_resource(BuyingFarmersByIdResource, '/buying/<int:form_id>')

# Quarantine
class QuarantinesResource(Resource):
    def options(self):
        return {}, 200

    def get(self):
        forms_list = Quarantine.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    def post(self):
        try:
            data = request.get_json()

            # Extract quarantine data
            quarantine_data = {
                'action': data['action'],
                'quarantine_approved_by': data['quarantine_approved_by'],
                'new_weight_in_after_sorting_or_regrading': data['new_weight_in_after_sorting_or_regrading'],
                'new_weight_out_after_sorting_or_regrading': data['new_weight_out_after_sorting_or_regrading'],
                'buying_farmer_id': data['buying_farmer_id'],
                'buying_customer_id': data['buying_customer_id'],
            }

            # Create a new quarantine instance
            new_form = Quarantine(**quarantine_data)

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class QuarantinesByIdResource(Resource):
    def get(self, form_id):
        try:
            form = Quarantine.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    def patch(self, form_id):
        try:
            form = Quarantine.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.action = data.get('action', form.action)
                form.quarantine_approved_by = data.get('quarantine_approved_by', form.quarantine_approved_by)
                form.new_weight_in_after_sorting_or_regrading = data.get('new_weight_in_after_sorting_or_regrading', form.new_weight_in_after_sorting_or_regrading)
                form.new_weight_out_after_sorting_or_regrading = data.get('new_weight_out_after_sorting_or_regrading', form.new_weight_out_after_sorting_or_regrading)
               
                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    def delete(self, form_id):
        try:
            form = Quarantine.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(QuarantinesResource, '/quarantine')
api.add_resource(QuarantinesByIdResource, '/quarantine/<int:form_id>')

# Customer
class BuyingCustomersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = BuyingCustomer.query.filter_by(loaded=False).all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @app.route('/quarantines.php')
    def quarantines():
        return "Quarantine page content"

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            quality_data = data.get('quality', {})

            # Extract buying customer data
            buying_customer_data = {
                'customer': data['customer'],
                'produce': data['produce'],
                'unit': data['unit'],
                'quality': json.dumps(quality_data),  # Ensure quality is JSON string
                'grn_number': data['grn_number'],
                'action': data['action'],
                'weight': data['weight'],
                'online_price': data['online_price'],
            }

            # Create a new buying customer instance
            new_form = BuyingCustomer(**buying_customer_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            # Include form ID in the response
            form_id = new_form.id

            if data['action'] == "Quarantine":
                # Send email with link to quarantine.php
                msg = Message('Quarantine Approval', recipients=['skaranja654@gmail.com'])
                msg.body = 'Your approval has been requested. Click the link to proceed to quarantine.'
                msg.html = f'<p>Your approval has been requested. Click the link to proceed to quarantine:</p><a href="https://extension.farmdatapod.com/quarantine.php?form=customer&id={form_id}">Quarantine Link</a>'
                mail.send(msg)

            response_dict = new_form.to_dict()
            response_dict['form_id'] = form_id
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class BuyingCustomersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = BuyingCustomer.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    # @jwt_required()
    def patch(self, form_id):
        try:
            form = BuyingCustomer.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.customer = data.get('customer', form.customer)
                form.produce = data.get('produce', form.produce)
                form.unit = data.get('unit', form.unit)
                form.quality = data.get('quality', form.quality)
                form.action = data.get('action', form.action)
                form.weight = data.get('weight', form.weight)
                form.online_price = data.get('online_price', form.online_price)
                form.grn_number = data.get('grn_number', form.grn_number)

                if 'loaded' in data:
                    form.loaded = data['loaded']

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = BuyingCustomer.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(BuyingCustomersResource, '/selling')
api.add_resource(BuyingCustomersByIdResource, '/selling/<int:form_id>')

# Mpesa Payments

# get Oauth token from M-pesa [function]
# Mpesa Payments
# Receiving payments
# get Oauth token from M-pesa [function]
def get_mpesa_token():
    load_dotenv()  # Load environment variables from .env file
    consumer_key = os.getenv("CONSUMER_KEY")
    consumer_secret = os.getenv("CONSUMER_SECRET")
    
    if not consumer_key or not consumer_secret:
        raise ValueError("CONSUMER_KEY or CONSUMER_SECRET not found in environment variables.")
    
    api_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

    # make a get request using python requests library
    r = requests.get(api_URL, auth=HTTPBasicAuth(consumer_key, consumer_secret))

    # return access_token from response
    return r.json()['access_token']

class MakeSTKPush(Resource):

    # get 'phone' and 'amount' from request body
    parser = reqparse.RequestParser()
    parser.add_argument('phone',
            type=str,
            required=True,
            help="This fied is required")

    parser.add_argument('amount',
            type=str,
            required=True,
            help="this fied is required")

    # make stkPush method
    def post(self):

        """ make and stk push to daraja API"""

        encode_data = b"<Business_shortcode><online_passkey><current timestamp>" 

        # encode business_shortcode, online_passkey and current_time (yyyyMMhhmmss) to base64
        passkey  = base64.b64encode(encode_data)

        # make stk push
        try:

            # get access_token
            access_token = get_mpesa_token()

            # stk_push request url
            api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

            # put access_token in request headers
            headers = { "Authorization": f"Bearer {access_token}" ,"Content-Type": "application/json" }

            # get phone and amount from request data
            data = MakeSTKPush.parser.parse_args()
            phone = data['phone']
            amount = data['amount']

            # get phone and amount
            data = MakeSTKPush.parser.parse_args()

            # define request body
            request = {
                "BusinessShortCode": 174379,
                "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjQwNDExMTYxMTI3",
                "Timestamp": "20240411161127",
                "TransactionType": "CustomerPayBillOnline",
                "Amount": amount,
                "PartyA": 254708374149,
                "PartyB": 174379,
                "PhoneNumber": phone,
                "CallBackURL": "https://deploy-run.onrender.com/offline-payment/confirmation",
                "AccountReference": "Farm Data Pod",
                "TransactionDesc": "Payment of X" 
            }

            # make request and catch response
            response = requests.post(api_url,json=request,headers=headers)

            # check response code for errors and return response
            if response.status_code > 299:
                return{
                    "success": False,
                    "message":"Sorry, something went wrong please try again later."
                },400

            # CheckoutRequestID = response.text['CheckoutRequestID']
            # return a respone to your user
            return {
                "data": json.loads(response.text)
            },200

        except:
            # catch error and return respones

            return {
                "success":False,
                "message":"Sorry something went wrong please try again."
            },400

# stk push path [POST request to {baseURL}/stkpush]
api.add_resource(MakeSTKPush,"/stkpush")

# Mpesa making payments
class MpesaBase:
    def __init__(self, env="sandbox", sandbox_url="https://sandbox.safaricom.co.ke", 
                 live_url="https://api.safaricom.co.ke"):
        load_dotenv()  # Load environment variables from .env file
        self.env = env
        self.app_key = os.getenv("APP_KEY")
        self.app_secret = os.getenv("APP_SECRET")
        self.sandbox_url = sandbox_url
        self.live_url = live_url
        self.token = None

        if not self.app_key or not self.app_secret:
            raise ValueError("APP_KEY or APP_SECRET not found in environment variables.")

    def authenticate(self):
        """To make Mpesa API calls, you will need to authenticate your app. This method is used to fetch the access token
        required by Mpesa. Mpesa supports client_credentials grant type. To authorize your API calls to Mpesa,
        you will need a Basic Auth over HTTPS authorization token. The Basic Auth string is a base64 encoded string
        of your app's client key and client secret.

            **Returns:**
                - access_token (str): This token is to be used with the Bearer header for further API calls to Mpesa.
        """
        if self.env == "production":
            base_safaricom_url = self.live_url
        else:
            base_safaricom_url = self.sandbox_url
        authenticate_uri = "/oauth/v1/generate?grant_type=client_credentials"
        authenticate_url = f"{base_safaricom_url}{authenticate_uri}"
        print(f"Authentication URL: {authenticate_url}")
        print(f"App Key: {self.app_key}")
        print(f"App Secret: {self.app_secret}")
        r = requests.get(authenticate_url,
                         auth=HTTPBasicAuth(str(self.app_key), str(self.app_secret)))
        print(f"Authentication Response Status Code: {r.status_code}")
        print(f"Authentication Response Content: {r.text}")
        r.raise_for_status()  # Raise an exception for HTTP errors
        self.token = r.json()['access_token']
        return r.json()['access_token']

class B2C(MpesaBase):
    def __init__(self, env="sandbox", sandbox_url="https://sandbox.safaricom.co.ke",
                 live_url="https://api.safaricom.co.ke"):
        # Use default values if none are provided
        super().__init__(env, sandbox_url, live_url)
        self.authentication_token = self.authenticate()

    def transact(self, initiator_name="testapi", security_credential="", command_id="BusinessPayment", amount=10,
                 party_a=600998, party_b=254713932167, remarks="Test remarks",
                 queue_timeout_url="https://mydomain.com/b2c/queue", result_url="https://mydomain.com/b2c/result", occasion="null"):
        """This method uses Mpesa's B2C API to transact between an M-Pesa short
        code to a phone number registered on M-Pesa.

                    **Args:**
                        - initiator_name (str): Username used to authenticate the transaction.
                        - security_credential (str): Generate from developer portal
                        - command_id (str): Options: SalaryPayment, BusinessPayment, PromotionPayment
                        - amount(str): Amount.
                        - party_a (int): B2C organization shortcode from which the money is to be sent.Shortcode (5-6 digits) - MSISDN (12 digits).
                        - party_b (int): MSISDN receiving the transaction (12 digits). Should start with 254 without + sign.
                        - remarks (str): Comments that are sent along with the transaction(maximum 100 characters).
                        - account_reference (str): Use if doing paybill to banks etc.
                        - queue_timeout_url (str): The url that handles information of timed out transactions.
                        - result_url (str): The url that receives results from M-Pesa api call.
                        - occasion (str):

                    **Returns:**
                        - OriginatorConverstionID (str): The unique request ID for tracking a transaction.
                        - ConversationID (str): The unique request ID returned by mpesa for each request made
                        - ResponseDescription (str): Response Description message
        """
        payload = {
            "InitiatorName": initiator_name,
            "SecurityCredential": security_credential,
            "CommandID": command_id,
            "Amount": amount,
            "PartyA": party_a,
            "PartyB": party_b,
            "Remarks": remarks,
            "QueueTimeOutURL": queue_timeout_url,
            "ResultURL": result_url,
            "Occasion": occasion
        }
        headers = {'Authorization': f"Bearer {self.authentication_token}", 'Content-Type': "application/json"}
        if self.env == "production":
            base_safaricom_url = self.live_url
        else:
            base_safaricom_url = self.sandbox_url
        saf_url = f"{base_safaricom_url}/mpesa/b2c/v1/paymentrequest"
        r = requests.post(saf_url, headers=headers, json=payload)
        print(f"Transaction Response Status Code: {r.status_code}")
        print(f"Transaction Response Content: {r.text}")
        r.raise_for_status()
        return r.json()
    
@app.route('/b2c', methods=['POST'])
def b2c_transaction():
    data = request.json
    phone_number = data.get('phone')
    amount = data.get('amount')

    security_credential = "qJ9APg6ot+QvgcH0axi4OKz2XtBsoXXaPi+OMfUxTHIeqZ2rIZEpVjbX52ojN9UduJvyjB/4NdYvLh6nPcsiIm/R/u7eF+FxHvM9yCwTubR4UhgrIUz6cVzQ0szrV4vAkysLqWb/l5/IJGsPnwklhUdqy9TkI+fMJJRJq7sm2B0AXGxuUAiRABz5qrtmODZXBXgQv8ZdwdfHi4Ye756AxdGJbxSyyqIy8/3ZSIfsHibAlGl8hCSGzWFv8YvaUk5RBVv/elaGi6ffSzbGfKyYhXJEY8fGNW72DAg1rlVnNw1Sonn4Wlv6lnNI0qpJzq8zvn18+monkQbZYIE/L7xCPg=="

    mpesa = B2C()
    response = mpesa.transact(party_b=phone_number, amount=amount, initiator_name="testapi", 
                               security_credential=security_credential, command_id="BusinessPayment",
                               party_a=600998, remarks="Test remarks",
                               queue_timeout_url="https://mydomain.com/b2c/queue", 
                               result_url="https://mydomain.com/b2c/result", occasion="null")

    return jsonify(response)

# C2B Offline Payments
def register_urls():
    access_token = get_access_token() 
    url = "https://sandbox.safaricom.co.ke/mpesa/c2b/v1/registerurl"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "ShortCode": "600992",
        "ResponseType": "Completed",
        # Remember to pass the url variable
        "ConfirmationURL": "https://deploy-run.onrender.com/offline-payment/confirmation",
        "ValidationURL": "https://deploy-run.onrender.com/offline-payment/validation"
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()

@app.route('/offline-payment/validation', methods=['POST'])
def payment_validation():
    data = request.json
    if not data:
        return jsonify({"ResultCode": 1, "ResultDesc": "Failed, no data received"})

    try:
        phone_number = '+' + str(data['MSISDN'])
        transaction_id = data['TransID']
        amount = data['TransAmount']
        till_number = data['BusinessShortCode']

        return jsonify({"ResultCode": 0, "ResultDesc": "Validation Successful"})
    
    except KeyError as e:
        return jsonify({"ResultCode": 500, "ResultDesc": f"Failed due to missing key: {str(e)}"})

@app.route('/offline-payment/confirmation', methods=['POST'])
def payment_confirmation():
    data = request.json
    if not data:
        return jsonify({"ResultCode": 1, "ResultDesc": "Failed, no data received"})

    try:
        # Extract relevant details from the confirmation payload
        phone_number = '+' + str(data['MSISDN'])
        amount = data['TransAmount']
        transaction_id = data['TransID']
        till_number = data['BusinessShortCode']

        # Send confirmation SMS
        send_confirmation_sms(phone_number, amount)

        return jsonify({"ResultCode": 0, "ResultDesc": "Payment Confirmed Successfully"})
    except KeyError as e:
        # Handle missing keys in the response
        return jsonify({"ResultCode": 1, "ResultDesc": f"Failed due to missing key: {str(e)}"})


# Africa's Talking sms confirmation
def send_confirmation_sms(phone_number, amount):

    username = os.getenv('AFRICASTALKING_USERNAME')
    api_key = os.getenv('AFRICASTALKING_API_KEY')

    # Initialize Africa's Talking client
    africastalking.initialize(username, api_key)

    # Create SMS service
    sms = africastalking.SMS

    # Send SMS
    response = sms.send(
        f"Your payment of KES {amount} has been successfully received. Thank you!",
        [phone_number] 
    )

    # Check the response and print message
    if response['SMSMessageData']['Recipients']:
        print("SMS sent successfully!")
        for recipient in response['SMSMessageData']['Recipients']:
            print(f"Message to {recipient['number']} sent with status: {recipient['status']}")
    else:
        print("Failed to send SMS.")

# send_confirmation_sms(10)

# Card Payment
# Render the payment form
@app.route('/')
def index():
    return render_template('payment_form.html')

# Handle the payment process
@app.route('/charge', methods=['POST'])
def charge():
    # Fetch values from the request
    amount = request.json['amount']
    email = request.json['email']

    # Load M-Pesa API credentials from environment variables
    consumer_key = os.getenv('MPESA_CONSUMER_KEY')
    consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
    callback_url = os.getenv('MPESA_CALLBACK_URL')

    # Construct the payment URL
    payment_url = f"https://demo.pesapal.com/API/PostPesapalDirectOrderV4?oauth_consumer_key={consumer_key}&oauth_signature_method=PLAINTEXT&oauth_signature={consumer_secret}%26&oauth_timestamp=123456789&oauth_nonce=123456&oauth_callback={callback_url}"

    # Make a request to Pesapal to initiate the payment
    response = requests.post(payment_url, data={
        'amount': amount,
        'description': 'Payment for Your Service',
        'email': email,
        'currency': 'KES',
    })

    if response.status_code == 200:
        # If successful, redirect the user to the Pesapal payment page
        return response.text
    else:
        # If there's an error, return an error message
        return jsonify({'status': 'error', 'message': 'Failed to initiate payment'})
    
# DPO Card Payment
@app.route('/process_payment', methods=['POST'])
def process_payment():
    try:
        # Get dynamic input from request
        data = request.json
        amount = data.get('amount')
        card_number = data.get('card_number')
        card_expiry = data.get('card_expiry')
        card_cvv = data.get('card_cvv')
        customer_name = data.get('customer_name', 'Customer')
        customer_email = data.get('customer_email', 'customer@example.com')

        # Construct user query
        user_query = {
            "amount": amount,
            "service_description": "Payment",
            "customer_name": customer_name,
            "customer_email": customer_email,
            "company_token": os.getenv("COMPANY_TOKEN"),
            "service_type": os.getenv("SERVICE_TYPE"),
            "currency": os.getenv("CURRENCY"),
            "company_reference": os.getenv("COMPANY_REFERENCE"),
            "address": os.getenv("ADDRESS"),
        }

        # Create token
        create_token_response = gateway.create_token(user_query)
        transtoken = create_token_response.get("API3G", {}).get("TransToken")

        # Verify token
        verify_token_response = gateway.verify_token({"transtoken": transtoken})
        transaction_ready = verify_token_response['API3G'].get('Result') == '900'

        if transaction_ready:
            # Charge credit card
            charge_card_query = {
                "transtoken": transtoken,
                "card_number": card_number,
                "card_expiry": card_expiry,
                "card_cvv": card_cvv,
                "card_holder_name": customer_name,
            }
            charge_card_response = gateway.charge_credit_card(charge_card_query)
            return jsonify(charge_card_response)
        else:
            return jsonify({"error": "Transaction status is not ready for charging."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Payment Endpoints
# Farmer
class PaymentFarmersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = PaymentFarmer.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Extract payment farmer data
            payment_farmer_data = {
                'buying_center': data['buying_center'],
                'cig': data['cig'],
                'producer': data['producer'],
                'grn': data['grn'],
                'net_balance': data['net_balance'],
                'payment_type': data['payment_type'],
                'outstanding_loan_amount': data['outstanding_loan_amount'],
                'payment_due': data['payment_due'],
                'set_loan_deduction': data['set_loan_deduction'],
                'net_balance_before': data['net_balance_before'],
                'net_balance_after_loan_deduction': data['net_balance_after_loan_deduction'],
                'comment': data['comment'],
            }

            # Create a new payment farmer instance
            new_form = PaymentFarmer(**payment_farmer_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class PaymentFarmersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = PaymentFarmer.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = PaymentFarmer.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.buying_center = data.get('buying_center', form.buying_center)
                form.cig = data.get('cig', form.cig)
                form.producer = data.get('producer', form.producer)
                form.grn = data.get('grn', form.grn)
                form.net_balance = data.get('net_balance', form.net_balance)
                form.payment_type = data.get('payment_type', form.payment_type)
                form.outstanding_loan_amount = data.get('outstanding_loan_amount', form.outstanding_loan_amount)
                form.payment_due = data.get('payment_due', form.payment_due)
                form.set_loan_deduction = data.get('set_loan_deduction', form.set_loan_deduction)
                form.net_balance_before = data.get('net_balance_before', form.net_balance_before)
                form.net_balance_after_loan_deduction = data.get('net_balance_after_loan_deduction', form.net_balance_after_loan_deduction)
                form.comment = data.get('comment', form.comment)

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = PaymentFarmer.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(PaymentFarmersResource, '/make-payment')
api.add_resource(PaymentFarmersByIdResource, '/make-payment/<int:form_id>')

# Customer
class PaymentCustomersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = PaymentCustomer.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Extract payment customer data
            payment_customer_data = {
                'village_or_estate': data['village_or_estate'],
                'customer': data['customer'],
                'grn': data['grn'],
                'amount': data['amount'],
                'net_balance': data['net_balance'],
                'payment_type': data['payment_type'],
                'enter_amount': data['enter_amount'],
                'net_balance_before': data['net_balance_before'],
                'net_balance_after': data['net_balance_after'],
                'comment': data['comment'],
            }

            # Create a new payment customer instance
            new_form = PaymentCustomer(**payment_customer_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class PaymentCustomersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = PaymentCustomer.query.get(form_id)
            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            form = PaymentCustomer.query.get(form_id)

            if form:
                # Updates form attributes based on the request data
                data = request.get_json()

                form.village_or_estate = data.get('village_or_estate', form.village_or_estate)
                form.customer = data.get('customer', form.customer)
                form.grn = data.get('grn', form.grn)
                form.amount = data.get('amount', form.amount)
                form.net_balance = data.get('net_balance', form.net_balance)
                form.payment_type = data.get('payment_type', form.payment_type)
                form.enter_amount = data.get('enter_amount', form.enter_amount)
                form.net_balance_before = data.get('net_balance_before', form.net_balance_before)
                form.net_balance_after = data.get('net_balance_after', form.net_balance_after)
                form.comment = data.get('comment', form.comment)

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = PaymentCustomer.query.get(form_id)
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(PaymentCustomersResource, '/receive-payment')
api.add_resource(PaymentCustomersByIdResource, '/receive-payment/<int:form_id>')


# Plan Jouney endpoint
class PlanJourneyResource(Resource):
    @jwt_required()
    @api.expect(api.model('PlanJourney', {
        'truck': fields.String,
        'driver': fields.String,
        'starting_mileage': fields.String,
        'starting_fuel': fields.String,
        'documentation': fields.String,
        'start_location': fields.String,
        'stop_points': fields.String,
        'final_destination': fields.String,
        'date_and_time': fields.String,
    }))
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        try:
            forms_list = PlanJourney.query.all()
            forms_dict_list = [form.to_dict() for form in forms_list]
            return {'forms': forms_dict_list}, 200

        except Exception as e:
            print(f"Error during retrieving planned journey: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            current_user_id = get_jwt_identity()

            # Parse datetime string to the expected format
            date_and_time = datetime.strptime(data['date_and_time'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')

            new_form = PlanJourney(
                truck=data['truck'],
                driver=data['driver'],
                starting_mileage=data['starting_mileage'],
                starting_fuel=data['starting_fuel'],
                documentation=data['documentation'],
                start_location=data['start_location'],
                final_destination=data['final_destination'],
                date_and_time=date_and_time,
                user_id=current_user_id,
                stop_points=json.dumps(data.get('stop_points', []))  # Ensure stop_points is JSON string
            )

            # Add Dispatch Inputs
            if 'dispatch_inputs' in data:
                for dispatch_input_data in data['dispatch_inputs']:
                    new_dispatch_input = DispatchInput(
                        grn=dispatch_input_data['grn'],
                        input=dispatch_input_data['input'],
                        description=dispatch_input_data['description'],
                        number_of_units=dispatch_input_data['number_of_units'],
                    )
                    new_form.dispatch_inputs.append(new_dispatch_input)

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add the PlanJourneyResource to the API
api.add_resource(PlanJourneyResource, '/plan-journey')

# Plan Journey by Id
class PlanJourneyByIdResource(Resource):
    @jwt_required()

    def get(self, journey_id):
        try:
            journey = PlanJourney.query.get(journey_id)
            if journey:
                return journey.to_dict(), 200
            else:
                return {'error': 'Journey not found'}, 404

        except Exception as e:
            print(f"Error during retrieving journey: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500


    @jwt_required()

    def patch(self, journey_id):
        try:
            journey = PlanJourney.query.get(journey_id)
            if journey:
                data = request.get_json()

                # Update fields if provided in the request
                for key, value in data.items():
                    if key == 'stop_points':
                        journey.stop_points = value
                    elif key == 'dispatch_inputs':
                        # Clear existing dispatch_inputs
                        journey.dispatch_inputs = []

                        # Add updated dispatch_inputs
                        for dispatch_input_data in value:
                            new_dispatch_input = DispatchInput(
                                grn=dispatch_input_data['grn'],
                                input=dispatch_input_data['input'],
                                description=dispatch_input_data['description'],
                                number_of_units=dispatch_input_data['number_of_units'],
                            )
                            journey.dispatch_inputs.append(new_dispatch_input)
                    elif key == 'date_and_time':
                        # Parse the date and time string into a datetime object
                        journey.date_and_time = datetime.strptime(value, '%m/%d/%Y %I:%M %p')
                    elif hasattr(journey, key):
                        setattr(journey, key, value)

                db.session.commit()
                return journey.to_dict(), 200
            else:
                return {'error': 'Journey not found'}, 404

        except Exception as e:
            db.session.rollback()
            print(f"Error during journey update: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def delete(self, journey_id):
        try:
            journey = PlanJourney.query.get(journey_id)
            if journey:
                db.session.delete(journey)
                db.session.commit()
                return {'message': 'Journey deleted successfully'}, 200
            else:
                return {'error': 'Journey not found'}, 404

        except Exception as e:
            db.session.rollback()
            print(f"Error during journey deletion: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(PlanJourneyByIdResource, '/plan-journey/<int:journey_id>')

class LoadingResource(Resource):    
    @jwt_required()

    def get(self):
        try:
            loadings = Loading.query.filter_by(offloaded=False).all()

            loadings_dict_list = [loading.to_dict() for loading in loadings]

            return {'loadings': loadings_dict_list}, 200

        except Exception as e:
            print(f"Error during retrieving loadings: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def post(self):
        try:
            data = request.get_json()

            current_user_id = get_jwt_identity()

            new_loading = Loading(
                grn=data['grn'],
                total_weight=data['total_weight'],
                truck_loading_number=data['truck_loading_number'],
                from_=data['from_'],
                to=data['to'],
                comment=data['comment'],
                user_id=current_user_id
            )

            db.session.add(new_loading)
            db.session.commit()

            response_dict = new_loading.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during loading creation: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
        
api.add_resource(LoadingResource, '/loading')

class LoadingByIdResource(Resource):
    @jwt_required()

    def get(self, loading_id):
        try:
            loading = Loading.query.get(loading_id)
            if loading:
                return loading.to_dict(), 200
            else:
                return {'error': 'Loading not found'}, 404

        except Exception as e:
            print(f"Error during retrieving loading: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def patch(self, loading_id):
        try:
            loading = Loading.query.get(loading_id)
            if loading:
                data = request.get_json()
                for key, value in data.items():
                    if hasattr(loading, key):
                        setattr(loading, key, value)
                db.session.commit()
                return loading.to_dict(), 200
            else:
                return {'error': 'Loading not found'}, 404

        except Exception as e:
            db.session.rollback()
            print(f"Error during loading update: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()

    def delete(self, loading_id):
        try:
            loading = Loading.query.get(loading_id)
            if loading:
                db.session.delete(loading)
                db.session.commit()
                return {'message': 'Loading deleted successfully'}, 200
            else:
                return {'error': 'Loading not found'}, 404

        except Exception as e:
            db.session.rollback()
            print(f"Error during loading deletion: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(LoadingByIdResource, '/loading/<int:loading_id>')

# Offloading endpoints
# Offloading
class OffloadingResource(Resource):
    @jwt_required()
    def get(self):
        offloading_list = Offloading.query.all()
        return jsonify([offloading.to_dict() for offloading in offloading_list])

    @jwt_required()
    def post(self):
        data = request.json
        offloaded_load = data.get('offloaded_load')
        total_weight = data.get('total_weight')
        truck_offloading_number = data.get('truck_offloading_number')
        comment = data.get('comment')
        user_id = get_jwt_identity()

        new_offloading = Offloading(
            offloaded_load=offloaded_load,
            total_weight=total_weight,
            truck_offloading_number=truck_offloading_number,
            comment=comment,
            user_id=user_id
        )
        db.session.add(new_offloading)
        db.session.commit()

        return {'message': 'Offloading created successfully'}, 201

class OfflloadingsByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        offloading = Offloading.query.get_or_404(form_id)
        return offloading.to_dict()

    @jwt_required()
    def patch(self, form_id):
        current_user_id = get_jwt_identity()
        offloading = Offloading.query.get_or_404(form_id)

        if offloading.user_id != current_user_id:
            return {'message': 'You are not authorized to modify this offloading'}, 403

        data = request.json
        for key, value in data.items():
            setattr(offloading, key, value)
        db.session.commit()
        return {'message': 'Offloading updated successfully'}, 200

    @jwt_required()
    def delete(self, form_id):
        current_user_id = get_jwt_identity()
        offloading = Offloading.query.get_or_404(form_id)

        if offloading.user_id != current_user_id:
            return {'message': 'You are not authorized to delete this offloading'}, 403

        db.session.delete(offloading)
        db.session.commit()
        return {'message': 'Offloading deleted successfully'}, 200
    
api.add_resource(OffloadingResource, '/offloading')
api.add_resource(OfflloadingsByIdResource, '/offloading/<int:form_id>')

# Processing Endpoints
class ProcessingResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = Processing.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            processing_data = {
                'product_name': data['product_name'],
                'traceability_code': data['traceability_code'],
                'batch_number': data['batch_number'],
                'received_date': data['received_date'],
                'weight_before_processing': data['weight_before_processing'],
                'processor_name': data['processor_name'],
                'supervisor_name': data['supervisor_name'],
                'issued_by': data['issued_by'],
                'received_by': data['received_by'],
                'approved_by': data['approved_by'],
                'labor_cost_per_unit': data['labor_cost_per_unit'],
                'processing_method': data['processing_method'],
                'product_quality': data['product_quality'],
                'best_before_date': data['best_before_date'],
                'packaging_type': data['packaging_type'],
                'unit_cost': data['unit_cost'],
                'number_of_units_issued': data['number_of_units_issued'],
                'received_product': data['received_product'],
                'waste_generated_kg': data['waste_generated_kg'],
                'waste_sold_kg': data['waste_sold_kg'],
                'waste_dumped_kg': data['waste_dumped_kg'],
            }

            new_form = Processing(**processing_data)

            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            db.session.add(new_form)
            db.session.commit()

            inputs_data = data.get('inputs', [])
            for input_data in inputs_data:
                new_input = Input(**input_data)
                new_form.inputs.append(new_input)

            db.session.commit()

            produces_data = data.get('product_mixes', [])
            for produce_data in produces_data:
                new_produce = ProductMix(**produce_data)
                new_form.product_mixes.append(new_produce)

            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

api.add_resource(ProcessingResource, '/processing')

# Processing by Id
class ProcessingByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        try:
            form = Processing.query.get(form_id)

            if form:
                form_dict = form.to_dict()
                return form_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            print(f"Error during GET request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def patch(self, form_id):
        try:
            data = request.get_json()

            # Assuming form_id is a single value (auto-incrementing primary key)
            form = Processing.query.filter_by(id=form_id).first()

            if form:
                # Update form attributes based on the request data
                form.product_name = data.get('product_name', form.product_name)
                form.traceability_code = data.get('traceability_code', form.traceability_code)
                form.batch_number = data.get('batch_number', form.batch_number)
                form.received_date = data.get('received_date', form.received_date)
                form.weight_before_processing = data.get('weight_before_processing', form.weight_before_processing)
                form.processor_name = data.get('processor_name', form.processor_name)
                form.supervisor_name = data.get('supervisor_name', form.supervisor_name)
                form.issued_by = data.get('issued_by', form.issued_by)
                form.received_by = data.get('received_by', form.received_by)
                form.approved_by = data.get('approved_by', form.approved_by)
                form.labor_cost_per_unit = data.get('labor_cost_per_unit', form.labor_cost_per_unit)
                form.processing_method = data.get('processing_method', form.processing_method)
                form.product_quality = data.get('product_quality', form.product_quality)
                form.best_before_date = data.get('best_before_date', form.best_before_date)
                form.packaging_type = data.get('packaging_type', form.packaging_type)
                form.unit_cost = data.get('unit_cost', form.unit_cost)
                form.number_of_units_issued = data.get('number_of_units_issued', form.number_of_units_issued)
                form.received_product = data.get('received_product', form.received_product)
                form.waste_generated_kg = data.get('waste_generated_kg', form.waste_generated_kg)
                form.waste_sold_kg = data.get('waste_sold_kg', form.waste_sold_kg)
                form.waste_dumped_kg = data.get('waste_dumped_kg', form.waste_dumped_kg)

                # Update inputs
                inputs_data = data.get('inputs', [])
                form.inputs = [Input(**input_data) for input_data in inputs_data]

                db.session.commit()

                products_mixes_data = data.get('product_mixes', [])
                form.product_mixes = [ProductMix(**product_mixes_data) for product_mixes_data in products_mixes_data]

                db.session.commit()

                response_dict = form.to_dict()
                return response_dict, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during PATCH request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

    @jwt_required()
    def delete(self, form_id):
        try:
            form = Processing.query.get(int(form_id))
            if form:
                db.session.delete(form)
                db.session.commit()
                return {'message': 'Form deleted successfully'}, 200
            else:
                return {'error': 'Form not found'}, 404
        except Exception as e:
            db.session.rollback()
            print(f"Error during DELETE request: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

# Add the resource to the API
api.add_resource(ProcessingByIdResource, '/processing/<int:form_id>')
# Rural Worker
from sqlalchemy import exc
class RuralWorkersResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = RuralWorker.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            current_user_id = get_jwt_identity()

            new_form = RuralWorker(
                other_name=data['other_name'],
                last_name=data['last_name'],
                rural_worker_code=data['rural_worker_code'],
                id_number=data['id_number'],
                gender=data['gender'],
                date_of_birth=data['date_of_birth'],
                email=data['email'],
                phone_number=data['phone_number'],
                education_level=data['education_level'],
                service=data['service'],
                other=data['other'],
                county=data['county'],
                sub_county=data['sub_county'],
                ward=data['ward'],
                village=data['village'],
                user_id=current_user_id
            )

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except IntegrityError as e:
            db.session.rollback()

            original_error_message = str(e.orig)
            print("Original IntegrityError message:", original_error_message)

            # Check for specific unique constraint violations
            if 'Duplicate entry' in original_error_message:
                if 'user_id' in original_error_message:
                    return {'error': 'This user has already submitted a form.'}, 400
                elif 'rural_worker_code' in original_error_message:
                    return {'error': 'Rural worker code already exists.'}, 400
                elif 'email' in original_error_message:
                    return {'error': 'Email already exists.'}, 400
                elif 'phone_number' in original_error_message:
                    return {'error': 'Phone number already exists.'}, 400
                elif 'id_number' in original_error_message:
                    return {'error': 'ID number already exists.'}, 400

            return {'error': 'Integrity error occurred. Please check your data.'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

class RuralWorkersByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = RuralWorker.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            form = RuralWorker.query.get_or_404(form_id)
            data = request.get_json()

            date_format_client = '%m/%d/%Y %I:%M %p'
            data['date_of_birth'] = datetime.strptime(data['date_of_birth'], date_format_client).strftime('%Y-%m-%d')

            # Validate required fields
            required_fields = ['other_name', 'last_name', 'rural_worker_code', 'id_number', 'gender', 'date_of_birth', 'email', 'phone_number', 'education_level', 'service', 'other', 'county', 'sub_county', 'ward', 'village']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400

            # Update form fields
            form.other_name = data['other_name']
            form.last_name = data['last_name']
            form.rural_worker_code = data['rural_worker_code']
            form.id_number = data['id_number']
            form.gender = data['gender']
            form.date_of_birth = data.get('date_of_birth', form.date_of_birth)
            form.email = data['email']
            form.phone_number = data['phone_number']
            form.education_level = data['education_level']
            form.service = data['service']
            form.other = data['other']
            form.county = data['county']
            form.sub_county = data['sub_county']
            form.ward = data['ward']
            form.village = data['village']

            db.session.commit()
            return form.to_dict()

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Kindly correctly fill the form'}, 400

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = RuralWorker.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(RuralWorkersResource, '/rural-workers')
api.add_resource(RuralWorkersByIdResource, '/rural-workers/<int:form_id>')

# Input finance
class InputFinancesResource(Resource):
    @jwt_required()
    def options(self):
        # Preflight request, respond successfully
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = InputFinance.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            data = request.get_json()

            # Extract input finance data
            input_finance_data = {
                'farmer': data['farmer'],
                'hub': data['hub'],
                'cig': data['cig'],
                'input': data['input'],
                'number_of_units': data['number_of_units'],
                'cost_per_unit': data['cost_per_unit'],
                'payment_cycle': data['payment_cycle'],
                'installment': data['installment'],
                'due_date': datetime.strptime(data['due_date'], '%m/%d/%Y %I:%M %p').strftime('%Y-%m-%d %H:%M:%S'),
                'total_cost': data['total_cost'],
            }

            # Create a new input finance instance
            new_form = InputFinance(**input_finance_data)

            # Set the user attribute
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            # Commit the new_form to the database
            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500

class InputFinanceByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = InputFinance.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            form = InputFinance.query.get_or_404(form_id)
            data = request.get_json()

            date_str = data.get('due_date')
            if date_str:
                form.due_date = datetime.strptime(date_str, "%m/%d/%Y %I:%M %p")

            form.farmer = data.get('farmer', form.farmer)
            form.hub = data.get('hub', form.hub)
            form.cig = data.get('cig', form.cig)
            form.input = data.get('input', form.input)
            form.number_of_units = data.get('number_of_units', form.number_of_units)
            form.cost_per_unit = data.get('cost_per_unit', form.cost_per_unit)
            form.payment_cycle = data.get('payment_cycle', form.payment_cycle)
            form.installment = data.get('installment', form.installment)
            form.total_cost = data.get('total_cost', form.total_cost)

            db.session.commit()
            return form.to_dict()

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = InputFinance.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(InputFinancesResource, '/input-finances')
api.add_resource(InputFinanceByIdResource, '/input-finances/<int:form_id>')

# Add Product
class AddProductsResource(Resource):
    @jwt_required()
    def options(self):
        return {}, 200

    @jwt_required()
    def get(self):
        forms_list = AddProduct.query.all()
        forms_dict_list = [form.to_dict() for form in forms_list]
        return forms_dict_list, 200

    @jwt_required()
    def post(self):
        try:
            # Extract form fields
            item_type = request.form.get('item_type')
            product_name = request.form.get('product_name')
            product_code = request.form.get('product_code')
            category = request.form.get('category')
            selling_price = request.form.get('selling_price')
            purchase_price = request.form.get('purchase_price')
            quantity = request.form.get('quantity')
            barcode = request.form.get('barcode')
            units = request.form.get('units')
            discount_type = request.form.get('discount_type')
            alert_quantity = request.form.get('alert_quantity')
            tax = request.form.get('tax')
            description = request.form.get('description')
            product_image = request.form.get('product_image')

            add_product_data = {
                'item_type': item_type,
                'product_name': product_name,
                'product_code': product_code,
                'category': category,
                'selling_price': selling_price,
                'purchase_price': purchase_price,
                'quantity': quantity,
                'barcode': barcode,
                'units': units,
                'discount_type': discount_type,
                'alert_quantity': alert_quantity,
                'tax': tax,
                'description': description,
                'product_image': product_image,
            }

            new_form = AddProduct(**add_product_data)

            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            new_form.user = user

            db.session.add(new_form)
            db.session.commit()

            response_dict = new_form.to_dict()
            return response_dict, 201

        except Exception as e:
            db.session.rollback()
            print(f"Error during form submission: {str(e)}")
            return {'error': 'An internal server error occurred'}, 500
class AddProductByIdResource(Resource):
    @jwt_required()
    def get(self, form_id):
        form = AddProduct.query.get_or_404(form_id)
        return form.to_dict()

    @jwt_required()
    def patch(self, form_id):
        try:
            form = AddProduct.query.get_or_404(form_id)
            data = request.get_json()

            form.item_type = data.get('item_type', form.item_type)
            form.product_name = data.get('product_name', form.product_name)
            form.product_code = data.get('product_code', form.product_code)
            form.category = data.get('category', form.category)
            form.selling_price = data.get('selling_price', form.selling_price)
            form.purchase_price = data.get('purchase_price', form.purchase_price)
            form.quantity = data.get('quantity', form.quantity)
            form.barcode = data.get('barcode', form.barcode)
            form.units = data.get('units', form.units)
            form.discount_type = data.get('discount_type', form.discount_type)
            form.alert_quantity = data.get('alert_quantity', form.alert_quantity)
            form.tax = data.get('tax', form.tax)
            form.description = data.get('description', form.description)
            form.product_image = data.get('product_image', form.product_image)

            db.session.commit()
            return form.to_dict()

        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    def delete(self, form_id):
        form = AddProduct.query.get_or_404(form_id)
        db.session.delete(form)
        db.session.commit()
        return {'message': 'Form deleted successfully'}

api.add_resource(AddProductsResource, '/add-products')
api.add_resource(AddProductByIdResource, '/add-products/<int:form_id>')

if __name__ == '__main__':
    app.run(debug=True)
