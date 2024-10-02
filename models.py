import re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates, relationship
from sqlalchemy import BigInteger, DateTime
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates, relationship
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
import json

Base = declarative_base()

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    """users model"""
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    other_name = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(255), nullable=False)
    verification_token = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    # table relationships
    hub_registration = relationship('Hub', back_populates='user')
    buying_center = relationship('BuyingCenter', back_populates='user')
    cigs = db.relationship('CIG', back_populates='user')
    hub_users_registration = relationship('HubUser', back_populates='user')
    custom_users_registration = relationship('CustomUser', back_populates='user')
    hq_users_registration = relationship('HQUser', back_populates='user')
    processing_users_registration = relationship('ProcessingUser', back_populates='user')
    individual_logistician_registration = relationship('IndividualLogisticianUser', back_populates='user')
    organisation_logistician_registration = relationship('OrganisationLogisticianUser', back_populates='user')
    individual_customer_registration = relationship('IndividualCustomerUser', back_populates='user')
    organisation_customer_registration = relationship('OrganisationCustomerUser', back_populates='user')
    producer_biodata_registration = relationship('ProducerBiodata', back_populates='user')
    cig_producer_biodata_registration = relationship('CIGProducerBiodata', back_populates='user')
    farmer_field_registration = relationship('FarmerFieldRegistration', back_populates='user')
    cig_farmer_field_registration = relationship('CIGFarmerFieldRegistration', back_populates='user')
    season_planning = relationship('SeasonPlanning', back_populates='user')
    extension_service_registration = relationship('ExtensionService', back_populates='user')
    training_registration = relationship('Training', back_populates='user')
    attendance_registration = relationship('Attendance', back_populates='user')
    farmer_price_distribution_registration = relationship('FarmerPriceDistribution', back_populates='user')
    customer_price_distribution_registration = relationship('CustomerPriceDistribution', back_populates='user')
    buying_farmer_registration = relationship('BuyingFarmer', back_populates='user')
    buying_customer_registration = relationship('BuyingCustomer', back_populates='user')
    payment_farmer_registration = relationship('PaymentFarmer', back_populates='user')
    plan_journey_registration = relationship('PlanJourney', back_populates='user')
    payment_customer_registration = relationship('PaymentCustomer', back_populates='user')
    loading_registration = relationship('Loading', back_populates='user')
    offloading_registration = relationship('Offloading', back_populates='user')
    processing_registration = relationship('Processing', back_populates='user')
    rural_worker_registration = relationship('RuralWorker', back_populates='user', uselist=False)
    input_finance_registration = relationship('InputFinance', back_populates='user')
    add_product_registration = relationship('AddProduct', back_populates='user')

    @staticmethod
    def validate_password(password):
        """Password validation"""
        if not re.search(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[A-Z])', password):
            raise ValueError('Password must include at least one number, special character, and uppercase letter.')
        return password

    @validates('password')
    def validate_password_field(self, key, password):
        """Validate the password field using the static method"""
        return self.validate_password(password)

    def to_dict(self):
        """to dict password validation"""
        return {
            "id": self.id,
            "last_name": self.last_name,
            "other_name": self.other_name,
            "user_type" : self.user_type,
            "email": self.email,
            "email_verified": self.email_verified,
            "password": self.password,
            "role": self.role,
            "verification_token": self.verification_token,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

class Hub(db.Model, SerializerMixin):
    """hub model"""
    __tablename__ = "hubs"

    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(255), nullable=False)
    hub_name = db.Column(db.String(255), nullable=False)
    hub_code = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    year_established = db.Column(DateTime)
    ownership = db.Column(db.String(255), nullable=False)
    floor_size = db.Column(db.String(255), nullable=False)
    facilities = db.Column(db.String(255), nullable=False)
    input_center = db.Column(db.String(255), nullable=False)
    type_of_building = db.Column(db.String(255), nullable=False)
    longitude = db.Column(db.String(255), nullable=False)
    latitude = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='hub_registration')

    # One-to-many relationship with Key Contact
    key_contacts = db.relationship('KeyContact', back_populates='hub', cascade='all, delete-orphan')



    def to_dict(self):
        """to dict hub model"""
        return {
            "id": self.id,
            "region": self.region,
            "hub_name": self.hub_name,
            "hub_code": self.hub_code,
            "address": self.address,
            "ownership": self.ownership,
            "floor_size": self.floor_size,
            "facilities": self.facilities,
            "input_center": self.input_center,
            "type_of_building": self.type_of_building,
            "longitude": self.longitude,
            "latitude": self.latitude,
            "year_established": self.year_established.strftime('%Y-%m-%d') if self.year_established else None,
            "key_contacts": [key_contact.to_dict() for key_contact in self.key_contacts],
            "user_id": self.user_id,
        }

# Key Contacts
class KeyContact(db.Model):
    """key contact model"""
    __tablename__ = 'KeyContacts'

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)

    # Foreign key to Hub table
    hub_id = db.Column(db.Integer, db.ForeignKey('hubs.id'))
    hub = db.relationship('Hub', back_populates='key_contacts')

    # Foreign key to Hub table
    buying_center_id = db.Column(db.Integer, db.ForeignKey('buyingCenters.id'))
    buying_center = db.relationship('BuyingCenter', back_populates='key_contacts')

    def to_dict(self):
        """to dict key contact model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "gender": self.gender,
            "date_of_birth": self.date_of_birth.strftime('%m/%d/%Y %I:%M %p'),
            "email": self.email,
            "phone_number": self.phone_number,
            "id_number": self.id_number,
            "role": self.role,
            "hub_id": self.hub_id,
            "buying_center_id": self.buying_center_id,
        }

class BuyingCenter(db.Model, SerializerMixin):
    """buying centers model"""
    __tablename__ = "buyingCenters"

    id = db.Column(db.Integer, primary_key=True)
    hub = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)
    buying_center_name = db.Column(db.String(255), nullable=False)
    buying_center_code = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    year_established = db.Column(DateTime)
    ownership = db.Column(db.String(255), nullable=False)
    floor_size = db.Column(db.String(255), nullable=False)
    facilities = db.Column(db.String(255), nullable=False)
    input_center = db.Column(db.String(255), nullable=False)
    type_of_building = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='buying_center') #table relationship (one to one relationship)

    # Relationship to the key contacts table
    key_contacts = db.relationship('KeyContact', back_populates='buying_center', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict buying centers model"""
        return {
            "id" : self.id,
            "hub" : self.hub,
            "county" : self.county,
            "sub_county" : self.sub_county,
            "ward" : self.ward,
            "village" : self.village,
            "buying_center_name" : self.buying_center_name,
            "buying_center_code" : self.buying_center_code,
            "address" : self.address,
            "year_established": self.format_datetime(self.year_established),
            "ownership"  : self.ownership,
            "floor_size" : self.floor_size,
            "facilities" : self.facilities,
            "input_center" : self.input_center,
            "type_of_building" : self.type_of_building,
            "location" : self.location,
            "key_contacts": [key_contact.to_dict() for key_contact in self.key_contacts],
            "user_id": self.user_id
        }

    def format_datetime(self, value):
        """Format datetime field to string"""
        return value.strftime('%Y-%m-%d') if value and isinstance(value, datetime) else value
    
class CIG(db.Model, SerializerMixin):
    """cig model"""
    __tablename__ = "cigs"

    id = db.Column(db.Integer, primary_key=True)
    hub = db.Column(db.String(255), nullable=False)
    cig_name = db.Column(db.String(255), nullable=False)
    no_of_members = db.Column(db.Integer)
    date_established = db.Column(DateTime)
    constitution = db.Column(db.String(255), nullable=False)
    registration = db.Column(db.String(255), nullable=False)
    elections_held = db.Column(db.String(255), nullable=False)
    date_of_last_elections = db.Column(DateTime)
    meeting_venue = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(255), nullable=False)
    scheduled_meeting_day = db.Column(db.String(255), nullable=False)
    scheduled_meeting_time = db.Column(db.String(255), nullable=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='cigs')

    # One-to-many relationship with Member
    members = db.relationship('Member', back_populates='cig', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict cig model"""
        return {
            "id": self.id,
            "hub": self.hub,
            "cig_name": self.cig_name,
            "no_of_members": self.no_of_members,
            "date_established": self.date_established.strftime('%m/%d/%Y %I:%M %p'),
            "constitution": self.constitution,
            "registration": self.registration,
            "elections_held": self.elections_held,
            "date_of_last_elections": self.date_of_last_elections.strftime('%m/%d/%Y %I:%M %p'),
            "meeting_venue": self.meeting_venue,
            "frequency": self.frequency,
            "scheduled_meeting_day": self.scheduled_meeting_day,
            "scheduled_meeting_time": self.scheduled_meeting_time,
            "user_id": self.user_id,
            "members": [member.to_dict() for member in self.members] 
        }

class Member(db.Model):
    """members model"""
    __tablename__ = 'members'

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    id_number = db.Column(db.Integer)
    product_involved = db.Column(db.String(255), nullable=False)
    hectorage_registered_under_cig = db.Column(db.String(255), nullable=False)

    # Foreign key to CIG table
    cig_id = db.Column(db.Integer, db.ForeignKey('cigs.id'))
    cig = db.relationship('CIG', back_populates='members')

    def to_dict(self):
        """to dict members model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "gender": self.gender,
            "date_of_birth": self.date_of_birth,
            "email": self.email,
            "phone_number": self.phone_number,
            "id_number": self.id_number,
            "product_involved": self.product_involved,
            "hectorage_registered_under_cig": self.hectorage_registered_under_cig,
            "cig_id": self.cig_id,
        }

# Users registration forms tables
    
# Custom Users
class CustomUser(db.Model, SerializerMixin):
    """ hq users model"""
    __tablename__ = "CustomUsers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    staff_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    education_level = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    reporting_to = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='custom_users_registration') 


    def to_dict(self):
        """to dict hq users model"""
        return {
            "id" : self.id,
            "role" : self.role,
            "education_level" : self.education_level,
            "staff_code" : self.staff_code,
            "other_name" : self.other_name,
            "last_name" : self.last_name,
            "id_number" : self.id_number,
            "gender" : self.gender,
            "date_of_birth" : self.date_of_birth.strftime('%Y-%m-%d'),
            "email" : self.email,
            "phone_number" : self.phone_number,
            "reporting_to" : self.reporting_to,
            "user_id": self.user_id
        }

# Hub Users
class HubUser(db.Model, SerializerMixin):
    """hub users model"""
    __tablename__ = "hubUsers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    education_level = db.Column(db.String(255), nullable=False)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='hub_users_registration') 


    def to_dict(self):
        """to dict hub users model"""
        return {
            "id" : self.id,
            "hub" : self.hub,
            "education_level" : self.education_level,
            "code" : self.code,
            "role" : self.role,
            "other_name" : self.other_name,
            "last_name" : self.last_name,
            "id_number" : self.id_number,
            "gender" : self.gender,
            "date_of_birth" : self.date_of_birth,
            "email" : self.email,
            "phone_number" : self.phone_number,
            "buying_center" : self.buying_center,
            "county"  : self.county,
            "sub_county" : self.sub_county,
            "ward" : self.ward,
            "village" : self.village,
            "user_id": self.user_id
        }

# HQ Users
class HQUser(db.Model, SerializerMixin):
    """ hq users model"""
    __tablename__ = "HQUsers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    staff_code = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    education_level = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    reporting_to = db.Column(db.String(255), nullable=False)
    related_roles = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='hq_users_registration') 


    def to_dict(self):
        """to dict hq users model"""
        return {
            "id" : self.id,
            "role" : self.role,
            "education_level" : self.education_level,
            "staff_code" : self.staff_code,
            "department" : self.department,
            "other_name" : self.other_name,
            "last_name" : self.last_name,
            "id_number" : self.id_number,
            "gender" : self.gender,
            "date_of_birth" : self.date_of_birth,
            "email" : self.email,
            "phone_number" : self.phone_number,
            "reporting_to" : self.reporting_to,
            "related_roles"  : self.related_roles,
            "user_id": self.user_id
        }

# Processing Users
class ProcessingUser(db.Model, SerializerMixin):
    """processing user model"""
    __tablename__ = "ProcessingUsers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    processor_code = db.Column(db.String(255), nullable=False)
    processing_plant = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    education_level = db.Column(db.String(255), nullable=False)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='processing_users_registration')

    def to_dict(self):
        """to dict processing users model"""
        return {
            "id" : self.id,
            "hub" : self.hub,
            "education_level" : self.education_level,
            "processor_code" : self.processor_code,
            "processing_plant": self.processing_plant,
            "other_name" : self.other_name,
            "last_name" : self.last_name,
            "id_number" : self.id_number,
            "gender" : self.gender,
            "date_of_birth" : self.date_of_birth.strftime('%Y-%m-%d'),
            "email" : self.email,
            "phone_number" : self.phone_number,
            "buying_center" : self.buying_center,
            "county"  : self.county,
            "sub_county" : self.sub_county,
            "ward" : self.ward,
            "village" : self.village,
            "user_id": self.user_id
        }
    
# Logisitician tables
# Individual logistician
class IndividualLogisticianUser(db.Model, SerializerMixin):
    """Individual logistician model"""
    __tablename__ = "individualLogisticianusers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    logistician_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    address = db.Column(db.String(255), nullable=False)
    hub = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), nullable=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='individual_logistician_registration')

    # One-to-many relationship with Member
    cars = db.relationship('Car', back_populates='individual_logistician', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict individual logistician model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "logistician_code": self.logistician_code,
            "id_number": self.id_number,
            "date_of_birth": self.date_of_birth.strftime('%Y-%m-%d'),
            "email": self.email,
            "phone_number": self.phone_number,
            "address": self.address,
            "hub": self.hub,
            "region": self.region,
            "user_id": self.user_id,
            "cars": [car.to_dict() for car in self.cars]  
        }

# Organisation logistician
class OrganisationLogisticianUser(db.Model, SerializerMixin):
    """organisation logistician model"""
    __tablename__ = "OrganisationLogisticianUsers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    logistician_code = db.Column(db.String(255), nullable=False)
    registration_number = db.Column(db.Integer)
    date_of_registration = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    address = db.Column(db.String(255), nullable=False)
    hub = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), nullable=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='organisation_logistician_registration')

    # One-to-many relationship with Car
    cars = db.relationship('Car', back_populates='organisation_logistician', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict organisation logistician model"""
        return {
            "id": self.id,
            "name": self.name,
            "logistician_code": self.logistician_code,
            "registration_number": self.registration_number,
            "date_of_registration": self.date_of_registration.strftime('%Y-%m-%d'),
            "email": self.email,
            "phone_number": self.phone_number,
            "address": self.address,
            "hub": self.hub,
            "region": self.region,
            "user_id": self.user_id,
            "cars": [car.to_dict() for car in self.cars]  
        }

# Cars to be added by the user logistician
class Car(db.Model):
    """Cars model shared by individual logistician and company logistician"""
    __tablename__ = 'cars'

    id = db.Column(db.Integer, primary_key=True)
    car_body_type = db.Column(db.String(255), nullable=False)
    car_model = db.Column(db.String(255), nullable=False)
    number_plate = db.Column(db.String(255), nullable=False)
    driver1_name = db.Column(db.String(255), nullable=False)
    driver2_name = db.Column(db.String(255), nullable=False)

    # Foreign key to Individual Logistician table
    individual_logistician_id = db.Column(db.Integer, db.ForeignKey('individualLogisticianusers.id'))
    individual_logistician = db.relationship('IndividualLogisticianUser', back_populates='cars')

    # Foreign key to Organisation Logistician table
    organisation_logistician_id = db.Column(db.Integer, db.ForeignKey('OrganisationLogisticianUsers.id'))
    organisation_logistician = db.relationship('OrganisationLogisticianUser', back_populates='cars')


    def to_dict(self):
        """to dict car model"""
        return {
            "id": self.id,
            "car_body_type": self.car_body_type,
            "car_model": self.car_model,
            "number_plate": self.number_plate,
            "driver1_name": self.driver1_name,
            "driver2_name": self.driver2_name,
            "individual_logistician_id": self.individual_logistician_id,
            "organisation_logistician_id": self.organisation_logistician_id,
        }


# Customers tables
# Individual Customer
class IndividualCustomerUser(db.Model, SerializerMixin):
    """Individual customer user"""
    __tablename__ = "individualCustomerusers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    customer_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)
    user_authorised = db.Column(db.Boolean, default=False)
    authorisation_token = db.Column(db.String(255), nullable=True)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='individual_customer_registration') 

    # One-to-many relationship with Product
    products = db.relationship('Product', back_populates='individual_customer', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict individual customer model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "customer_code": self.customer_code,
            "id_number": self.id_number,
            "date_of_birth": self.date_of_birth.strftime('%Y-%m-%d'),
            "email": self.email,
            "phone_number": self.phone_number,
            "county": self.county,
            "sub_county": self.sub_county,
            "ward": self.ward,
            "village": self.village,
            "user_id": self.user_id,
            "user_authorised": self.user_authorised,
            "authorisation_token": self.authorisation_token,
            "products": [product.to_dict() for product in self.products]  
        }

# Organisation customer
class OrganisationCustomerUser(db.Model, SerializerMixin):
    """Organisation customer user"""
    __tablename__ = "OrganisationCustomerusers"

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False)
    customer_code = db.Column(db.String(255), nullable=False)
    registration_number = db.Column(db.Integer)
    sector = db.Column(db.String(255), nullable=False)
    date_of_registration = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)
    # director 1
    other_name1 = db.Column(db.String(255), nullable=False)
    last_name1 = db.Column(db.String(255), nullable=False)
    id_number1 = db.Column(db.Integer)
    gender1 = db.Column(db.String(255), nullable=False)
    date_of_birth1 = db.Column(DateTime)
    email1 = db.Column(db.String(255), nullable=False)
    phone_number1 = db.Column(db.BigInteger)
    # director 2
    other_name2 = db.Column(db.String(255), nullable=False)
    last_name2 = db.Column(db.String(255), nullable=False)
    id_number2 = db.Column(db.Integer)
    gender2 = db.Column(db.String(255), nullable=False)
    date_of_birth2 = db.Column(DateTime)
    email2 = db.Column(db.String(255), nullable=False)
    phone_number2 = db.Column(db.BigInteger)
    # Key contact
    other_name3 = db.Column(db.String(255), nullable=False)
    last_name3 = db.Column(db.String(255), nullable=False)
    id_number3 = db.Column(db.Integer)
    gender3 = db.Column(db.String(255), nullable=False)
    date_of_birth3 = db.Column(DateTime)
    email3 = db.Column(db.String(255), nullable=False)
    phone_number3 = db.Column(db.BigInteger)
    user_authorised = db.Column(db.Boolean, default=False)
    authorisation_token = db.Column(db.String(255), nullable=True)


    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='organisation_customer_registration') 

    # One-to-many relationship with Product
    products = db.relationship('Product', back_populates='organisation_customer', cascade='all, delete-orphan')

    def to_dict(self):
        """to dict organisation customer model"""
        return {
            "id": self.id,
            "company_name": self.company_name,
            "customer_code": self.customer_code,
            "registration_number": self.registration_number,
            "sector": self.sector,
            "date_of_registration": self.date_of_registration.strftime('%Y-%m-%d'),
            "email": self.email,
            "phone_number": self.phone_number,
            "county": self.county,
            "sub_county": self.sub_county,
            "ward": self.ward,
            "village": self.village,
            "other_name1": self.other_name1,
            "last_name1": self.last_name1,
            "id_number1": self.id_number1,
            "gender1": self.gender1,
            "date_of_birth1": self.date_of_birth1.strftime('%Y-%m-%d'),
            "email1": self.email1,
            "phone_number1": self.phone_number1,
            "other_name2": self.other_name2,
            "last_name2": self.last_name2,
            "id_number2": self.id_number2,
            "gender2": self.gender2,
            "date_of_birth2": self.date_of_birth2.strftime('%Y-%m-%d'),
            "email2": self.email2,
            "phone_number2": self.phone_number2,
            "other_name3": self.other_name3,
            "last_name3": self.last_name3,
            "id_number3": self.id_number3,
            "gender3": self.gender3,
            "date_of_birth3": self.date_of_birth3.strftime('%Y-%m-%d'),
            "email3": self.email3,
            "phone_number3": self.phone_number3,
            "user_id": self.user_id,
            "user_authorised": self.user_authorised,
            "authorisation_token": self.authorisation_token,
            "products": [product.to_dict() for product in self.products]  
        }

# Product to be added by the user logistician
class Product(db.Model):
    """Product model shared by both Individual customers and company customers"""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(255), nullable=False)
    products_interested_in = db.Column(db.String(255), nullable=False)
    volume_in_kgs = db.Column(db.String(255), nullable=False)
    packaging = db.Column(db.String(255), nullable=False)
    quality = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(255), nullable=False)

    # Foreign key to Individual Logistician table
    individual_customer_id = db.Column(db.Integer, db.ForeignKey('individualCustomerusers.id'))
    individual_customer = db.relationship('IndividualCustomerUser', back_populates='products')

    # Foreign key to Individual Logistician table
    organisation_customer_id = db.Column(db.Integer, db.ForeignKey('OrganisationCustomerusers.id'))
    organisation_customer = db.relationship('OrganisationCustomerUser', back_populates='products')

    def to_dict(self):
        """to dict company customer model"""
        return {
            "id": self.id,
            "category": self.category,
            "products_interested_in": self.products_interested_in,
            "volume_in_kgs": self.volume_in_kgs,
            "packaging": self.packaging,
            "quality": self.quality,
            "frequency": self.frequency,
            "individual_customer_id": self.individual_customer_id,
            "organisation_customer_id": self.organisation_customer_id,
        }

# Farmers tables
# Farmer's Biodata
class ProducerBiodata(db.Model, SerializerMixin):
    """Farmer Bio-data user table model"""
    __tablename__ = "producersBiodata"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    farmer_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    education_level = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)
    primary_producer = db.Column(db.Text, nullable=False)
    # baseline
    total_land_size = db.Column(db.String(255), nullable=False)
    cultivate_land_size = db.Column(db.String(255), nullable=True)
    homestead_size = db.Column(db.String(255), nullable=False)
    uncultivated_land_size = db.Column(db.String(255), nullable=False)
    farm_accessibility = db.Column(db.String(255), nullable=False)
    number_of_family_workers = db.Column(db.String(255), nullable=False)
    number_of_hired_workers = db.Column(db.String(255), nullable=False)
    access_to_irrigation = db.Column(db.String(255), nullable=False)
    crop_list = db.Column(db.String(255), nullable=False)
    farmer_interest_in_extension = db.Column(db.String(255), nullable=False)
    # main challenges
    knowledge_related = db.Column(db.String(255), nullable=False)
    soil_related = db.Column(db.String(255), nullable=False)
    compost_related = db.Column(db.String(255), nullable=False)
    nutrition_related = db.Column(db.String(255), nullable=False)
    pests_related = db.Column(db.String(255), nullable=False)
    disease_related = db.Column(db.String(255), nullable=False)
    quality_related = db.Column(db.String(255), nullable=False)
    market_related = db.Column(db.String(255), nullable=False)
    food_loss_related = db.Column(db.String(255), nullable=False)
    finance_related = db.Column(db.String(255), nullable=False)
    weather_related = db.Column(db.String(255), nullable=False)
    # livestock
    dairy_cattle = db.Column(db.String(255), nullable=False)
    beef_cattle = db.Column(db.String(255), nullable=False)
    sheep = db.Column(db.String(255), nullable=False)
    poultry = db.Column(db.String(255), nullable=False)
    pigs = db.Column(db.String(255), nullable=False)
    rabbits = db.Column(db.String(255), nullable=False)
    beehives = db.Column(db.String(255), nullable=False)
    donkeys = db.Column(db.String(255), nullable=False)
    goats = db.Column(db.String(255), nullable=False)
    camels = db.Column(db.String(255), nullable=False)
    aquaculture = db.Column(db.String(255), nullable=False)
    # infrastructure
    housing_type = db.Column(db.String(255), nullable=False)
    housing_floor = db.Column(db.String(255), nullable=False)
    housing_roof = db.Column(db.String(255), nullable=False)
    lighting_fuel = db.Column(db.String(255), nullable=False)
    cooking_fuel = db.Column(db.String(255), nullable=False)
    water_filter = db.Column(db.String(255), nullable=False)
    water_tank_greater_than_5000lts = db.Column(db.String(255), nullable=False)
    hand_washing_facilities = db.Column(db.String(255), nullable=False)
    ppes = db.Column(db.String(255), nullable=False)
    water_well_or_weir = db.Column(db.String(255), nullable=False)
    irrigation_pump = db.Column(db.String(255), nullable=False)
    harvesting_equipment = db.Column(db.String(255), nullable=False)
    transportation_type = db.Column(db.String(255), nullable=False)
    toilet_floor = db.Column(db.String(255), nullable=False)
    user_approved = db.Column(db.Boolean, default=False)
    ta = db.Column(db.String(255), default="")

    # Market Produce relationship to the farmer biodata table
    commercialProduces = db.relationship('CommercialProduce', back_populates='producer_biodata', cascade='all, delete-orphan')
    # Domestic Produce relationship to the farmer biodata table
    domesticProduces = db.relationship('DomesticProduce', back_populates='producer_biodata', cascade='all, delete-orphan')
    # one to many relationship to the field registration model
    field_registrations = db.relationship('FarmerFieldRegistration', back_populates='producer_biodata')
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='producer_biodata_registration')

    @property
    def primary_producer_data(self):
        return json.loads(self.primary_producer) if self.primary_producer else None

    @primary_producer_data.setter
    def primary_producer_data(self, value):
        self.primary_producer = json.dumps(value)

    def to_dict(self):
        """to dict producer biodata model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "farmer_code": self.farmer_code,
            "id_number": self.id_number,
            "date_of_birth": self.date_of_birth,
            "email": self.email,
            "phone_number": self.phone_number,
            "hub": self.hub,
            "buying_center": self.buying_center,
            "primary_producer": self.primary_producer_data,
            "gender": self.gender,
            "education_level": self.education_level,
            "county": self.county,
            "sub_county": self.sub_county,
            "ward": self.ward,
            "village": self.village,
            "total_land_size": self.total_land_size,
            "cultivate_land_size": self.cultivate_land_size,
            "homestead_size": self.homestead_size,
            "uncultivated_land_size": self.uncultivated_land_size,
            "farm_accessibility": self.farm_accessibility,
            "number_of_family_workers": self.number_of_family_workers,
            "number_of_hired_workers": self.number_of_hired_workers,
            "farmer_interest_in_extension": self.farmer_interest_in_extension,
            "access_to_irrigation": self.access_to_irrigation,
            "crop_list": self.crop_list,
            "knowledge_related": self.knowledge_related,
            "soil_related": self.soil_related,
            "compost_related": self.compost_related,
            "nutrition_related": self.nutrition_related,
            "pests_related": self.pests_related,
            "disease_related": self.disease_related,
            "quality_related": self.quality_related,
            "market_related": self.market_related,
            "food_loss_related": self.food_loss_related,
            "finance_related": self.finance_related,
            "weather_related": self.weather_related,
            "dairy_cattle": self.dairy_cattle,
            "beef_cattle": self.beef_cattle,
            "sheep": self.sheep,
            "poultry": self.poultry,
            "pigs": self.pigs,
            "rabbits": self.rabbits,
            "beehives": self.beehives,
            "donkeys": self.donkeys,
            "goats": self.goats,
            "aquaculture": self.aquaculture,
            "camels": self.camels,
            "housing_type": self.housing_type,
            "housing_floor": self.housing_floor,
            "housing_roof": self.housing_roof,
            "lighting_fuel": self.lighting_fuel,
            "cooking_fuel": self.cooking_fuel,
            "water_filter": self.water_filter,
            "water_tank_greater_than_5000lts": self.water_tank_greater_than_5000lts,
            "hand_washing_facilities": self.hand_washing_facilities,
            "ppes": self.ppes,
            "water_well_or_weir": self.water_well_or_weir,
            "irrigation_pump": self.irrigation_pump,
            "harvesting_equipment": self.harvesting_equipment,
            "transportation_type": self.transportation_type,
            "toilet_floor": self.toilet_floor,
            "user_id": self.user_id,
            "user_approved": self.user_approved,
            "ta": self.ta,
            "commercialProduces": [product.to_dict() for product in self.commercialProduces],
            "domesticProduces": [product.to_dict() for product in self.domesticProduces]
        }  
    
# Market Produce to be added by the user logistician
class CommercialProduce(db.Model):
    """Commercial produce model added in the farmer biodata"""
    __tablename__ = 'commercialProduces'

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(255), nullable=False)
    product_category = db.Column(db.String(255), nullable=False)
    acerage = db.Column(db.String(255), nullable=False)

    # Foreign key to Individual Logistician table
    producer_biodata_id = db.Column(db.Integer, db.ForeignKey('producersBiodata.id'))
    producer_biodata = db.relationship('ProducerBiodata', back_populates='commercialProduces')

    cig_producer_biodata_id = db.Column(db.Integer, db.ForeignKey('CIGproducersBiodata.id'))
    cig_producer_biodata = db.relationship('CIGProducerBiodata', back_populates='commercialProduces')


    def to_dict(self):
        """to dict market produce model"""
        return {
            "id": self.id,
            "product": self.product,
            "product_category": self.product_category,
            "acerage": self.acerage,
            "producer_biodata_id": self.producer_biodata_id,
        }


# Domestic Produce to be added by the user logistician
class DomesticProduce(db.Model):
    """Domestic produce model added in the farmer biodata"""
    __tablename__ = 'domesticProduces'

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(255), nullable=False)
    product_category = db.Column(db.String(255), nullable=False)
    acerage = db.Column(db.String(255), nullable=False)

    # Foreign key to Individual Logistician table
    producer_biodata_id = db.Column(db.Integer, db.ForeignKey('producersBiodata.id'))
    producer_biodata = db.relationship('ProducerBiodata', back_populates='domesticProduces')

    
    cig_producer_biodata_id = db.Column(db.Integer, db.ForeignKey('CIGproducersBiodata.id'))
    cig_producer_biodata = db.relationship('CIGProducerBiodata', back_populates='domesticProduces')

    def to_dict(self):
        """to dict domestic produce model"""
        return {
            "id": self.id,
            "product": self.product,
            "product_category": self.product_category,
            "acerage": self.acerage,
            "producer_biodata_id": self.producer_biodata_id,
        }

# Farmers field registration
class FarmerFieldRegistration(db.Model, SerializerMixin):
    """farmer field registration"""
    __tablename__ = "farmerfieldregistrations"

    id = db.Column(db.Integer, primary_key=True)
    producer = db.Column(db.String(255), nullable=False)
    field_number = db.Column(db.Integer)
    field_size = db.Column(db.String(255), nullable=False)
    crop1 = db.Column(db.String(255), nullable=False)
    crop_variety1 = db.Column(db.String(255), nullable=False)
    date_planted1 = db.Column(DateTime)
    date_of_harvest1 = db.Column(DateTime)
    population1 = db.Column(db.String(255), nullable=False)
    baseline_yield_last_season1 = db.Column(db.BigInteger)
    baseline_income_last_season1 = db.Column(db.String(255), nullable=False)
    baseline_cost_of_production_last_season1 = db.Column(db.String(255), nullable=False)
    crop2 = db.Column(db.String(255), nullable=False)
    crop_variety2 = db.Column(db.String(255), nullable=False)
    date_planted2 = db.Column(DateTime)
    date_of_harvest2 = db.Column(DateTime)
    population2 = db.Column(db.String(255), nullable=False)
    baseline_yield_last_season2 = db.Column(db.BigInteger)
    baseline_income_last_season2 = db.Column(db.String(255), nullable=False)
    baseline_cost_of_production_last_season2 = db.Column(db.String(255), nullable=False)

    # Many-to-one relationship to ProducerBiodata
    producer_biodata_id = db.Column(db.Integer, db.ForeignKey('producersBiodata.id'), nullable=False)
    producer_biodata = db.relationship('ProducerBiodata', back_populates='field_registrations')

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='farmer_field_registration')

    def to_dict(self):
        """to dict field registration model"""
        return {
            "id": self.id,
            "producer": self.producer,
            "field_number": self.field_number,
            "field_size": self.field_size,
            "crop1": self.crop1,
            "crop_variety1": self.crop_variety1,
            "date_planted1": self.date_planted1.strftime('%Y-%m-%d %H:%M:%S') if self.date_planted1 else None,
            "date_of_harvest1": self.date_of_harvest1.strftime('%Y-%m-%d %H:%M:%S') if self.date_of_harvest1 else None,
            "population1": self.population1,
            "baseline_yield_last_season1": self.baseline_yield_last_season1,
            "baseline_income_last_season1": self.baseline_income_last_season1,
            "baseline_cost_of_production_last_season1": self.baseline_income_last_season1,
            "crop2": self.crop2,
            "crop_variety2": self.crop_variety2,
            "date_planted2": self.date_planted2.strftime('%Y-%m-%d %H:%M:%S') if self.date_planted2 else None,
            "date_of_harvest2": self.date_of_harvest2.strftime('%Y-%m-%d %H:%M:%S') if self.date_of_harvest2 else None,
            "population2": self.population2,
            "baseline_yield_last_season2": self.baseline_yield_last_season2,
            "baseline_income_last_season2": self.baseline_income_last_season2,
            "baseline_cost_of_production_last_season2": self.baseline_income_last_season2,
            "user_id": self.user_id,
            "producer_biodata_id": self.producer_biodata_id
        }
    
# CIG Producer Table Models
class CIGProducerBiodata(db.Model, SerializerMixin):
    """CIG Farmer Bio-data user table model"""
    __tablename__ = "CIGproducersBiodata"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    farmer_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    education_level = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)
    primary_producer = db.Column(db.Text, nullable=False)
    # baseline
    total_land_size = db.Column(db.String(255), nullable=False)
    cultivate_land_size = db.Column(db.String(255), nullable=True)
    homestead_size = db.Column(db.String(255), nullable=False)
    uncultivated_land_size = db.Column(db.String(255), nullable=False)
    farm_accessibility = db.Column(db.String(255), nullable=False)
    number_of_family_workers = db.Column(db.String(255), nullable=False)
    number_of_hired_workers = db.Column(db.String(255), nullable=False)
    access_to_irrigation = db.Column(db.String(255), nullable=False)
    crop_list = db.Column(db.String(255), nullable=False)
    farmer_interest_in_extension = db.Column(db.String(255), nullable=False)
    # main challenges
    knowledge_related = db.Column(db.String(255), nullable=False)
    soil_related = db.Column(db.String(255), nullable=False)
    compost_related = db.Column(db.String(255), nullable=False)
    nutrition_related = db.Column(db.String(255), nullable=False)
    pests_related = db.Column(db.String(255), nullable=False)
    disease_related = db.Column(db.String(255), nullable=False)
    quality_related = db.Column(db.String(255), nullable=False)
    market_related = db.Column(db.String(255), nullable=False)
    food_loss_related = db.Column(db.String(255), nullable=False)
    finance_related = db.Column(db.String(255), nullable=False)
    weather_related = db.Column(db.String(255), nullable=False)
    # livestock
    dairy_cattle = db.Column(db.String(255), nullable=False)
    beef_cattle = db.Column(db.String(255), nullable=False)
    sheep = db.Column(db.String(255), nullable=False)
    poultry = db.Column(db.String(255), nullable=False)
    pigs = db.Column(db.String(255), nullable=False)
    rabbits = db.Column(db.String(255), nullable=False)
    beehives = db.Column(db.String(255), nullable=False)
    donkeys = db.Column(db.String(255), nullable=False)
    goats = db.Column(db.String(255), nullable=False)
    camels = db.Column(db.String(255), nullable=False)
    aquaculture = db.Column(db.String(255), nullable=False)
    # infrastructure
    housing_type = db.Column(db.String(255), nullable=False)
    housing_floor = db.Column(db.String(255), nullable=False)
    housing_roof = db.Column(db.String(255), nullable=False)
    lighting_fuel = db.Column(db.String(255), nullable=False)
    cooking_fuel = db.Column(db.String(255), nullable=False)
    water_filter = db.Column(db.String(255), nullable=False)
    water_tank_greater_than_5000lts = db.Column(db.String(255), nullable=False)
    hand_washing_facilities = db.Column(db.String(255), nullable=False)
    ppes = db.Column(db.String(255), nullable=False)
    water_well_or_weir = db.Column(db.String(255), nullable=False)
    irrigation_pump = db.Column(db.String(255), nullable=False)
    harvesting_equipment = db.Column(db.String(255), nullable=False)
    transportation_type = db.Column(db.String(255), nullable=False)
    toilet_floor = db.Column(db.String(255), nullable=False)
    user_approved=db.Column(db.Boolean, default=False)

    # Producer relationship to the farmer biodata table
    commercialProduces = db.relationship('CommercialProduce', back_populates='cig_producer_biodata', cascade='all, delete-orphan')
    # Domestic Produce relationship to the farmer biodata table
    domesticProduces = db.relationship('DomesticProduce', back_populates='cig_producer_biodata', cascade='all, delete-orphan')
    # one to many relationship to the field registration model
    cig_field_registrations = db.relationship('CIGFarmerFieldRegistration', back_populates='cig_producer_biodata')
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='cig_producer_biodata_registration')

    @property
    def primary_producer_data(self):
        return json.loads(self.primary_producer) if self.primary_producer else None

    @primary_producer_data.setter
    def primary_producer_data(self, value):
        self.primary_producer = json.dumps(value)

    def to_dict(self):
        """to dict cig farmer biodata model"""
        return {
            "id": self.id,
            "other_name": self.other_name,
            "last_name": self.last_name,
            "farmer_code": self.farmer_code,
            "id_number": self.id_number,
            "date_of_birth": self.date_of_birth.strftime('%Y-%m-%d'),
            "email": self.email,
            "phone_number": self.phone_number,
            "hub": self.hub,
            "buying_center": self.buying_center,
            "primary_producer": self.primary_producer_data,
            "gender": self.gender,
            "education_level": self.education_level,
            "county": self.county,
            "sub_county": self.sub_county,
            "ward": self.ward,
            "village": self.village,
            "total_land_size": self.total_land_size,
            "cultivate_land_size": self.cultivate_land_size,
            "homestead_size": self.homestead_size,
            "uncultivated_land_size": self.uncultivated_land_size,
            "farm_accessibility": self.farm_accessibility,
            "number_of_family_workers": self.number_of_family_workers,
            "number_of_hired_workers": self.number_of_hired_workers,
            "farmer_interest_in_extension": self.farmer_interest_in_extension,
            "access_to_irrigation": self.access_to_irrigation,
            "crop_list": self.crop_list,
            "knowledge_related": self.knowledge_related,
            "soil_related": self.soil_related,
            "compost_related": self.compost_related,
            "nutrition_related": self.nutrition_related,
            "pests_related": self.pests_related,
            "disease_related": self.disease_related,
            "quality_related": self.quality_related,
            "market_related": self.market_related,
            "food_loss_related": self.food_loss_related,
            "finance_related": self.finance_related,
            "weather_related": self.weather_related,
            "dairy_cattle": self.dairy_cattle,
            "beef_cattle": self.beef_cattle,
            "sheep": self.sheep,
            "poultry": self.poultry,
            "pigs": self.pigs,
            "rabbits": self.rabbits,
            "beehives": self.beehives,
            "donkeys": self.donkeys,
            "goats": self.goats,
            "aquaculture": self.aquaculture,
            "camels": self.camels,
            "housing_type": self.housing_type,
            "housing_floor": self.housing_floor,
            "housing_roof": self.housing_roof,
            "lighting_fuel": self.lighting_fuel,
            "cooking_fuel": self.cooking_fuel,
            "water_filter": self.water_filter,
            "water_tank_greater_than_5000lts": self.water_tank_greater_than_5000lts,
            "hand_washing_facilities": self.hand_washing_facilities,
            "ppes": self.ppes,
            "water_well_or_weir": self.water_well_or_weir,
            "irrigation_pump": self.irrigation_pump,
            "harvesting_equipment": self.harvesting_equipment,
            "transportation_type": self.transportation_type,
            "toilet_floor": self.toilet_floor,
            "user_id": self.user_id,
            "user_approved": self.user_approved,
            "commercialProduces": [product.to_dict() for product in self.commercialProduces],
            "domesticProduces": [product.to_dict() for product in self.domesticProduces]
        }

# Farmers field registration
class CIGFarmerFieldRegistration(db.Model, SerializerMixin):
    """CIG farmer field registration"""
    __tablename__ = "CIGfarmerfieldregistrations"

    id = db.Column(db.Integer, primary_key=True)
    producer = db.Column(db.String(255), nullable=False)
    field_number = db.Column(db.Integer)
    field_size = db.Column(db.String(255), nullable=False)
    crop1 = db.Column(db.String(255), nullable=False)
    crop_variety1 = db.Column(db.String(255), nullable=False)
    date_planted1 = db.Column(DateTime)
    date_of_harvest1 = db.Column(DateTime)
    population1 = db.Column(db.String(255), nullable=False)
    baseline_yield_last_season1 = db.Column(db.BigInteger)
    baseline_income_last_season1 = db.Column(db.String(255), nullable=False)
    baseline_cost_of_production_last_season1 = db.Column(db.String(255), nullable=False)
    crop2 = db.Column(db.String(255), nullable=False)
    crop_variety2 = db.Column(db.String(255), nullable=False)
    date_planted2 = db.Column(DateTime)
    date_of_harvest2 = db.Column(DateTime)
    population2 = db.Column(db.String(255), nullable=False)
    baseline_yield_last_season2 = db.Column(db.BigInteger)
    baseline_income_last_season2 = db.Column(db.String(255), nullable=False)
    baseline_cost_of_production_last_season2 = db.Column(db.String(255), nullable=False)

    # Many-to-one relationship to CIGProducerBiodata
    cig_producer_biodata_id = db.Column(db.Integer, db.ForeignKey('CIGproducersBiodata.id'), nullable=False)
    cig_producer_biodata = db.relationship('CIGProducerBiodata', back_populates='cig_field_registrations')

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='cig_farmer_field_registration')
    

    def to_dict(self):
        """to dict field registration model"""
        return {
            "id": self.id,
            "producer": self.producer,
            "field_number": self.field_number,
            "field_size": self.field_size,
            "crop1": self.crop1,
            "crop_variety1": self.crop_variety1,
            "date_planted1": self.date_planted1.strftime('%Y-%m-%d %H:%M:%S') if self.date_planted1 else None,
            "date_of_harvest1": self.date_of_harvest1.strftime('%Y-%m-%d %H:%M:%S') if self.date_of_harvest1 else None,
            "population1": self.population1,
            "baseline_yield_last_season1": self.baseline_yield_last_season1,
            "baseline_income_last_season1": self.baseline_income_last_season1,
            "baseline_cost_of_production_last_season1": self.baseline_income_last_season1,
            "crop2": self.crop2,
            "crop_variety2": self.crop_variety2,
            "date_planted2": self.date_planted2.strftime('%Y-%m-%d %H:%M:%S') if self.date_planted2 else None,
            "date_of_harvest2": self.date_of_harvest2.strftime('%Y-%m-%d %H:%M:%S') if self.date_of_harvest2 else None,
            "population2": self.population2,
            "baseline_yield_last_season2": self.baseline_yield_last_season2,
            "baseline_income_last_season2": self.baseline_income_last_season2,
            "baseline_cost_of_production_last_season2": self.baseline_income_last_season2,
            "user_id": self.user_id,
            "producer_biodata_id": self.cig_producer_biodata_id
        }

# Seasons Planning
class SeasonPlanning(db.Model, SerializerMixin):
    """Season Planning user table model"""
    __tablename__ = "seasonsPlanning"

    id = Column(db.Integer, primary_key=True)
    producer = Column(String(255), nullable=False)
    field = Column(String(255), nullable=False)
    planned_date_of_planting = Column(DateTime)
    week_number = Column(db.Integer)
    # Plan crop management
    nursery = Column(db.Text, nullable=False)
    gapping = Column(db.Text, nullable=False)
    soil_analysis = Column(db.Text, nullable=False)
    liming = Column(db.Text, nullable=False)
    transplanting = Column(db.Text, nullable=False)
    weeding = Column(db.Text, nullable=False)
    prunning_thinning_desuckering = Column(db.Text, nullable=False)
    mulching = Column(db.Text, nullable=False)
    harvesting = Column(db.Text, nullable=False)
    # Plan nutrition
    plan_nutritions = relationship('PlanNutrition', back_populates='season_planning', cascade='all, delete-orphan')
    # Scouting station
    scouting_stations = relationship('ScoutingStation', back_populates='season_planning', cascade='all, delete-orphan')
    # Plan disease
    preventative_diseases = relationship('PreventativeDisease', back_populates='season_planning', cascade='all, delete-orphan')
    # Plant pest
    preventative_pests = relationship('PreventativePest', back_populates='season_planning', cascade='all, delete-orphan')
    # Plan irrigation
    plan_irrigations = relationship('PlanIrrigation', back_populates='season_planning', cascade='all, delete-orphan')

    marketProduces = relationship('MarketProduce', back_populates='season_planning', cascade='all, delete-orphan')
    
    # Foreign key to User table
    user_id = Column(String(36), db.ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='season_planning') # one to many table relationship to the user table

    @property
    def nursery_data(self):
        return json.loads(self.nursery) if self.nursery else None

    @nursery_data.setter
    def nursery_data(self, value):
        self.nursery = json.dumps(value)

    @property
    def gapping_data(self):
        return json.loads(self.gapping) if self.gapping else None

    @gapping_data.setter
    def gapping_data(self, value):
        self.gapping = json.dumps(value)

    @property
    def soil_analysis_data(self):
        return json.loads(self.soil_analysis) if self.soil_analysis else None

    @soil_analysis_data.setter
    def soil_analysis_data(self, value):
        self.soil_analysis = json.dumps(value)

    @property
    def liming_data(self):
        return json.loads(self.liming) if self.liming else None

    @liming_data.setter
    def liming_data(self, value):
        self.liming = json.dumps(value)

    @property
    def transplanting_data(self):
        return json.loads(self.transplanting) if self.transplanting else None

    @transplanting_data.setter
    def transplanting_data(self, value):
        self.transplanting = json.dumps(value)

    @property
    def weeding_data(self):
        return json.loads(self.weeding) if self.weeding else None

    @weeding_data.setter
    def weeding_data(self, value):
        self.weeding = json.dumps(value)

    @property
    def prunning_thinning_desuckering_data(self):
        return json.loads(self.prunning_thinning_desuckering) if self.prunning_thinning_desuckering else None

    @prunning_thinning_desuckering_data.setter
    def prunning_thinning_desuckering_data(self, value):
        self.prunning_thinning_desuckering = json.dumps(value)

    @property
    def mulching_data(self):
        return json.loads(self.mulching) if self.mulching else None

    @mulching_data.setter
    def mulching_data(self, value):
        self.mulching = json.dumps(value)

    @property
    def harvesting_data(self):
        return json.loads(self.harvesting) if self.harvesting else None

    @harvesting_data.setter
    def harvesting_data(self, value):
        self.harvesting = json.dumps(value)

    def to_dict(self):
        """to dict season planning model"""
        return {
            "id": self.id,
            "producer": self.producer,
            "field": self.field,
            "planned_date_of_planting": self.planned_date_of_planting.strftime('%Y-%m-%d') if self.planned_date_of_planting else None,
            "week_number": self.week_number,
            # Plan crop management
            "nursery": self.nursery_data,
            "gapping": self.gapping_data,
            "soil_analysis": self.soil_analysis_data,
            "liming": self.liming_data,
            "transplanting": self.transplanting_data,
            "weeding": self.weeding_data,
            "prunning_thinning_desuckering": self.prunning_thinning_desuckering_data,
            "mulching": self.mulching_data,
            "harvesting": self.harvesting_data,
            # Plan nutrition
            "plan_nutritions": [plan_nutrition.to_dict() for plan_nutrition in self.plan_nutritions],
            # Diseases
            "preventative_diseases": [preventative_disease.to_dict() for preventative_disease in self.preventative_diseases],
            # Pests
            "preventative_pests": [preventative_pest.to_dict() for preventative_pest in self.preventative_pests],
            # Plan irrigation
            "plan_irrigations": [plan_irrigation.to_dict() for plan_irrigation in self.plan_irrigations],
            # Scouting station
            "scouting_stations": [scouting_station.to_dict() for scouting_station in self.scouting_stations],
            # market produces
            "marketProduces": [marketProduce.to_dict() for marketProduce in self.marketProduces],
            "user_id": self.user_id, 
        }
    
class MarketProduce(db.Model, SerializerMixin):
    """Market produce model added in the farmer biodata"""
    __tablename__ = 'marketProduces'

    id = Column(db.Integer, primary_key=True)
    product = Column(String(255), nullable=False)
    product_category = Column(String(255), nullable=False)
    acerage = Column(String(255), nullable=False)

    # Foreign key
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='marketProduces')

    # Assuming ExtensionService is defined somewhere else in your code
    extension_service_id = Column(db.Integer, db.ForeignKey('extensionServices.id'))
    extension_service = relationship('ExtensionService', back_populates='marketProduces')

    # Relationship to the farmer price distribution model
    farmer_price_distribution = relationship('FarmerPriceDistribution', uselist=False, back_populates='produce')
    # Relationship to the customer price distribution model
    customer_price_distribution = relationship('CustomerPriceDistribution', uselist=False, back_populates='produce')

    def to_dict(self):
        """to dict market produce model"""
        return {
            "id": self.id,
            "product": self.product,
            "product_category": self.product_category,
            "acerage": self.acerage,
            "season_planning_id": self.season_planning_id,
        } 

class PlanNutrition(db.Model, SerializerMixin):
    """Plan nutrition model to be added to the table season registrations"""
    __tablename__ = 'planNutritions'

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(255), nullable=False)
    product_name = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    application_rate = db.Column(db.String(255), nullable=True)
    time_of_application = db.Column(db.String(255), nullable=True)
    method_of_application = db.Column(db.String(255), nullable=True)
    product_formulation = db.Column(db.String(255), nullable=False)
    date_of_application = db.Column(DateTime)
    total_mixing_ratio = db.Column(db.String(255), nullable=False)
    # Foreign key to Season Planning table
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='plan_nutritions')

    def to_dict(self):
        """to dict plan nutrition model"""
        return {
            "id": self.id,
            "product": self.product,
            "product_name": self.product_name,
            "unit": self.unit,
            "cost_per_unit": self.cost_per_unit,
            "application_rate": self.application_rate,
            "time_of_application": self.time_of_application,
            "method_of_application": self.method_of_application,
            "product_formulation": self.product_formulation,
            "date_of_application": self.date_of_application.strftime('%Y-%m-%d') if self.date_of_application else None,
            "total_mixing_ratio": self.total_mixing_ratio,
            "season_planning_id": self.season_planning_id,
        }

class ScoutingStation(db.Model, SerializerMixin):
    """Scouting Station model to be added to the table season planning"""
    __tablename__ = 'scoutingStations'

    id = db.Column(db.Integer, primary_key=True)
    bait_station = db.Column(db.String(255), nullable=False)
    type_of_bait_provided = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(255), nullable=True)

    # Foreign key to Season Planning table
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='scouting_stations')

    def to_dict(self):
        """to dict scout station model"""
        return {
            "id": self.id,
            "bait_station": self.bait_station,
            "type_of_bait_provided": self.type_of_bait_provided,
            "frequency": self.frequency,
            "season_planning_id": self.season_planning_id,
        }

class PreventativeDisease(db.Model, SerializerMixin):
    """Preventative disease model to be added to the table season registrations"""
    __tablename__ = 'preventativeDiseases'

    id = db.Column(db.Integer, primary_key=True)
    disease = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    formulation = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    volume_of_water = db.Column(db.String(255), nullable=False)
    frequency_of_application = db.Column(db.String(255), nullable=False)
    total_cost = db.Column(db.String(255), nullable=False)

    # Foreign key to Season Planning table
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='preventative_diseases')

    def to_dict(self):
        """to dict disease management model"""
        return {
            "id": self.id,
            "disease": self.disease,
            "product": self.product,
            "category": self.category,
            "formulation": self.formulation,
            "dosage": self.dosage,
            "unit": self.unit,
            "cost_per_unit": self.cost_per_unit,
            "volume_of_water": self.volume_of_water,
            "frequency_of_application": self.frequency_of_application,
            "total_cost": self.total_cost,
            "season_planning_id": self.season_planning_id,
        }

class PreventativePest(db.Model, SerializerMixin):
    """Preventative pest model to be added to the table season registrations"""
    __tablename__ = 'preventativePests'

    id = db.Column(db.Integer, primary_key=True)
    pest = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    formulation = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    volume_of_water = db.Column(db.String(255), nullable=False)
    frequency_of_application = db.Column(db.String(255), nullable=False)
    total_cost = db.Column(db.String(255), nullable=False)

    # Foreign key to Season Planning table
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='preventative_pests')

    def to_dict(self):
        """to dict pest management model"""
        return {
            "id": self.id,
            "pest": self.pest,
            "product": self.product,
            "category": self.category,
            "formulation": self.formulation,
            "dosage": self.dosage,
            "unit": self.unit,
            "cost_per_unit": self.cost_per_unit,
            "volume_of_water": self.volume_of_water,
            "frequency_of_application": self.frequency_of_application,
            "total_cost": self.total_cost,
            "season_planning_id": self.season_planning_id,
        }

class PlanIrrigation(db.Model, SerializerMixin):
    """Plan irrigation model to be added to the table season registrations"""
    __tablename__ = 'planIrrigations'

    id = db.Column(db.Integer, primary_key=True)
    type_of_irrigation = db.Column(db.String(255), nullable=False)
    discharge_hours = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(255), nullable=False)
    cost_of_fuel = db.Column(db.String(255), nullable=False)
    unit_cost = db.Column(db.String(255), nullable=False)

    # Foreign key to Season Planning table
    season_planning_id = db.Column(db.Integer, db.ForeignKey('seasonsPlanning.id'))
    season_planning = db.relationship('SeasonPlanning', back_populates='plan_irrigations')

    def to_dict(self):
        """to dict irrigation model"""
        return {
            "id": self.id,
            "type_of_irrigation": self.type_of_irrigation,
            "discharge_hours": self.discharge_hours,
            "unit_cost": self.unit_cost,
            "frequency": self.frequency,
            "cost_of_fuel": self.cost_of_fuel,
            "season_planning_id": self.season_planning_id,
        } 

# Extension services table models
class ExtensionService(db.Model, SerializerMixin):
    """Extension Service user table model"""
    __tablename__ = "extensionServices"
    # Provide Extension
    id = db.Column(db.Integer, primary_key=True)
    producer = db.Column(db.String(255), nullable=False)
    field = db.Column(db.String(255), nullable=False)
    planned_date_of_planting = db.Column(DateTime)
    week_number = db.Column(db.Integer)
    # plan crop management
    nursery = Column(db.Text, nullable=False)
    gapping = Column(db.Text, nullable=False)
    soil_analysis = Column(db.Text, nullable=False)
    liming = Column(db.Text, nullable=False)
    transplanting = Column(db.Text, nullable=False)
    weeding = Column(db.Text, nullable=False)
    prunning_thinning_desuckering = Column(db.Text, nullable=False)
    mulching = Column(db.Text, nullable=False)
    harvesting = Column(db.Text, nullable=False)
    # register scouting station
    ext_scouting_stations = db.relationship('ExtScoutingStation', back_populates='extension_service_registration', cascade='all, delete-orphan') # One-to-many relationship with pest outbreaks
    # register pesticides used
    pesticides_used = db.relationship('PesticideUsed', back_populates='extension_service_registration', cascade='all, delete-orphan')
    # register fertilizers/compost used
    fertlizers_used = db.relationship('FertilizerUsed', back_populates='extension_service_registration', cascade='all, delete-orphan')
    # register labor
    forecast_yields = db.relationship('ForecastYield', back_populates='extension_service_registration', cascade='all, delete-orphan')

    marketProduces = db.relationship('MarketProduce', back_populates='extension_service', cascade='all, delete-orphan')
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='extension_service_registration')

    @property
    def nursery_data(self):
        return json.loads(self.nursery) if self.nursery else None

    @nursery_data.setter
    def nursery_data(self, value):
        self.nursery = json.dumps(value)

    @property
    def gapping_data(self):
        return json.loads(self.gapping) if self.gapping else None

    @gapping_data.setter
    def gapping_data(self, value):
        self.gapping = json.dumps(value)

    @property
    def soil_analysis_data(self):
        return json.loads(self.soil_analysis) if self.soil_analysis else None

    @soil_analysis_data.setter
    def soil_analysis_data(self, value):
        self.soil_analysis = json.dumps(value)

    @property
    def liming_data(self):
        return json.loads(self.liming) if self.liming else None

    @liming_data.setter
    def liming_data(self, value):
        self.liming = json.dumps(value)

    @property
    def transplanting_data(self):
        return json.loads(self.transplanting) if self.transplanting else None

    @transplanting_data.setter
    def transplanting_data(self, value):
        self.transplanting = json.dumps(value)

    @property
    def weeding_data(self):
        return json.loads(self.weeding) if self.weeding else None

    @weeding_data.setter
    def weeding_data(self, value):
        self.weeding = json.dumps(value)

    @property
    def prunning_thinning_desuckering_data(self):
        return json.loads(self.prunning_thinning_desuckering) if self.prunning_thinning_desuckering else None

    @prunning_thinning_desuckering_data.setter
    def prunning_thinning_desuckering_data(self, value):
        self.prunning_thinning_desuckering = json.dumps(value)

    @property
    def mulching_data(self):
        return json.loads(self.mulching) if self.mulching else None

    @mulching_data.setter
    def mulching_data(self, value):
        self.mulching = json.dumps(value)

    @property
    def harvesting_data(self):
        return json.loads(self.harvesting) if self.harvesting else None

    @harvesting_data.setter
    def harvesting_data(self, value):
        self.harvesting = json.dumps(value)

    def to_dict(self):
        """to dict season planning model"""
        return {
            "id": self.id,
            "producer": self.producer,
            "field": self.field,
            "planned_date_of_planting": self.planned_date_of_planting.strftime('%Y-%m-%d') if self.planned_date_of_planting else None,
            "week_number": self.week_number,
            # Plan crop management
            "nursery": self.nursery_data,
            "gapping": self.gapping_data,
            "soil_analysis": self.soil_analysis_data,
            "liming": self.liming_data,
            "transplanting": self.transplanting_data,
            "weeding": self.weeding_data,
            "prunning_thinning_desuckering": self.prunning_thinning_desuckering_data,
            "mulching": self.mulching_data,
            "harvesting": self.harvesting_data,
            # scouting station
            "ext_scouting_stations": [ext_scouting_station.to_dict() for ext_scouting_station in self.ext_scouting_stations],
            # pesticide used
            "pesticides_used": [pesticide_used.to_dict() for pesticide_used in self.pesticides_used],
            # fertilizer used
            "fertlizers_used": [fertlizer_used.to_dict() for fertlizer_used in self.fertlizers_used],
            # register forecast yields
            "forecast_yields": [forecast_yield.to_dict() for forecast_yield in self.forecast_yields],
            "marketProduces": [marketProduce.to_dict() for marketProduce in self.marketProduces],
            "user_id": self.user_id, 
        }
    

# Register Pest Outbreak table
class ExtScoutingStation(db.Model):
    """Scouting Station model to be added to the table extension service registrations"""
    __tablename__ = 'extScoutingStations'

    id = db.Column(db.Integer, primary_key=True)
    scouting_method = db.Column(db.String(255), nullable=False)
    bait_station = db.Column(db.String(255), nullable=False)
    pest_or_disease = db.Column(db.String(255), nullable=False)
    management = db.Column(db.String(255), nullable=False)

    # Foreign key to Extension Service table
    extension_service_registration_id = db.Column(db.Integer, db.ForeignKey('extensionServices.id'))
    extension_service_registration = db.relationship('ExtensionService', back_populates='ext_scouting_stations')

    def to_dict(self):
        """to dict scouting stations model"""
        return {
            "id": self.id,
            "scouting_method": self.scouting_method,
            "bait_station": self.bait_station,
            "pest_or_disease": self.pest_or_disease,
            "management": self.management,
            "extension_service_id": self.extension_service_registration_id,
        }

# Register pesticide used
class PesticideUsed(db.Model):
    """Pesticide used model to be added to the table extension service registrations"""
    __tablename__ = 'pesticidesUsed'

    id = db.Column(db.Integer, primary_key=True)
    register = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    formulation = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    volume_of_water = db.Column(db.String(255), nullable=False)
    frequency_of_application = db.Column(db.String(255), nullable=False)
    total_cost = db.Column(db.String(255), nullable=False)

    # Foreign key to Ext Services table
    extension_service_registration_id = db.Column(db.Integer, db.ForeignKey('extensionServices.id'))
    extension_service_registration = db.relationship('ExtensionService', back_populates='pesticides_used')

    def to_dict(self):
        """to dict pesticide used model"""
        return {
            "id": self.id,
            "register": self.register,
            "product": self.product,
            "category": self.category,
            "formulation": self.formulation,
            "dosage": self.dosage,
            "unit": self.unit,
            "cost_per_unit": self.cost_per_unit,
            "volume_of_water": self.volume_of_water,
            "frequency_of_application": self.frequency_of_application,
            "total_cost": self.total_cost,
            "extension_service_id": self.extension_service_registration_id,
        }
# Register fertilizer/compost used
class FertilizerUsed(db.Model):
    """Fertilizer used model to be added to the table extension service registrations"""
    __tablename__ = 'fertilizersUsed'

    id = db.Column(db.Integer, primary_key=True)
    register = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    formulation = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    volume_of_water = db.Column(db.String(255), nullable=False)
    frequency_of_application = db.Column(db.String(255), nullable=False)
    total_cost = db.Column(db.String(255), nullable=False)

    # Foreign key to Ext Service table
    extension_service_registration_id = db.Column(db.Integer, db.ForeignKey('extensionServices.id'))
    extension_service_registration = db.relationship('ExtensionService', back_populates='fertlizers_used')

    def to_dict(self):
        """to dict fertilizer used model"""
        return {
            "id": self.id,
            "register": self.register,
            "product": self.product,
            "category": self.category,
            "formulation": self.formulation,
            "dosage": self.dosage,
            "unit": self.unit,
            "cost_per_unit": self.cost_per_unit,
            "volume_of_water": self.volume_of_water,
            "frequency_of_application": self.frequency_of_application,
            "total_cost": self.total_cost,
            "extension_service_id": self.extension_service_registration_id,
        }
# Register Forecast Yield
class ForecastYield(db.Model):
    """Forecast Yield model to be added to the table extension service registrations"""
    __tablename__ = 'forecastYields'

    id = db.Column(db.Integer, primary_key=True)
    crop_population_pc = db.Column(db.String(255), nullable=False)
    yield_forecast_pc = db.Column(db.String(255), nullable=False)
    forecast_quality = db.Column(db.String(255), nullable=True)
    ta_comments = db.Column(db.String(255), nullable=False)

    # Foreign key to Extension Services table
    extension_service_registration_id = db.Column(db.Integer, db.ForeignKey('extensionServices.id'))
    extension_service_registration = db.relationship('ExtensionService', back_populates='forecast_yields')

    def to_dict(self):
        """to dict forecast yield model"""
        return {
            "id": self.id,
            "crop_population_pc": self.crop_population_pc,
            "yield_forecast_pc": self.yield_forecast_pc,
            "forecast_quality": self.forecast_quality,
            "ta_comments": self.ta_comments,
            "extension_service_id": self.extension_service_registration_id,
        }
    
# Training table
class Training(db.Model, SerializerMixin):
    """Training model"""
    __tablename__ = "trainings"

    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(255), nullable=False)
    trainer_name = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    course_description = db.Column(db.String(255), nullable=False)
    date_of_training = db.Column(db.String(255), nullable=False)
    content_of_training = db.Column(db.String(255), nullable=False)
    venue = db.Column(db.String(255), nullable=False)
    participants = db.Column(db.Text, nullable=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='training_registration')

    @property
    def participants_data(self):
        return json.loads(self.participants) if self.participants else None

    @participants_data.setter
    def participants_data(self, value):
        self.participants = json.dumps(value)

    def to_dict(self):
        """to dict training model"""
        return {
            "id": self.id,
            "course_name": self.course_name,
            "trainer_name": self.trainer_name,
            "date_of_training": self.date_of_training,
            "content_of_training": self.content_of_training,
            "venue": self.venue,
            "buying_center": self.buying_center,
            "participants": self.participants_data,
            "course_description": self.course_description,
            "user_id": self.user_id,
        }
    
# Attendance Model 
class Attendance(db.Model, SerializerMixin):
    """Attendance  model"""
    __tablename__ = "attendances"

    id = db.Column(db.Integer, primary_key=True)
    attendance = db.Column(db.String(255), nullable=False)
    training_id = db.Column(db.String(255), nullable=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='attendance_registration')

    def to_dict(self):
        """to dict attendance model"""
        return {
            "id": self.id,
            "attendance": self.attendance,
            "training_id": self.training_id,
            "user_id": self.user_id,
        }
    
    
# Farmer Price distribution table
class FarmerPriceDistribution(db.Model, SerializerMixin):
    """Farmer Price distribution model"""
    __tablename__ = "farmerPriceDistributions"

    id = db.Column(db.Integer, primary_key=True)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    online_price = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    date = db.Column(DateTime)
    comments = db.Column(db.String(255), nullable=False)

    # boolean to check if the product is already sold
    sold = db.Column(db.Boolean, default=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='farmer_price_distribution_registration')  # one to one table relationship to the user table

    # Foreign key to the marketProduces table model
    produce_id = db.Column(db.Integer, db.ForeignKey('marketProduces.id'), nullable=False)
    produce = db.relationship('MarketProduce', uselist=False, back_populates='farmer_price_distribution')

    def to_dict(self):
        """to dict farmer price distribution model"""
        return {
            "id": self.id,
            "produce_id": self.produce_id,
            "online_price": self.online_price,
            "hub": self.hub,
            "buying_center": self.buying_center,
            "unit": self.unit,
            "date": self.date.strftime('%Y-%m-%d'),
            "comments": self.comments,
            "sold": self.sold,
            "user_id": self.user_id,
        }
    
# Customer Price distribution table
class CustomerPriceDistribution(db.Model, SerializerMixin):
    """Customer Price distribution model"""
    __tablename__ = "customerPriceDistributions"

    id = db.Column(db.Integer, primary_key=True)
    hub = db.Column(db.String(255), nullable=False)
    buying_center = db.Column(db.String(255), nullable=False)
    online_price = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    date = db.Column(DateTime)
    comments = db.Column(db.String(255), nullable=False)

    # boolean to check if the product is already sold
    sold = db.Column(db.Boolean, default=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='customer_price_distribution_registration')  # one to one table relationship to the user table

     # Foreign key to the marketProduces table model
    produce_id = db.Column(db.Integer, db.ForeignKey('marketProduces.id'), nullable=False)
    produce = db.relationship('MarketProduce', uselist=False, back_populates='customer_price_distribution')

    def to_dict(self):
        """to dict customer price distribution model"""
        return {
            "id": self.id,
            "produce_id": self.produce_id,
            "online_price": self.online_price,
            "hub": self.hub,
            "buying_center": self.buying_center,
            "unit": self.unit,
            "date": self.date.strftime('%Y-%m-%d'),
            "comments": self.comments,
            "sold": self.sold,
            "user_id": self.user_id,
        }
    
# Buying Farmer table model
class BuyingFarmer(db.Model, SerializerMixin):
    """Buying farmer model"""
    __tablename__ = "buyingFarmers"

    id = db.Column(db.Integer, primary_key=True)
    buying_center = db.Column(db.String(255), nullable=False)
    producer = db.Column(db.String(255), nullable=False)
    produce = db.Column(db.String(255), nullable=False)
    # Farmer buying details
    grn_number = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    quality = db.Column(db.Text, nullable=False)
    action = db.Column(db.String(255), nullable=False)
    weight = db.Column(db.String(255), nullable=False)
    
    # grn loaded status
    loaded = db.Column(db.Boolean, default=False, nullable=False)
    
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='buying_farmer_registration')
    
    # Define one-to-one relationship with Quarantine table
    quarantines = db.relationship('Quarantine', back_populates='buying_farmer', cascade='all, delete-orphan')
    
    @property
    def quality_data(self):
        return json.loads(self.quality) if self.quality else None

    @quality_data.setter
    def quality_data(self, value):
        self.quality = json.dumps(value)

    def to_dict(self):
        """to dict buying farmer model"""
        return {
            "id": self.id,
            "buying_center": self.buying_center,
            "producer": self.producer,
            "produce": self.produce,
            "unit": self.unit,
            "quality": self.quality_data,
            "action": self.action,
            "weight": self.weight,
            "grn_number": self.grn_number,
            "loaded": self.loaded,
            "user_id": self.user_id,
        }
    
class Quarantine(db.Model, SerializerMixin):
    """Quarantine model"""
    __tablename__ = "quarantines"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    quarantine_approved_by = db.Column(db.String(255), nullable=False)
    new_weight_in_after_sorting_or_regrading = db.Column(db.String(255), nullable=False)
    new_weight_out_after_sorting_or_regrading = db.Column(db.String(255), nullable=False)

    # Define foreign keys for relationships with BuyingFarmer and BuyingCustomer
    buying_farmer_id = db.Column(db.Integer, db.ForeignKey('buyingFarmers.id'))
    buying_customer_id = db.Column(db.Integer, db.ForeignKey('buyingCustomers.id'))

    # Define relationships with BuyingFarmer and BuyingCustomer
    buying_farmer = db.relationship('BuyingFarmer', back_populates='quarantines')
    buying_customer = db.relationship('BuyingCustomer', back_populates='quarantine')

    def to_dict(self):
        """to dict quarantine model"""
        return {
            "id": self.id,
            "action": self.action,
            "quarantine_approved_by": self.quarantine_approved_by,
            "new_weight_in_after_sorting_or_regrading": self.new_weight_in_after_sorting_or_regrading,
            "new_weight_out_after_sorting_or_regrading": self.new_weight_out_after_sorting_or_regrading,
        }
    
# Buying Customer table
class BuyingCustomer(db.Model, SerializerMixin):
    """Buying customer model"""
    __tablename__ = "buyingCustomers"

    id = db.Column(db.Integer, primary_key=True)
    produce = db.Column(db.String(255), nullable=False)
    customer = db.Column(db.String(255), nullable=False)
    # Customer buying details
    grn_number = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    quality = db.Column(db.Text, nullable=False)
    action = db.Column(db.String(255), nullable=False)
    weight = db.Column(db.String(255), nullable=False)
    online_price = db.Column(db.String(255), nullable=False)
    
    # grn loaded status
    loaded = db.Column(db.Boolean, default=False, nullable=False)
    
    # Define one-to-many relationship with Quarantine table
    quarantine = db.relationship('Quarantine', back_populates='buying_customer', cascade='all, delete-orphan')
    
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='buying_customer_registration')  # one-to-one table relationship to the user table
    
    @property
    def quality_data(self):
        return json.loads(self.quality) if self.quality else None

    @quality_data.setter
    def quality_data(self, value):
        self.quality = json.dumps(value)

    def to_dict(self):
        """to dict buying customer model"""
        return {
            "id": self.id,
            "customer": self.customer,
            "produce": self.produce,
            "unit": self.unit,
            "grn_number": self.grn_number,
            "quality": self.quality_data,
            "action": self.action,
            "weight": self.weight,
            "online_price": self.online_price,
            "loaded": self.loaded,
            "user_id": self.user_id,
        }
     
# Payment Farmer table
class PaymentFarmer(db.Model, SerializerMixin):
    """Payment farmer model"""
    __tablename__ = "paymentFarmers"

    id = db.Column(db.Integer, primary_key=True)
    buying_center = db.Column(db.String(255), nullable=False)
    cig = db.Column(db.String(255), nullable=False)
    producer = db.Column(db.String(255), nullable=False)
    grn = db.Column(db.String(255), nullable=False)
    # Customer buying details
    net_balance = db.Column(db.String(255), nullable=False)
    payment_type = db.Column(db.String(255), nullable=False)
    outstanding_loan_amount = db.Column(db.String(255), nullable=False)
    payment_due = db.Column(db.String(255), nullable=False)
    set_loan_deduction = db.Column(db.String(255), nullable=False)
    net_balance_before = db.Column(db.String(255), nullable=False)
    net_balance_after_loan_deduction = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.String(255), nullable=False)
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='payment_farmer_registration')  # one to one table relationship to the user table

    def to_dict(self):
        """to dict payment farmer model"""
        return {
            "id": self.id,
            "buying_center": self.buying_center,
            "cig": self.cig,
            "producer": self.producer,
            "grn": self.grn,
            "net_balance": self.net_balance,
            "payment_type": self.payment_type,
            "outstanding_loan_amount": self.outstanding_loan_amount,
            "payment_due": self.payment_due,
            "set_loan_deduction": self.set_loan_deduction,
            "net_balance_before": self.net_balance_before,
            "net_balance_after_loan_deduction": self.net_balance_after_loan_deduction,
            "comment": self.comment,
            "user_id": self.user_id,
        }
    
# Payment Customer table
class PaymentCustomer(db.Model, SerializerMixin):
    """Payment customer model"""
    __tablename__ = "paymentCustomers"

    id = db.Column(db.Integer, primary_key=True)
    village_or_estate = db.Column(db.String(255), nullable=False)
    customer = db.Column(db.String(255), nullable=False)
    grn = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.String(255), nullable=False)
    # Customer buying details
    net_balance = db.Column(db.String(255), nullable=False)
    payment_type = db.Column(db.String(255), nullable=False)
    enter_amount = db.Column(db.String(255), nullable=False)
    net_balance_before = db.Column(db.String(255), nullable=False)
    net_balance_after = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.String(255), nullable=False)
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='payment_customer_registration')  # one to one table relationship to the user table

    def to_dict(self):
        """to dict payment customer model"""
        return {
            "id": self.id,
            "village_or_estate": self.village_or_estate,
            "customer": self.customer,
            "grn": self.grn,
            "amount": self.amount,
            "net_balance": self.net_balance,
            "payment_type": self.payment_type,
            "enter_amount": self.enter_amount,
            "net_balance_before": self.net_balance_before,
            "net_balance_after": self.net_balance_after,
            "comment": self.comment,
            "user_id": self.user_id,
        }
    
class PlanJourney(db.Model, SerializerMixin):
    """PlanJourney model"""
    __tablename__ = "planJournies"

    id = db.Column(db.Integer, primary_key=True)
    truck = db.Column(db.String(255), nullable=False)
    driver = db.Column(db.String(255), nullable=False)
    starting_mileage = db.Column(db.String(255), nullable=False)
    starting_fuel = db.Column(db.String(255), nullable=False)
    start_location = db.Column(db.String(255), nullable=False)
    documentation = db.Column(db.String(255), nullable=False)
    stop_points = db.Column(db.Text, nullable=False)
    final_destination = db.Column(db.String(255), nullable=False)
    date_and_time = db.Column(DateTime)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='plan_journey_registration')

    # One-to-many relationship with dispatch inputs
    dispatch_inputs = db.relationship('DispatchInput', back_populates='plan_journey', cascade='all, delete-orphan')

    @property
    def stop_points_data(self):
        return json.loads(self.stop_points) if self.stop_points else None

    @stop_points_data.setter
    def stop_points_data(self, value):
        self.stop_points = json.dumps(value)

    def to_dict(self):
        """to dict plan journey model"""
        return {
            "id": self.id,
            "truck": self.truck,
            "driver": self.driver,
            "starting_mileage": self.starting_mileage,
            "starting_fuel": self.starting_fuel,
            "documentation": self.documentation,
            "start_location": self.start_location,
            "stop_points": self.stop_points_data,
            "final_destination": self.final_destination,
            "date_and_time": self.date_and_time.strftime('%Y-%m-%d') if self.date_and_time else None,
            "dispatch_inputs": [dispatch_input.to_dict() for dispatch_input in self.dispatch_inputs],
            "user_id": self.user_id,
        }

    @staticmethod
    def parse_datetime(datetime_str):
        """Parse datetime string into datetime object"""
        return datetime.strptime(datetime_str, '%m/%d/%Y %I:%M %p')

    def from_dict(self, data):
        """Assign values to object attributes from a dictionary"""
        for field in ['truck', 'driver', 'starting_mileage', 'starting_fuel', 'documentation', 'start_location', 'stop_points', 'final_destination', 'date_and_time', 'user_id']:
            if field in data:
                if field == 'date_and_time':
                    # Parse datetime string and assign without changing format
                    self.date_and_time = datetime.strptime(data[field], '%m/%d/%Y %I:%M %p')
                elif field == 'stop_points':
                    self.stop_points_data = data[field]
                else:
                    setattr(self, field, data[field])

# Loading model
class DispatchInput(db.Model):
    """dispatch inputs model"""
    __tablename__ = "dispatchInputs"

    id = db.Column(db.Integer, primary_key=True)
    grn = db.Column(db.String(255), nullable=False)
    input = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    number_of_units = db.Column(db.String(255), nullable=False)

    # Foreign key to Hub table
    plan_journey_id = db.Column(db.Integer, db.ForeignKey('planJournies.id'))
    plan_journey = db.relationship('PlanJourney', back_populates='dispatch_inputs')

    def to_dict(self):
        """to dict dispatch inputs model"""
        return {
            "id": self.id,
            "grn": self.grn,
            "input": self.input,
            "description": self.description,
            "number_of_units": self.number_of_units,
            "plan_journey_id": self.plan_journey_id,
        }
    
# Loading Model
class Loading(db.Model, SerializerMixin):
    """Loading model"""
    __tablename__ = "loadings"

    id = db.Column(db.Integer, primary_key=True)
    grn = db.Column(db.String(255), nullable=False)
    total_weight = db.Column(db.String(255), nullable=False)
    truck_loading_number = db.Column(db.String(255), nullable=False)
    from_ = db.Column(db.String(255), nullable=False)
    to = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.String(255), nullable=False)
    offloaded = db.Column(db.Boolean, default=False)

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='loading_registration')

    def to_dict(self):
        """to dict loading model"""
        return {
            "id": self.id,
            "grn": self.grn,
            "total_weight": self.total_weight,
            "truck_loading_number": self.truck_loading_number,
            "from_": self.from_,
            "to": self.to,
            "comment": self.comment,
            "offloaded": self.offloaded,
            "user_id": self.user_id,
        }

# Offloading table
class Offloading(db.Model, SerializerMixin):
    """Offloading model"""
    __tablename__ = "offloadings"

    id = db.Column(db.Integer, primary_key=True)
    offloaded_load = db.Column(db.String(255), nullable=False)
    total_weight = db.Column(db.String(255), nullable=False)
    truck_offloading_number = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.String(255), nullable=False)
    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='offloading_registration')

    def to_dict(self):
        """to dict offloading model"""
        return {
            "id": self.id,
            "offloaded_load": self.offloaded_load,
            "total_weight": self.total_weight,
            "truck_offloading_number": self.truck_offloading_number,
            "comment": self.comment,
            "user_id": self.user_id,
        }

# Processing
class Processing(db.Model, SerializerMixin):
    """Processing user table model"""
    __tablename__ = "processings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_name = db.Column(db.String(255), nullable=False)
    batch_number = db.Column(db.String(255), nullable=False)
    traceability_code = db.Column(db.String(255), nullable=False)
    received_date = db.Column(DateTime)
    weight_before_processing = db.Column(db.String(255), nullable=False)
    processor_name = db.Column(db.String(255), nullable=False)
    supervisor_name = db.Column(db.String(255), nullable=False)
    issued_by = db.Column(db.String(255), nullable=False)
    received_by = db.Column(db.String(255), nullable=False)
    approved_by = db.Column(db.String(255), nullable=False)
    labor_cost_per_unit = db.Column(db.String(255), nullable=False)
    processing_method = db.Column(db.String(255), nullable=False)
    product_quality = db.Column(db.String(255), nullable=False)
    best_before_date = db.Column(DateTime)
    packaging_type = db.Column(db.String(255), nullable=False)
    unit_cost = db.Column(db.String(255), nullable=False)
    number_of_units_issued = db.Column(db.Integer, primary_key=True)
    received_product = db.Column(db.String(255), nullable=False)
    waste_generated_kg = db.Column(db.Integer, primary_key=True)
    waste_sold_kg = db.Column(db.Integer, primary_key=True)
    waste_dumped_kg = db.Column(db.Integer, primary_key=True)

    # Inputs relationship to the farmer biodata table
    inputs = db.relationship('Input', back_populates='processing', cascade='all, delete-orphan')
    product_mixes = db.relationship('ProductMix', back_populates='processing', cascade='all, delete-orphan')

    # Foreign key to User table
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='processing_registration') # one to one table relationship to the user table

    def to_dict(self):
        """to dict processing model"""
        return {
            "id": self.id,
            "product_name": self.product_name,
            "batch_number": self.batch_number,
            "traceability_code": self.traceability_code,
            "received_date": self.received_date.strftime('%Y-%m-%d'),
            "weight_before_processing": self.weight_before_processing,
            "processor_name": self.processor_name,
            "supervisor_name": self.supervisor_name,
            "issued_by": self.issued_by,
            "received_by": self.received_by,
            "approved_by": self.approved_by,
            "labor_cost_per_unit": self.labor_cost_per_unit,
            "product_quality": self.product_quality,
            "processing_method" : self.processing_method,
            "best_before_date": self.best_before_date.strftime('%Y-%m-%d'),
            "packaging_type": self.packaging_type,
            "unit_cost": self.unit_cost,
            "number_of_units_issued": self.number_of_units_issued,
            "received_product": self.received_product,
            "waste_generated_kg": self.waste_generated_kg,
            "waste_sold_kg": self.waste_sold_kg,
            "waste_dumped_kg": self.waste_dumped_kg,
        }
    
class Input(db.Model):
    """Input model added in the farmer biodata"""
    __tablename__ = 'inputs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    input_issued = db.Column(db.String(255), nullable=False)
    price_per_unit = db.Column(db.Integer, primary_key=True)
    weight_per_unit = db.Column(db.Integer, primary_key=True)

    # Foreign key to processing table
    processing_id = db.Column(db.Integer, db.ForeignKey('processings.id'))
    processing = db.relationship('Processing', back_populates='inputs')

    def to_dict(self):
        """to dict input model"""
        return {
            "id": self.id,
            "input_issued": self.input_issued,
            "price_per_unit": self.price_per_unit,
            "weight_per_unit": self.processing_id,
        }
    
# ProductMix
class ProductMix(db.Model):
    """Product mix model added in the farmer biodata"""
    __tablename__ = 'productMixes'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, primary_key=True)
    price_per_quantity = db.Column(db.Integer, primary_key=True)

    # Foreign key to processing table
    processing_id = db.Column(db.Integer, db.ForeignKey('processings.id'))
    processing = db.relationship('Processing', back_populates='product_mixes')

    def to_dict(self):
        """to dict input model"""
        return {
            "id": self.id,
            "product_name": self.product_name,
            "quantity": self.quantity,
            "price_per_quantity": self.price_per_quantity,
        }

# Rural Worker
class RuralWorker(db.Model, SerializerMixin):
    """Rural worker model"""
    __tablename__ = "ruralWorkers"

    id = db.Column(db.Integer, primary_key=True)
    other_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    rural_worker_code = db.Column(db.String(255), nullable=False)
    id_number = db.Column(db.Integer)
    gender = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(DateTime)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.BigInteger)
    education_level = db.Column(db.String(255), nullable=False)
    service = db.Column(db.String(255), nullable=False)
    other = db.Column(db.String(255), nullable=False)
    county = db.Column(db.String(255), nullable=False)
    sub_county = db.Column(db.String(255), nullable=False)
    ward = db.Column(db.String(255), nullable=False)
    village = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, unique=True)

    user = relationship('User', back_populates='rural_worker_registration')

    def to_dict(self):
        """to dict rural worker model"""
        return {
            "id" : self.id,
            "service" : self.service,
            "education_level" : self.education_level,
            "rural_worker_code" : self.rural_worker_code,
            "other_name" : self.other_name,
            "last_name" : self.last_name,
            "id_number" : self.id_number,
            "gender" : self.gender,
            "date_of_birth" : self.date_of_birth.strftime('%Y-%m-%d'),
            "email" : self.email,
            "phone_number" : self.phone_number,
            "other" : self.other,
            "county"  : self.county,
            "sub_county" : self.sub_county,
            "ward" : self.ward,
            "village" : self.village,
            "user_id": self.user_id
        }

# Input Finance
class InputFinance(db.Model, SerializerMixin):
    """Input finance model"""
    __tablename__ = "inputFinances"

    id = db.Column(db.Integer, primary_key=True)
    farmer = db.Column(db.String(255), nullable=False)
    hub = db.Column(db.String(255), nullable=False)
    cig = db.Column(db.String(255), nullable=False)
    input = db.Column(db.String(255), nullable=False)
    number_of_units = db.Column(db.String(255), nullable=False)
    cost_per_unit = db.Column(db.String(255), nullable=False)
    payment_cycle = db.Column(db.String(255), nullable=False)
    installment = db.Column(db.String(255), nullable=False)
    due_date = db.Column(DateTime)
    total_cost = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='input_finance_registration')

    def to_dict(self):
        """to dict input finance model"""
        return {
            "id" : self.id,
            "farmer" : self.farmer,
            "hub" : self.hub,
            "cig" : self.cig,
            "input" : self.input,
            "number_of_units" : self.number_of_units,
            "cost_per_unit" : self.cost_per_unit,
            "payment_cycle" : self.payment_cycle,
            "installment" : self.installment,
            "due_date" : self.due_date.strftime('%Y-%m-%d'),
            "total_cost" : self.total_cost,
            "user_id": self.user_id
        }
    

# Add product model
class AddProduct(db.Model, SerializerMixin):
    """Add product model"""
    __tablename__ = "addProducts"

    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(255), nullable=False)
    product_name = db.Column(db.String(255), nullable=False)
    product_code = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    selling_price = db.Column(db.Integer)
    purchase_price = db.Column(db.Integer)
    quantity = db.Column(db.Integer)
    barcode = db.Column(db.String(255), nullable=False)
    units = db.Column(db.String(255), nullable=False)
    discount_type = db.Column(db.String(255), nullable=False)
    alert_quantity = db.Column(db.String(255), nullable=False)
    tax = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    product_image = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='add_product_registration')

    def to_dict(self):
        """to dict input finance model"""
        return {
            "id" : self.id,
            "item_type" : self.item_type,
            "product_name" : self.product_name,
            "product_code" : self.product_code,
            "category" : self.category,
            "selling_price" : self.selling_price,
            "purchase_price" : self.purchase_price,
            "quantity" : self.quantity,
            "barcode" : self.barcode,
            "units" : self.units,
            "discount_type" : self.discount_type,
            "alert_quantity" : self.alert_quantity,
            "tax" : self.tax,
            "description" : self.description,
            "product_image" : self.product_image,
            "user_id": self.user_id
        }