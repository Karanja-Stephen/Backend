from faker import Faker
from app import app, db
import random
from random import choice, randint
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from models import ProducerBiodata, MarketProduce, DomesticProduce, FarmerFieldRegistration, KeyContact, Hub, BuyingCenter, SeasonPlanning, ScoutingStation, PlanIrrigation, PreventativePest, PreventativeDisease, PlanNutrition, ExtensionService, ExtScoutingStation, PesticideUsed, FertilizerUsed, ForecastYield, CustomerPriceDistribution, FarmerPriceDistribution, HubUser, User, Training, Attendance, BuyingFarmer, CommercialProduce

fake = Faker()

# Create Flask app instance
app = app

# Seed Producer Biodata
subcounties_in_county = {
                "Embu": ["Embu East", "Embu North", "Embu West", "Mbeere North", "Mbeere South"],
                "Kirinyaga": ["Gichugu", "Kirinyaga Central", "Kirinyaga East", "Kirinyaga West", "Mwea East", "Mwea West"],
                "Machakos": ["Kangundo", "Kathiani", "Machakos Town", "Masinga", "Matungulu", "Mavoko", "Mwala", "Yatta"],
                "Nakuru": ["Bahati", "Gilgil", "Kuresoi North", "Kuresoi South", "Molo", "Naivasha", "Nakuru East", "Nakuru North", "Nakuru West", "Njoro", "Rongai", "Subukia"],
            }

def generate_random_id():
    existing_ids = ProducerBiodata.query.with_entities(ProducerBiodata.id).all()
    existing_ids_within_range = [id[0] for id in existing_ids if 1 <= id[0] <= 100]
    
    if existing_ids_within_range:
        return random.choice(existing_ids_within_range)
    else:
        return None

def generate_producer_land_sizes(total_land_size):
    cultivate_land_size = random.uniform(0.1, total_land_size - 0.2)
    uncultivated_land_size = total_land_size - cultivate_land_size
    
    min_homestead_size = max(0.1, total_land_size - 0.1)
    homestead_size = random.uniform(0.1, min_homestead_size)
    
    return {
        "cultivate_land_size": "{:.2f}".format(cultivate_land_size),
        "uncultivated_land_size": "{:.2f}".format(uncultivated_land_size),
        "homestead_size": "{:.2f}".format(homestead_size)
    }


# Seeding hubs
county_coordinates = {
    "Embu": {"latitude": "-0.5362", "longitude": "37.4594"},
    "Kirinyaga": {"latitude": "-0.6", "longitude": "37.25"},
    "Machakos": {"latitude": "-1.5147", "longitude": "37.2638"},
    "Nakuru": {"latitude": "-0.2794", "longitude": "36.0756"},
}

def generate_buying_center_name(county):
    buying_center_name = f"{county} Buying Center"
    existing_buying_centers = BuyingCenter.query.filter(BuyingCenter.hub.like(f"{county}%")).all()
    existing_numbers = [int(buying_center.buying_center_name.split()[-1]) for buying_center in existing_buying_centers if buying_center.buying_center_name.split()[-1].isdigit()]
    if existing_numbers:
        buying_center_name += f" {max(existing_numbers) + 1}"
    else:
        buying_center_name += " 2"
    return buying_center_name

def seed_hub_and_key_contacts():
    with app.app_context():
        for county, coordinates in county_coordinates.items():
            hub_data = {
                "region": county,
                "hub_name": f"{county} Hub",
                "hub_code": fake.uuid4(),
                "address": fake.address(),
                "year_established": fake.date_between(start_date='-30y', end_date='-10y'),
                "ownership": fake.random_element(elements=("Owned", "Leased")),
                "floor_size": fake.random_number(digits=4),
                "facilities": fake.random_element(elements=("Refrigiration/Cooling", "Hand Washing Facilities", "Produce Handling Unit", "Washrooms")),
                "input_center": fake.random_element(elements=("Yes", "No")),
                "type_of_building": fake.random_element(elements=("Permanent", "Temporary")),
                "longitude": coordinates["longitude"],
                "latitude": coordinates["latitude"],
                "user_id": "c88531f9-d821-45e3-9bee-c76250414954",
            }

            # Create hub instance
            hub = Hub(**hub_data)

            key_contacts_data = []
            for _ in range(3):
                key_contact_data = {
                    "other_name": fake.first_name(),
                    "last_name": fake.last_name(),
                    "id_number": fake.random_number(digits=9),
                    "gender": fake.random_element(elements=("Male", "Female")),
                    "role": fake.random_element(elements=("Customer", "Supplier", "Manager")),
                    "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=90),
                    "email": fake.email(),
                    "phone_number": fake.random_number(digits=9),
                }
                key_contacts_data.append(key_contact_data)

            key_contacts = [KeyContact(**contact_data) for contact_data in key_contacts_data]

            hub.key_contacts.extend(key_contacts)

            # Commit to the database
            db.session.add(hub)
            db.session.commit()

def seed_buying_center_and_key_contacts():
    with app.app_context():
        for county, coordinates in county_coordinates.items():
            county_location = random.choice(list(county_coordinates.keys()))
            subcounty = fake.random_element(elements=subcounties_in_county[county])
            ward = random.choice(subcounties_in_county[county])
            # Generate fake data for hub
            buying_center_data = {
                "hub": f"{county} Hub",
                "county": county,
                "sub_county": subcounty,
                "ward": ward,
                "village": ward,
                "buying_center_name": f"{county} Buying Center",
                "buying_center_code": fake.uuid4(),
                "address": fake.address(),
                "year_established": fake.date_between(start_date='-30y', end_date='-10y'),
                "ownership": fake.random_element(elements=("Owned", "Leased")),
                "floor_size": fake.random_number(digits=4),
                "facilities": fake.random_element(elements=("Refrigiration/Cooling", "Hand Washing Facilities", "Produce Handling Unit", "Washrooms")),
                "input_center": fake.random_element(elements=("Yes", "No")),
                "type_of_building": fake.random_element(elements=("Permanent", "Temporary")),
                "location": f"{coordinates['longitude']} {coordinates['latitude']}",
                "user_id": "c88531f9-d821-45e3-9bee-c76250414954",
            }

            # Create hub instance
            buying_center = BuyingCenter(**buying_center_data)

            key_contacts_data = []
            for _ in range(3):
                key_contact_data = {
                    "other_name": fake.first_name(),
                    "last_name": fake.last_name(),
                    "id_number": fake.random_number(digits=9),
                    "gender": fake.random_element(elements=("Male", "Female")),
                    "role": fake.random_element(elements=("Customer", "Supplier", "Manager")),
                    "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=90),
                    "email": fake.email(),
                    "phone_number": fake.random_number(digits=9),
                }
                key_contacts_data.append(key_contact_data)

            key_contacts = [KeyContact(**contact_data) for contact_data in key_contacts_data]

            buying_center.key_contacts.extend(key_contacts)

            db.session.add(buying_center)
            db.session.commit()
# Names
kenyan_first_names = ["Wanjohi", "Kamau", "Gitau", "Njoroge", "Maina", "Wanjiru", "Nyambura", "Wangari", "Waithera", "Njeri", "Ochieng", "Odhiambo", "Onyango", "Omondi", "Otieno", "Akinyi", "Atieno", "Adhiambo", "Achieng", "Anyango"]
kenyan_last_names = ["Mwangi", "Kibet", "Mutua", "Kimani", "Musyoka", "Auma", "Ogutu", "Omollo", "Owiti", "Njenga", "Waweru", "Nzomo", "Njoroge", "Njeri", "Nyambura", "Kamau", "Odongo", "Achieng", "Kosgei", "Mugo"]

# Seed the TA's
def seed_hub_users():
    with app.app_context():
        # Define Kenyan names
        kenyan_first_names = ["Wanjohi", "Kamau", "Gitau", "Njoroge", "Maina", "Wanjiru", "Nyambura", "Wangari", "Waithera", "Njeri", "Ochieng", "Odhiambo", "Onyango", "Omondi", "Otieno", "Akinyi", "Atieno", "Adhiambo", "Achieng", "Anyango"]
        kenyan_last_names = ["Mwangi", "Kibet", "Mutua", "Kimani", "Musyoka", "Auma", "Ogutu", "Omollo", "Owiti", "Njenga", "Waweru", "Nzomo", "Njoroge", "Njeri", "Nyambura", "Kamau", "Odongo", "Achieng", "Kosgei", "Mugo"]
        # Define roles and other necessary details
        role = "Technical Assistant"
        password = "Password@1234"  # This password must meet the validation criteria

        if not User.validate_password(password):
            raise ValueError('Password must include at least one number, special character, and uppercase letter.')

        for county, coordinates in county_coordinates.items():
            for _ in range(11):
                other_name = random.choice(kenyan_first_names)
                last_name = random.choice(kenyan_last_names)
                code = fake.unique.random_number(digits=5)
                email = fake.unique.email()
                phone_number = fake.random_number(digits=10)
                id_number = fake.random_number(digits=8)
                gender = fake.random_element(elements=("Male", "Female"))
                date_of_birth = fake.date_of_birth(minimum_age=25, maximum_age=60)
                education_level = fake.random_element(elements=("Primary", "Secondary", "Tertiary"))
                buying_center = f"{county} Buying Center"
                sub_county = f"{county} Sub-County"
                ward = f"{county} Ward"
                village = f"{county} Village"

                # Create new user
                new_user = User(
                    other_name=other_name,
                    last_name=last_name,
                    user_type='Hub User',
                    role=role,
                    email=email,
                    password=password
                )

                db.session.add(new_user)
                db.session.commit()

                # Create corresponding HubUser
                new_hub_user = HubUser(
                    other_name=other_name,
                    last_name=last_name,
                    code=code,
                    role=role,
                    id_number=id_number,
                    gender=gender,
                    date_of_birth=date_of_birth,
                    email=email,
                    phone_number=phone_number,
                    education_level=education_level,
                    hub=f"{county} Hub",
                    buying_center=buying_center,
                    county=county,
                    sub_county=sub_county,
                    ward=ward,
                    village=village,
                    user_id=new_user.id
                )

                db.session.add(new_hub_user)
        
        db.session.commit()

def seed_producer_biodata():
    with app.app_context():
        # Define Kenyan names
        kenyan_first_names = ["Wanjohi", "Kamau", "Gitau", "Njoroge", "Maina", "Wanjiru", "Nyambura", "Wangari", "Waithera", "Njeri", "Ochieng", "Odhiambo", "Onyango", "Omondi", "Otieno", "Akinyi", "Atieno", "Adhiambo", "Achieng", "Anyango"]
        kenyan_last_names = ["James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Charles", "Thomas", "Christopher", "Daniel", "Matthew", "Anthony", "Donald", "Mark", "Paul", "Steven", "Andrew", "Kenneth", "George", "Joshua", "Kevin", "Brian", "Edward", "Ronald", "Timothy", "Jason", "Jeffrey", "Ryan", "Jacob", "Gary", "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin", "Scott", "Brandon", "Benjamin", "Samuel", "Gregory", "Frank", "Alexander", "Raymond", "Patrick", "Jack", "Dennis", "Jerry"]
        # Fetch existing TAs' user IDs
        existing_tas = User.query.filter_by(role="Technical Assistant").all()
        if not existing_tas:
            raise ValueError("No existing TAs found. Seed TAs first.")

        existing_ta_ids = [ta.id for ta in existing_tas]

        for _ in range(150):
            # Generate fake data for each producer
            date_of_birth = fake.date_time_between(start_date='-69y', end_date='-18y').strftime('%Y-%m-%dT%H:%M:%S')
            phone_number = fake.numerify(text='##########')
            county = random.choice(list(subcounties_in_county.keys()))
            subcounty = fake.random_element(elements=subcounties_in_county[county])
            ward = random.choice(subcounties_in_county[county])

            total_land_size = random.uniform(0.1, 3)
            land_sizes = generate_producer_land_sizes(total_land_size)
            
            # Randomly select an existing TA ID
            ta_id = random.choice(existing_ta_ids)
            
            producer_data = {
                "other_name": random.choice(kenyan_first_names),
                "last_name": random.choice(kenyan_last_names),
                "farmer_code": fake.uuid4(),
                "id_number": fake.random_number(digits=9),
                "gender": fake.random_element(elements=("Male", "Female")),
                "date_of_birth": date_of_birth,
                "email": fake.email(),
                "phone_number": phone_number,
                "hub": f"{county} Hub",
                "buying_center": f"{county} Buying Center",
                "gender": fake.random_element(elements=("Male", "Female")),
                "education_level": fake.random_element(elements=("Doctorate", "Masters", "Bachelor's Degree", "Diploma", "High School", "Primary Education", "None")),
                "county": county,
                "sub_county": subcounty,
                "ward": ward,
                "village": ward,
                "primary_producer": [
                    {
                        "response": "Yes",
                        "firstname": fake.first_name(),
                        "other_name": fake.first_name(),
                        "id_number": fake.random_number(digits=9),
                        "phone_number": phone_number,
                        "gender": fake.random_element(elements=("Male", "Female")),
                        "email": fake.email(),
                        "date_of_birth": date_of_birth
                    }
                ],
                "total_land_size": "{:.2f}".format(total_land_size),
                **land_sizes,
                "farm_accessibility": fake.random_element(elements=("Tarmac Road", "All Weather Murram", "Dry Weather Road", "Inaccessible by Road")),
                "number_of_family_workers": fake.random_digit(),
                "number_of_hired_workers": fake.random_digit(),
                "farmer_interest_in_extension": fake.random_element(elements=("Yes", "No")),
                "access_to_irrigation": fake.random_element(elements=("Yes", "No")),
                "crop_list": fake.random_element(elements=("crop1", "crop2", "crop3")),
                "knowledge_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "soil_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "compost_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "nutrition_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "pests_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "disease_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "quality_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "market_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "food_loss_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "finance_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "weather_related": fake.random_element(elements=("High", "Moderate", "Low", "None")),
                "dairy_cattle": fake.random_element(elements=("Yes", "No")),
                "beef_cattle": fake.random_element(elements=("Yes", "No")),
                "sheep": fake.random_element(elements=("Yes", "No")),
                "poultry": fake.random_element(elements=("Yes", "No")),
                "pigs": fake.random_element(elements=("Yes", "No")),
                "rabbits": fake.random_element(elements=("Yes", "No")),
                "beehives": fake.random_element(elements=("Yes", "No")),
                "donkeys": fake.random_element(elements=("Yes", "No")),
                "goats": fake.random_element(elements=("Yes", "No")),
                "camels": fake.random_element(elements=("Yes", "No")),
                "aquaculture": fake.random_element(elements=("Yes", "No")),
                "housing_type": fake.random_element(elements=("Permanent", "Semi-permanent", "Temporary")),
                "housing_floor": fake.random_element(elements=("Tiled", "Concrete", "Earthed")),
                "housing_roof": fake.random_element(elements=("Grass", "Corrugated", "Tiled")),
                "lighting_fuel": fake.random_element(elements=("Electricity", "Solar", "Biogas", "Kerosene", "None")),
                "cooking_fuel": fake.random_element(elements=("Electricity", "Firewood", "Biogas", "Kerosene", "Charcoal")),
                "water_filter": fake.random_element(elements=("Yes", "No")),
                "water_tank_greater_than_5000lts": fake.random_element(elements=("Yes", "No")),
                "hand_washing_facilities": fake.random_element(elements=("Yes", "No")),
                "ppes": fake.random_element(elements=("Yes", "No")),
                "water_well_or_weir": fake.random_element(elements=("Yes", "No")),
                "irrigation_pump": fake.random_element(elements=("Yes", "No")),
                "harvesting_equipment": fake.random_element(elements=("Crate", "Bucket", "Bag")),
                "transportation_type": fake.random_element(elements=("Donkey", "Bull", "Hand-cart", "Motor Vehicle", "Motorcycle/Bicycle")),
                "toilet_floor": fake.random_element(elements=("Washable", "Non-washable")),
                "user_approved": fake.random_element(elements=(True, False)),
                "ta": ta_id,
                "user_id": "c88531f9-d821-45e3-9bee-c76250414954"
            }
            producer = ProducerBiodata(**producer_data)
            
            # Generate and attach market produce
            products = [
                {"product": "Tea", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Coffee", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Green Maize", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Fodder Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tree Tomato", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tomato", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "African Leafy Vegetables", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cabbage", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Irish Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Lettuce", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Passion Fruit", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Bananas", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garden Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cow Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucurbits", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Avocado", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Carrots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garlic", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Ginger", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Mango", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pineapple", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Orange", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Watermelon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Sweet Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Yams", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Arrow Roots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pumpkins", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Thorn Melon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spinach", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Kales", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spring Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Leeks", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucumber", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Macadamia", "product_category": "Nuts/Oil Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))}
            ]
            # Shuffle the products list to randomize selection
            random.shuffle(products)

            # Generate and attach market produce
            for data in products[:random.randint(1, 5)]:
                data["producer_biodata_id"] = producer.id
                market_produce = CommercialProduce(**data)
                producer.commercialProduces.append(market_produce)

            # Generate and attach domestic produce
            for data in products[:random.randint(1, 5)]:
                data["producer_biodata_id"] = producer.id
                domestic_produce = DomesticProduce(**data)
                producer.domesticProduces.append(domestic_produce)

            db.session.add(producer)
        db.session.commit()

# Seeding field registration data
def seed_farmer_field_registration():
    with app.app_context():
        # Get all producer biodata
        producers = ProducerBiodata.query.all()

        for producer in producers:
            field_data = {
                "producer_biodata_id": producer.id,
                "producer": producer.farmer_code,
                "field_number": random.randint(1, 100),
                "field_size": "{:.2f}".format(random.uniform(0.5, 5)),
                "crop1": "crop1",
                "crop_variety1": "variety1",
                "date_planted1": datetime.now(),
                "date_of_harvest1": datetime.now(),
                "population1": "population1",
                "baseline_yield_last_season1": random.randint(100, 1000),
                "baseline_income_last_season1": "income1",
                "baseline_cost_of_production_last_season1": "cost1",
                "crop2": "crop2",
                "crop_variety2": "variety2",
                "date_planted2": datetime.now(),
                "date_of_harvest2": datetime.now(),
                "population2": "population2",
                "baseline_yield_last_season2": random.randint(100, 1000),
                "baseline_income_last_season2": "income2",
                "baseline_cost_of_production_last_season2": "cost2",
                "user_id": "c88531f9-d821-45e3-9bee-c76250414954",
            }

            field_registration = FarmerFieldRegistration(**field_data)

            db.session.add(field_registration)
        
        db.session.commit()
    
# Seed Season planning 

def seed_seasons():
    with app.app_context():
        user_id = "c88531f9-d821-45e3-9bee-c76250414954"
        producers = ProducerBiodata.query.all()
        field_numbers = FarmerFieldRegistration.query.all()

        for _ in range(150):
            producer = random.choice(producers).id
            field_number = random.choice(field_numbers).field_number
            planned_date_of_planting = fake.date_time_this_year()
            week_number = fake.random_int(min=1, max=52)

            
            # Generate nested JSON data
            nursery = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            gapping = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            soil_analysis = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date(), "type_of_analysis": "Major Nutrition Scope (Macro)"}
            liming = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date(), "cost_per_unit": "100", "number_of_units": "100"}
            transplanting = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date(), "projected_yield": "100", "plant_population": "100"}
            weeding = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            prunning_thinning_desuckering = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            mulching = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            harvesting = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date(), "projected_yield": "100", "plant_population": "100"}
            user_id = "c88531f9-d821-45e3-9bee-c76250414954"
            # Create SeasonPlanning instance
            season_planning = SeasonPlanning(
                user_id=user_id,
                producer=producer,
                field=field_number,
                # crop=crop,
                planned_date_of_planting=planned_date_of_planting,
                week_number=week_number,
                nursery=nursery,
                gapping=gapping,
                soil_analysis=soil_analysis,
                liming=liming,
                transplanting=transplanting,
                weeding=weeding,
                prunning_thinning_desuckering=prunning_thinning_desuckering,
                mulching=mulching,
                harvesting=harvesting
            )

            db.session.add(season_planning)
            products = [
                {"product": "Tea", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Coffee", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Green Maize", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Fodder Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tree Tomato", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tomato", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "African Leafy Vegetables", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cabbage", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Irish Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Lettuce", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Passion Fruit", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Bananas", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garden Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cow Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucurbits", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Avocado", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Carrots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garlic", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Ginger", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Mango", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pineapple", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Orange", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Watermelon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Sweet Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Yams", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Arrow Roots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pumpkins", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Thorn Melon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spinach", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Kales", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spring Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Leeks", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucumber", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Macadamia", "product_category": "Nuts/Oil Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))}
            ]
            # Shuffle the products list to randomize selection
            random.shuffle(products)

            # Generate and attach market produce
            for data in products[:random.randint(1, 5)]:
                data["season_planning_id"] = season_planning.id
                market_produce = MarketProduce(**data)
                season_planning.marketProduces.append(market_produce)

            # Create related PlanNutrition instance
            plan_nutrition = PlanNutrition(
                product="Fertilizer A",
                product_name="Fertilizer A",
                unit="15",
                cost_per_unit="10",
                application_rate="2",
                time_of_application="Morning",
                method_of_application="Spraying",
                product_formulation="Powder",
                date_of_application="2024-03-31",
                total_mixing_ratio="1:1000",
                season_planning=season_planning
            )
            
            db.session.add(plan_nutrition)

            # Create related ScoutingStation instance
            scouting_station = ScoutingStation(
                bait_station="Station A",
                type_of_bait_provided="Bait A",
                frequency="Monthly",
                season_planning=season_planning
            )

            db.session.add(scouting_station)

            # Create related PreventativeDisease instance
            preventative_disease = PreventativeDisease(
                disease="Disease A",
                product="Pesticide A",
                category="Category A",
                formulation="Formulation A",
                dosage="5",
                unit="2",
                cost_per_unit="20",
                volume_of_water="10",
                frequency_of_application="Weekly",
                total_cost="200",
                season_planning=season_planning
            )

            db.session.add(preventative_disease)

            # Create related PreventativePest instance
            preventative_pest = PreventativePest(
                pest="Pest A",
                product="Pesticide B",
                category="Category B",
                formulation="Formulation B",
                dosage="4",
                unit="9",
                cost_per_unit="15",
                volume_of_water="8",
                frequency_of_application="Bi-weekly",
                total_cost="120",
                season_planning=season_planning
            )

            db.session.add(preventative_pest)

            # Create related PlanIrrigation instance
            plan_irrigation = PlanIrrigation(
                type_of_irrigation="Drip Irrigation",
                frequency="Daily",
                discharge_hours="2",
                unit_cost="5",
                cost_of_fuel="2",
                season_planning=season_planning
            )

            db.session.add(plan_irrigation)

        # Commit all changes to the database
        db.session.commit()

# Seed Extension 
def seed_extensions():
    with app.app_context():
        user_id = "c88531f9-d821-45e3-9bee-c76250414954"
        producers = ProducerBiodata.query.all()
        field_numbers = FarmerFieldRegistration.query.all()

        for _ in range(150):
            producer = random.choice(producers).id
            field_number = random.choice(field_numbers).field_number
            planned_date_of_planting = fake.date_time_this_year()
            week_number = fake.random_int(min=1, max=52)

            # Generate nested JSON data
            nursery = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                       "start_date": fake.date()}
            gapping = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                       "start_date": fake.date()}
            soil_analysis = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                             "start_date": fake.date(), "type_of_analysis": "Major Nutrition Scope (Macro)"}
            liming = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                      "start_date": fake.date(), "cost_per_unit": "100", "number_of_units": "100"}
            transplanting = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                             "start_date": fake.date(), "projected_yield": "100", "plant_population": "100"}
            weeding = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                       "start_date": fake.date()}
            prunning_thinning_desuckering = {"man_days": randint(1, 5), "unit_cost": "100",
                                              "date_range": "2024-05-12 to 2024-05-22", "start_date": fake.date()}
            mulching = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                        "start_date": fake.date()}
            harvesting = {"man_days": randint(1, 5), "unit_cost": "100", "date_range": "2024-05-12 to 2024-05-22",
                          "start_date": fake.date(), "projected_yield": "100", "plant_population": "100"}

            # Create ExtensionService instance
            extension_service = ExtensionService(
                user_id=user_id,
                producer=producer,
                field=field_number,
                planned_date_of_planting=planned_date_of_planting,
                week_number=week_number,
                nursery=nursery,
                gapping=gapping,
                soil_analysis=soil_analysis,
                liming=liming,
                transplanting=transplanting,
                weeding=weeding,
                prunning_thinning_desuckering=prunning_thinning_desuckering,
                mulching=mulching,
                harvesting=harvesting
            )

            db.session.add(extension_service)

            products = [
                {"product": "Tea", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Coffee", "product_category": "Plantation Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Green Maize", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Fodder Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Nappiergrass", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tree Tomato", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Tomato", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "African Leafy Vegetables", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cabbage", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Irish Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Lettuce", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Passion Fruit", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Bananas", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garden Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cow Peas", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucurbits", "product_category": "Cereals/Pulses", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Avocado", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Carrots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Garlic", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Ginger", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Mango", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pineapple", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Orange", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Watermelon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Sweet Potatoes", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Yams", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Arrow Roots", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Capsicum", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Pumpkins", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Thorn Melon", "product_category": "Fruits", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spinach", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Kales", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Spring Onions", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Leeks", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Cucumber", "product_category": "Vegetables", "acerage": "{:.2f}".format(random.uniform(0.1, 3))},
                {"product": "Macadamia", "product_category": "Nuts/Oil Crops", "acerage": "{:.2f}".format(random.uniform(0.1, 3))}
            ]
            # Shuffle the products list to randomize selection
            random.shuffle(products)

            # Generate and attach market produce
            for data in products[:random.randint(1, 5)]:
                data["extension_service_id"] = extension_service.id
                market_produce = MarketProduce(**data)
                extension_service.marketProduces.append(market_produce)

            # Create related ExtScoutingStation instance
            ext_scouting_stations = ExtScoutingStation(
                scouting_method="Fertilizer A",
                bait_station="Fertilizer A",
                pest_or_disease="15",
                management="10",
                extension_service_registration=extension_service
            )
            db.session.add(ext_scouting_stations)

            # Create related PesticideUsed instance
            pesticides_used = PesticideUsed(
                register="register A",
                product="Pesticide A",
                category="Category A",
                formulation="Formulation A",
                dosage="5",
                unit="2",
                cost_per_unit="20",
                volume_of_water="10",
                total_cost="200",
                frequency_of_application="Weekly",
                extension_service_registration=extension_service
            )
            db.session.add(pesticides_used)

            # Create related FertilizerUsed instance
            fertilizers_used = FertilizerUsed(
                register="register A",
                product="Pesticide A",
                category="Category A",
                formulation="Formulation A",
                dosage="5",
                unit="2",
                cost_per_unit="20",
                volume_of_water="10",
                frequency_of_application="Weekly",
                total_cost="200",
                extension_service_registration=extension_service
            )
            db.session.add(fertilizers_used)

            # Create related ForecastYield instance
            forecast_yields = ForecastYield(
                crop_population_pc="register A",
                yield_forecast_pc="Pesticide A",
                forecast_quality="Category A",
                ta_comments="Formulation A",
                extension_service_registration=extension_service
            )
            db.session.add(forecast_yields)

        # Commit all changes to the database
        db.session.commit()

# Price distributions
def seed_farmer_price_distributions():
    with app.app_context():
        # Fetch existing MarketProduce IDs
        existing_produce_ids = [produce.id for produce in MarketProduce.query.all()]
        
        for county, coordinates in county_coordinates.items():
            hub = f"{county} Hub"
            buying_center = f"{county} Buying Center"
            
            for _ in range(150):
                # Generate fake data
                online_price = fake.random_number(digits=3)
                unit = fake.random_element(elements=("kg", "lbs", "gallons"))
                date = fake.date_this_year()
                comments = fake.sentence()
                sold = fake.boolean()
                user_id = "c88531f9-d821-45e3-9bee-c76250414954"
                produce_id = random.choice(existing_produce_ids)

                farmer_price_distribution = FarmerPriceDistribution(
                    hub=hub,
                    buying_center=buying_center,
                    online_price=online_price,
                    unit=unit,
                    date=date,
                    comments=comments,
                    sold=sold,
                    user_id=user_id,
                    produce_id=produce_id
                )

                db.session.add(farmer_price_distribution)
        
        db.session.commit()

def seed_customer_price_distributions():
    with app.app_context():
        existing_produce_ids = [produce.id for produce in MarketProduce.query.all()]
        
        for county, coordinates in county_coordinates.items():
            hub = f"{county} Hub"
            buying_center = f"{county} Buying Center"

            for _ in range(150):
                online_price = fake.random_number(digits=3)
                unit = fake.random_element(elements=("kg", "lbs", "gallons"))
                date = fake.date_this_year()
                comments = fake.sentence()
                sold = fake.boolean()
                user_id = "c88531f9-d821-45e3-9bee-c76250414954"
                produce_id = random.choice(existing_produce_ids)

                # Create a new CustomerPriceDistribution instance
                customer_price_distribution = CustomerPriceDistribution(
                    hub=hub,
                    buying_center=buying_center,
                    online_price=online_price,
                    unit=unit,
                    date=date,
                    comments=comments,
                    sold=sold,
                    user_id=user_id,
                    produce_id=produce_id
                )

                db.session.add(customer_price_distribution)
        
        db.session.commit()

# seed trainings
def seed_trainings_and_attendance():
    with app.app_context():
        # Define agricultural course names
        course_names = [
            "Crop Rotation Techniques", "Soil Health and Fertility", "Integrated Pest Management", 
            "Sustainable Farming Practices", "Modern Irrigation Methods", "Post-Harvest Handling",
            "Agroforestry", "Organic Farming", "Greenhouse Farming", "Livestock Management",
            "Dairy Farming", "Poultry Farming", "Fisheries Management", "Agribusiness and Marketing",
            "Climate-Smart Agriculture", "Use of Technology in Agriculture", "Seed Selection and Breeding",
            "Farm Mechanization", "Water Conservation Techniques", "Food Security and Nutrition"
        ]

        # Define buying centers
        buying_centers = list(county_coordinates.keys())

        # Fetch existing producers
        existing_producers = ProducerBiodata.query.all()
        # Fetch existing TAs
        technical_assistants = HubUser.query.filter_by(role='Technical Assistant').all()

        # Define ten hardcoded date ranges
        date_ranges = [
            "2024-01-01 - 2024-01-10",
            "2024-02-01 - 2024-02-10",
            "2024-03-01 - 2024-03-10",
            "2024-04-01 - 2024-04-10",
            "2024-05-01 - 2024-05-10",
            "2024-06-01 - 2024-06-10",
            "2024-07-01 - 2024-07-10",
            "2024-08-01 - 2024-08-10",
            "2024-09-01 - 2024-09-10",
            "2024-10-01 - 2024-10-10"
        ]

        for buying_center in buying_centers:
            sub_counties = subcounties_in_county[buying_center]
            venues = [f"{sub_county} Venue" for sub_county in sub_counties]

            for _ in range(7):
                course_name = random.choice(course_names)
                trainer = random.choice(technical_assistants)
                trainer_name = f"{trainer.other_name} {trainer.last_name}"
                course_description = fake.sentence()
                date_of_training = random.choice(date_ranges)

                # Select 15 random producers as participants
                participants = random.sample(existing_producers, 15)

                # Create corresponding Training
                training = Training(
                    course_name=course_name,
                    trainer_name=trainer_name,
                    buying_center=buying_center,
                    course_description=course_description,
                    date_of_training=date_of_training,
                    content_of_training=fake.paragraph(),
                    venue=random.choice(venues),
                    participants=[{"name": f"{producer.other_name} {producer.last_name}", "email": producer.email} for producer in participants],
                    user_id="c88531f9-d821-45e3-9bee-c76250414954"
                )

                db.session.add(training)
                db.session.commit()

                # Create corresponding Attendance
                for producer in participants:
                    attendance = Attendance(
                        attendance="Present",
                        training_id=training.id,
                        user_id=producer.user_id
                    )

                    db.session.add(attendance)

        db.session.commit()

# Seed buying
def seed_buying_farmers():
    with app.app_context():
        existing_producers = ProducerBiodata.query.all()
        existing_produce = MarketProduce.query.all()

        buying_centers = list(county_coordinates.keys())

        for _ in range(100):
            buying_center = random.choice(buying_centers)
            producer = random.choice(existing_producers)
            produce = random.choice(existing_produce)
            grn_number = fake.uuid4()
            unit = fake.random_element(elements=("Kg", "Ton"))
            quality = {"humidity": fake.random_int(0, 100), "temperature": fake.random_int(0, 100)}
            action = "Accept"
            weight = fake.random_int(1, 100)

            buying_farmer = BuyingFarmer(
                buying_center=buying_center,
                producer=producer.other_name + " " + producer.last_name,
                produce=produce.id,
                grn_number=grn_number,
                unit=unit,
                quality=quality,
                action=action,
                weight=weight,
                user_id="c88531f9-d821-45e3-9bee-c76250414954"
            )

            db.session.add(buying_farmer)

        db.session.commit()
      
if __name__ == '__main__':
    seed_hub_users()
    seed_producer_biodata()
    seed_hub_and_key_contacts()
    seed_buying_center_and_key_contacts()
    seed_farmer_field_registration()
    seed_seasons()
    seed_extensions()
    seed_customer_price_distributions()
    seed_farmer_price_distributions()
    seed_trainings_and_attendance()
    seed_buying_farmers()