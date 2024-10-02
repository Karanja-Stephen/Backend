# from sqlalchemy import create_engine
# from sqlalchemy.engine.url import URL
# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base


# Base = declarative_base()

# # Aiven
# class Config:
#     SQLALCHEMY_DATABASE_URI = 'mysql://avnadmin:AVNS_mJ_eZwhGMQzxby-slZe@farmdata-mfalmesteve-b5cd.h.aivencloud.com:22965/farmdata'
#     SQLALCHEMY_TRACK_MODIFICATIONS = False

# engine = create_engine(
#     Config.SQLALCHEMY_DATABASE_URI,
#     connect_args={
#         'ssl': {
#             'ssl_ca': '/ca.pem'
#         }
#     }
# )

# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Hostgator
class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://farmdat1_Wasomi2:r69P4hdMRtRr@192.254.250.180/farmdat1_mysql_farmdata'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://farmdat1_Wasomi2:r69P4hdMRtRr@192.254.250.180/farmdat1_mysql_farmdata'