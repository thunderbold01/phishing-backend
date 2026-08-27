import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, db

with app.app_context():
    db.create_all()
    print('Banco de dados inicializado com sucesso!')
    print(f'URI: {app.config["SQLALCHEMY_DATABASE_URI"][:50]}...')
