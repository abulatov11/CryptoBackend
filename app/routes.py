from app import app
from app.blueprints.mode import mode_blueprint
from app.blueprints.codeword import codeword_blueprint
from app.blueprints.heartbeat import heartbeat_blueprint
from app.blueprints.blockchain import blockchain_blueprint
from app.blueprints.authenticate import authenticate_blueprint
from app.blueprints.server import server_blueprint
from app.blueprints.dh import dh_blueprint
from app.blueprints.rsa_low_public_exp import rsa_low_public_exp_blueprint
from app.blueprints.rsa_low_private_exp import rsa_low_private_exp_blueprint
from app.blueprints.assignment3 import assignment3
from app.blueprints.files import files

app.register_blueprint(mode_blueprint)

app.register_blueprint(codeword_blueprint)

app.register_blueprint(blockchain_blueprint)

app.register_blueprint(authenticate_blueprint)

app.register_blueprint(server_blueprint)

app.register_blueprint(dh_blueprint)

app.register_blueprint(rsa_low_public_exp_blueprint)
app.register_blueprint(rsa_low_private_exp_blueprint)

app.register_blueprint(assignment3)
app.register_blueprint(files)

app.register_blueprint(heartbeat_blueprint)