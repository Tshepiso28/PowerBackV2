from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt, get_jwt_identity
)
import psycopg2
from psycopg2 import extras
from psycopg2.errors import IntegrityError
import os

app = Flask(__name__)

#CORS(app)
CORS(app, resources={r"/*": {"origins": "http://localhost:4200"}})

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        database=os.environ.get('DB_NAME', 'rentdb'),
        user=os.environ.get('DB_USER', 'damacm179'),
        password=os.environ.get('DB_PASSWORD', '1017'),
        cursor_factory=extras.DictCursor
    )

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM user_rent WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        return jsonify({'message': 'User already exists'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute(
        "INSERT INTO user_rent (full_name, email, password_hash) VALUES (%s, %s, %s)",
        (name, email, password_hash)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM user_rent WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user and bcrypt.check_password_hash(user['password_hash'], password):
        access_token = create_access_token(identity=str(user['id']))
        cursor.close()
        conn.close()
        return jsonify({'access_token': access_token}), 200

    cursor.close()
    conn.close()
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/signout', methods=['POST'])
@jwt_required()
def signout():
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return jsonify({"message": "Successfully signed out"}), 200

def is_user_subscribed(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_subscribed FROM user_rent WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user and user['is_subscribed']

@app.route('/solar-panels/<int:panel_id>', methods=['GET'])
@jwt_required()
def view_solar_panel(panel_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT sp.id, sp.name, sp.description, sp.rental_price_per_day, sp.owner_id, sp.product_type, "
        "sp.serial_number, sp.location, sp.is_available, ur.full_name as owner_name "
        "FROM solar_panels sp "
        "JOIN user_rent ur ON sp.owner_id = ur.id "
        "WHERE sp.id = %s",
        (panel_id,)
    )
    panel = cursor.fetchone()
    cursor.close()
    conn.close()

    if not panel:
        return jsonify({'message': 'Power Source not found'}), 404

    return jsonify({
        'id': panel['id'],
        'name': panel['name'],
        'description': panel['description'],
        'rental_price_per_day': float(panel['rental_price_per_day']),
        'owner_id': panel['owner_id'],
        'owner_name': panel['owner_name'],
        'product_type': panel['product_type'],
        'serial_number': panel['serial_number'],
        'location': panel['location'],
        'is_available': panel['is_available']
    }), 200

@app.route('/solar-panels', methods=['GET'])
@jwt_required()
def list_solar_panels():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, description, rental_price_per_day, owner_id, product_type, serial_number, location "
        "FROM solar_panels WHERE is_available = TRUE"
    )
    panels = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([
        {
            'id': panel['id'],
            'name': panel['name'],
            'description': panel['description'],
            'rental_price_per_day': float(panel['rental_price_per_day']),
            'owner_id': panel['owner_id'],
            'product_type': panel['product_type'],
            'serial_number': panel['serial_number'],
            'location': panel['location']
        } for panel in panels
    ]), 200

@app.route('/solar-panels/owned', methods=['GET'])
@jwt_required()
def list_owned_solar_panels():
    user_id = get_jwt_identity()
    if not is_user_subscribed(user_id):
        return jsonify({'message': 'Subscription required to view owned Power Source'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, description, rental_price_per_day, is_available, owner_id, product_type, serial_number, location "
        "FROM solar_panels WHERE owner_id = %s",
        (user_id,)
    )
    panels = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([
        {
            'id': panel['id'],
            'name': panel['name'],
            'description': panel['description'],
            'rental_price_per_day': float(panel['rental_price_per_day']),
            'is_available': panel['is_available'],
            'owner_id': panel['owner_id'],
            'product_type': panel['product_type'],
            'serial_number': panel['serial_number'],
            'location': panel['location']
        } for panel in panels
    ]), 200

@app.route('/solar-panels', methods=['POST'])
@jwt_required()
def add_solar_panel():
    user_id = get_jwt_identity()
    if not is_user_subscribed(user_id):
        return jsonify({'message': 'Subscription required to add Power Source'}), 403
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    rental_price_per_day = data.get('rental_price_per_day')
    product_type = data.get('product_type')
    serial_number = data.get('serial_number')
    location = data.get('location')
    
    if not all([name, rental_price_per_day, product_type, serial_number]) or \
       not isinstance(rental_price_per_day, (int, float)) or rental_price_per_day <= 0:
        return jsonify({'message': 'Invalid or missing required fields'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO solar_panels (name, description, rental_price_per_day, owner_id, product_type, serial_number, location) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (name, description, rental_price_per_day, user_id, product_type, serial_number, location)
        )
        panel_id = cursor.fetchone()['id']
        conn.commit()
    except IntegrityError as e:
        cursor.close()
        conn.close()
        if 'unique_serial_number' in str(e):
            return jsonify({'message': 'Serial number already exists'}), 400
        raise e
    finally:
        cursor.close()
        conn.close()
    
    return jsonify({'message': 'Power Source added successfully', 'panel_id': panel_id}), 201

@app.route('/solar-panels/<int:panel_id>', methods=['PATCH'])
@jwt_required()
def update_solar_panel(panel_id):
    user_id = get_jwt_identity()
    if not is_user_subscribed(user_id):
        return jsonify({'message': 'Subscription required to update Power Source'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT owner_id FROM solar_panels WHERE id = %s",
        (panel_id,)
    )
    panel = cursor.fetchone()
    
    if not panel:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Power Source not found'}), 404
    
    if panel['owner_id'] != int(user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Unauthorized to update this Power Source'}), 403
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    rental_price_per_day = data.get('rental_price_per_day')
    is_available = data.get('is_available')
    product_type = data.get('product_type')
    serial_number = data.get('serial_number')
    location = data.get('location')
    
    if rental_price_per_day is not None and (not isinstance(rental_price_per_day, (int, float)) or rental_price_per_day <= 0):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Invalid rental price'}), 400
    
    if is_available is not None and not isinstance(is_available, bool):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Invalid availability status'}), 400
    
    updates = []
    params = []
    if name:
        updates.append("name = %s")
        params.append(name)
    if description is not None:
        updates.append("description = %s")
        params.append(description)
    if rental_price_per_day is not None:
        updates.append("rental_price_per_day = %s")
        params.append(rental_price_per_day)
    if is_available is not None:
        updates.append("is_available = %s")
        params.append(is_available)
    if product_type:
        updates.append("product_type = %s")
        params.append(product_type)
    if serial_number:
        updates.append("serial_number = %s")
        params.append(serial_number)
    if location is not None:
        updates.append("location = %s")
        params.append(location)
    
    if not updates:
        cursor.close()
        conn.close()
        return jsonify({'message': 'No fields to update'}), 400
    
    params.append(panel_id)
    query = f"UPDATE solar_panels SET {', '.join(updates)} WHERE id = %s"
    
    try:
        cursor.execute(query, params)
        conn.commit()
    except IntegrityError as e:
        cursor.close()
        conn.close()
        if 'unique_serial_number' in str(e):
            return jsonify({'message': 'Serial number already exists'}), 400
        raise e
    finally:
        cursor.close()
        conn.close()
    
    return jsonify({'message': 'Power Source updated successfully'}), 200

@app.route('/solar-panels/<int:panel_id>', methods=['DELETE'])
@jwt_required()
def delete_solar_panel(panel_id):
    user_id = get_jwt_identity()
    if not is_user_subscribed(user_id):
        return jsonify({'message': 'Subscription required to delete Power Source'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT owner_id FROM solar_panels WHERE id = %s",
        (panel_id,)
    )
    panel = cursor.fetchone()
    
    if not panel:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Power Source not found'}), 404
    
    if panel['owner_id'] != int(user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Unauthorized to delete this Power Source'}), 403
    
    cursor.execute(
        "SELECT id FROM rentals WHERE solar_panel_id = %s AND status = %s",
        (panel_id, 'active')
    )
    active_rental = cursor.fetchone()
    
    if active_rental:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Cannot delete Power Source with active rental'}), 400
    
    cursor.execute("DELETE FROM solar_panels WHERE id = %s", (panel_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Power source deleted successfully'}), 200

@app.route('/rentals', methods=['POST'])
@jwt_required()
def rent_solar_panel():
    user_id = get_jwt_identity()
    data = request.get_json()
    solar_panel_id = data.get('solar_panel_id')
    
    if not solar_panel_id or not isinstance(solar_panel_id, int):
        return jsonify({'message': 'Valid solar_panel_id required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT is_available, owner_id FROM solar_panels WHERE id = %s",
        (solar_panel_id,)
    )
    panel = cursor.fetchone()
    
    if not panel:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Power Source not found'}), 404
    
    if not panel['is_available']:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Power Source not available'}), 400
    
    if panel['owner_id'] == int(user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Cannot rent your own Power Source'}), 400
    
    cursor.execute(
        "INSERT INTO rentals (user_id, solar_panel_id) VALUES (%s, %s) RETURNING id",
        (user_id, solar_panel_id)
    )
    rental_id = cursor.fetchone()['id']
    cursor.execute(
        "UPDATE solar_panels SET is_available = FALSE WHERE id = %s",
        (solar_panel_id,)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Power Source rented successfully', 'rental_id': rental_id}), 201

@app.route('/rentals', methods=['GET'])
@jwt_required()
def list_rentals():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT r.id, r.solar_panel_id, r.rental_start_date, r.status, sp.name, sp.rental_price_per_day, "
        "sp.product_type, sp.serial_number, sp.location "
        "FROM rentals r JOIN solar_panels sp ON r.solar_panel_id = sp.id "
        "WHERE r.user_id = %s",
        (user_id,)
    )
    rentals = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([
        {
            'id': rental['id'],
            'solar_panel_id': rental['solar_panel_id'],
            'name': rental['name'],
            'rental_price_per_day': float(rental['rental_price_per_day']),
            'rental_start_date': rental['rental_start_date'].isoformat(),
            'status': rental['status'],
            'product_type': rental['product_type'],
            'serial_number': rental['serial_number'],
            'location': rental['location']
        } for rental in rentals
    ]), 200
    
@app.route('/rentals/<int:rental_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_rental(rental_id):
    user_id = get_jwt_identity()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT user_id, solar_panel_id, status FROM rentals WHERE id = %s",
        (rental_id,)
    )
    rental = cursor.fetchone()
    
    if not rental:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Rental not found'}), 404
    
    if rental['user_id'] != int(user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Unauthorized to cancel this rental'}), 403
    
    if rental['status'] != 'active':
        cursor.close()
        conn.close()
        return jsonify({'message': f'Cannot cancel a rental with status: {rental["status"]}'}), 400
    
    cursor.execute(
        "UPDATE rentals SET status = 'canceled' WHERE id = %s",
        (rental_id,)
    )
    
    cursor.execute(
        "UPDATE solar_panels SET is_available = TRUE WHERE id = %s",
        (rental['solar_panel_id'],)
    )
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Rental canceled successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True)