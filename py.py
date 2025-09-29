from flask import Flask, send_from_directory, abort, request, Response, session, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from waitress import serve
import os
from dotenv import load_dotenv
import openai
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
PORT = 3003
# The directory where this script and the static files are located.
# os.path.dirname is a common way to get this.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure Poe API client and key rotation
POE_API_KEYS_STR = os.getenv("POE_API_KEYS")
if not POE_API_KEYS_STR:
    raise ValueError("POE_API_KEYS environment variable not set or empty.")
POE_API_KEYS = [key.strip() for key in POE_API_KEYS_STR.split(',')]
current_key_index = 0

client = openai.OpenAI(
    api_key=POE_API_KEYS[current_key_index],
    base_url="https://api.poe.com/v1",
)

# Create a Flask app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "a_super_secret_key_for_development")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    custom_instructions = db.Column(db.Text, nullable=True)
    custom_instructions_enabled = db.Column(db.Boolean, nullable=False, default=True)
    memories = db.relationship('Memory', backref='user', lazy=True, cascade="all, delete-orphan")
    chats = db.relationship('Chat', backref='user', lazy=True, cascade="all, delete-orphan")

class Memory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # UUID used for public shareable chat URLs (e.g. /c/<uuid>)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='chat', lazy=True, cascade="all, delete-orphan")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False) # 'user' or 'assistant'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()
    # Ensure the `uuid` column exists in the DB and backfill values if needed.
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        table_names = inspector.get_table_names()
        if 'chat' in table_names:
            cols = [c['name'] for c in inspector.get_columns('chat')]
            if 'uuid' not in cols:
                # SQLite supports ADD COLUMN; add uuid column allowing NULLs first
                try:
                    with db.engine.connect() as conn:
                        conn.execute(text('ALTER TABLE chat ADD COLUMN uuid VARCHAR(36)'))
                        conn.commit()
                except Exception as inner_e:
                    print(f"Failed to add 'uuid' column to chat table: {inner_e}")
            # Backfill any missing uuids
            chats_missing_uuid = Chat.query.filter((Chat.uuid == None) | (Chat.uuid == '')).all()
            for ch in chats_missing_uuid:
                ch.uuid = str(uuid.uuid4())
            if chats_missing_uuid:
                db.session.commit()
    except Exception as e:
        # Migration failed or inspector not available; print and continue. This avoids crashing the server.
        print(f"UUID migration/population skipped or failed: {e}")

# --- Auth Routes ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"message": "Missing name, email, or password"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 400

    new_user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password)
    )
    db.session.add(new_user)
    db.session.commit()
    
    session['user_email'] = email
    
    return jsonify({"user": {"name": name, "email": email}}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401
    
    session['user_email'] = email
    
    return jsonify({"user": {"name": user.name, "email": user.email}})

@app.route('/signout', methods=['POST'])
def signout():
    session.pop('user_email', None)
    return jsonify({"message": "Signed out"}), 200

@app.route('/check_auth')
def check_auth():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401
    
    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None) # Clean up invalid session
        return jsonify({"message": "User not found"}), 401

    return jsonify({"name": user.name, "email": user.email})

@app.route('/instructions', methods=['GET', 'POST'])
def handle_instructions():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401
    
    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None)
        return jsonify({"message": "User not found"}), 401

    if request.method == 'GET':
        return jsonify({
            "instructions": user.custom_instructions or "",
            "enabled": user.custom_instructions_enabled
        })

    if request.method == 'POST':
        data = request.get_json()
        instructions = data.get('instructions', '')
        enabled = data.get('enabled', True)

        if len(instructions) > 1500:
            return jsonify({"message": "Instructions cannot exceed 1500 characters."}), 400
        
        user.custom_instructions = instructions
        user.custom_instructions_enabled = enabled
        db.session.commit()
        return jsonify({"message": "Instructions saved successfully."}), 200


@app.route('/change_name', methods=['POST'])
def change_name():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401
    
    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None)
        return jsonify({"message": "User not found"}), 401

    data = request.get_json()
    new_name = data.get('name', '').strip()

    if not new_name:
        return jsonify({"message": "Name cannot be empty."}), 400
    if len(new_name) > 150:
         return jsonify({"message": "Name is too long."}), 400

    user.name = new_name
    db.session.commit()
    return jsonify({"message": "Name changed successfully.", "name": user.name}), 200


@app.route('/delete_all_chats', methods=['POST'])
def delete_all_chats():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401
    
    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None)
        return jsonify({"message": "User not found"}), 401
    
    Chat.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    
    return jsonify({"message": "All chats deleted successfully."}), 200


# --- Saved Memory Routes ---
@app.route('/memories', methods=['GET'])
def get_memories():
    user_email = session.get('user_email')
    if not user_email: return jsonify({"message": "Not authenticated"}), 401
    user = User.query.filter_by(email=user_email).first()
    if not user: return jsonify({"message": "User not found"}), 401
    
    memories = Memory.query.filter_by(user_id=user.id).order_by(Memory.created_at.asc()).all()
    return jsonify([{'id': mem.id, 'content': mem.content} for mem in memories])

@app.route('/memories', methods=['POST'])
def add_memory():
    user_email = session.get('user_email')
    if not user_email: return jsonify({"message": "Not authenticated"}), 401
    user = User.query.filter_by(email=user_email).first()
    if not user: return jsonify({"message": "User not found"}), 401
    
    data = request.get_json()
    content = data.get('content', '').strip()

    if not content: return jsonify({"message": "Memory content cannot be empty."}), 400
    if len(content) > 500: return jsonify({"message": "Memory cannot exceed 500 characters."}), 400
    
    if Memory.query.filter_by(user_id=user.id).count() >= 250:
        return jsonify({"message": "Memory limit of 250 reached."}), 400

    new_memory = Memory(user_id=user.id, content=content)
    db.session.add(new_memory)
    db.session.commit()
    
    return jsonify({"message": "Memory saved.", "memory": {"id": new_memory.id, "content": new_memory.content}}), 201

@app.route('/memories/<int:memory_id>', methods=['DELETE'])
def delete_memory(memory_id):
    user_email = session.get('user_email')
    if not user_email: return jsonify({"message": "Not authenticated"}), 401
    user = User.query.filter_by(email=user_email).first()
    if not user: return jsonify({"message": "User not found"}), 401

    memory = db.session.get(Memory, memory_id)
    if not memory or memory.user_id != user.id:
        return jsonify({"message": "Memory not found or access denied."}), 404
        
    db.session.delete(memory)
    db.session.commit()
    return jsonify({"message": "Memory deleted successfully."}), 200

@app.route('/memories/all', methods=['DELETE'])
def delete_all_memories():
    user_email = session.get('user_email')
    if not user_email: return jsonify({"message": "Not authenticated"}), 401
    user = User.query.filter_by(email=user_email).first()
    if not user: return jsonify({"message": "User not found"}), 401
    
    Memory.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    
    return jsonify({"message": "All memories deleted successfully."}), 200


# --- Routing ---

# Serve index.html for both '/' and '/index.html'
@app.route('/')
@app.route('/index.html')
def serve_index():
    try:
        # Flask's send_from_directory is secure and handles headers correctly
        return send_from_directory(BASE_DIR, 'index.html')
    except FileNotFoundError:
        # Abort with a 500 error if the file is missing
        print(f"Server Error: Could not find 'index.html' in {BASE_DIR}")
        abort(500, "Server Error: Could not read the HTML file.")

# Serve the favicon
@app.route('/gpt.ico')
def serve_favicon():
    # By default, send_from_directory sends a 404 if the file isn't found
    return send_from_directory(BASE_DIR, 'gpt.ico', mimetype='image/vnd.microsoft.icon')

# --- API Route for Model Name ---
@app.route('/model')
def get_model_name():
    # The default model is gpt-4o, its display name is 4o.
    return {"model": "4o"}

# --- API Route for Chat ---
@app.route('/history')
def get_history():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify([]), 401
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify([]), 401
    
    chats = Chat.query.filter_by(user_id=user.id).order_by(Chat.created_at.desc()).all()
    # Include UUID so frontend can build links like /c/<uuid>
    return jsonify([{'id': chat.id, 'uuid': chat.uuid, 'title': chat.title} for chat in chats])

@app.route('/chat/<int:chat_id>')
def serve_chat_page(chat_id):
    """
    Serve the single-page app for a specific chat URL. The actual chat messages
    are available from the API endpoint `/api/chat/<id>` which enforces
    authentication and access control. Serving the HTML here allows deep-links
    like `/chat/123` to load the app; the API will still prevent unauthorized
    access to the chat data.
    """
    # If we can resolve a UUID for this numeric chat id, redirect to the nicer /c/<uuid> URL
    chat = db.session.get(Chat, chat_id)
    if chat and chat.uuid:
        return redirect(url_for('serve_chat_by_uuid', chat_uuid=chat.uuid))

    # Fallback: serve the SPA (legacy behavior)
    try:
        return send_from_directory(BASE_DIR, 'index.html')
    except FileNotFoundError:
        print(f"Server Error: Could not find 'index.html' in {BASE_DIR}")
        abort(500, "Server Error: Could not read the HTML file.")


# New, user-facing route that mirrors ChatGPT-style short links: /c/<uuid>
@app.route('/c/<chat_uuid>')
def serve_chat_by_uuid(chat_uuid: str):
    # The SPA is the same; the API endpoint will use the uuid to fetch messages.
    try:
        return send_from_directory(BASE_DIR, 'index.html')
    except FileNotFoundError:
        print(f"Server Error: Could not find 'index.html' in {BASE_DIR}")
        abort(500, "Server Error: Could not read the HTML file.")


@app.route('/api/chat/<int:chat_id>')
def get_chat_messages(chat_id):
    """
    API endpoint that returns chat messages JSON for the authenticated user.
    This endpoint enforces authentication and ownership checks so only the
    chat owner can read their messages.
    """
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401
    
    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None)
        return jsonify({"message": "User not found"}), 401

    chat = db.session.get(Chat, chat_id)
    if not chat or chat.user_id != user.id:
        return jsonify({"message": "Chat not found or access denied"}), 404
        
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp.asc()).all()
    return jsonify([{'role': msg.role, 'content': msg.content} for msg in messages])


# New API endpoint that accepts the chat UUID instead of numeric id.
@app.route('/api/chat/uuid/<chat_uuid>')
def get_chat_messages_by_uuid(chat_uuid: str):
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({"message": "Not authenticated"}), 401

    user = User.query.filter_by(email=user_email).first()
    if not user:
        session.pop('user_email', None)
        return jsonify({"message": "User not found"}), 401

    chat = Chat.query.filter_by(uuid=chat_uuid).first()
    if not chat or chat.user_id != user.id:
        return jsonify({"message": "Chat not found or access denied"}), 404

    messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp.asc()).all()
    return jsonify([{'role': msg.role, 'content': msg.content} for msg in messages])


# Backwards-compatibility: redirect old numeric API to the new UUID-based API when possible
@app.route('/api/chat/redirect/<int:chat_id>')
def redirect_api_chat_numeric(chat_id):
    chat = db.session.get(Chat, chat_id)
    if not chat:
        return jsonify({"message": "Chat not found"}), 404
    return redirect(url_for('get_chat_messages_by_uuid', chat_uuid=chat.uuid))


@app.route('/chat', methods=['POST'])
def chat():
    user_email = session.get('user_email')
    if not user_email:
        return "Unauthorized", 401
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return "Unauthorized", 401

    messages_json = request.form.get('messages')
    if not messages_json:
        return "No messages provided.", 400
    
    try:
        api_messages = json.loads(messages_json)
        if not isinstance(api_messages, list) or not all(isinstance(m, dict) for m in api_messages):
            raise ValueError("Messages must be a list of dicts.")
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Invalid messages format: {e}")
        return "Invalid JSON in messages field.", 400

    system_content_parts = []
    
    is_temporary_str = request.form.get('is_temporary', 'false')
    is_temporary = is_temporary_str.lower() == 'true'

    if not is_temporary:
        # Add saved memories
        memories = Memory.query.filter_by(user_id=user.id).order_by(Memory.created_at.asc()).all()
        if memories:
            memories_text = "\n".join([f"- {mem.content}" for mem in memories])
            system_content_parts.append(f"Persistent context — integrate the following memories into reasoning and responses without restating unless explicitly asked:\n{memories_text}")

        # Add custom instructions
        if user.custom_instructions and user.custom_instructions_enabled:
            system_content_parts.append(f"Mandatory behavioral directives — incorporate the following instructions into all reasoning and responses without omission:\n{user.custom_instructions}")
        
    if system_content_parts:
        system_prompt = {"role": "system", "content": "\n\n".join(system_content_parts)}
        api_messages.insert(0, system_prompt)

    model_name = request.form.get('model', 'gpt-4o')
    if model_name == 'gpt-4o':
        model_name = 'ChatGPT-4o-Latest'
    chat_id_str = request.form.get('chat_id')
    chat_uuid_str = request.form.get('chat_uuid')
    chat_id = int(chat_id_str) if chat_id_str and chat_id_str != 'null' else None
    user_message_content = api_messages[-1]['content'] if api_messages else ''

    # Handle file upload
    if 'attachment' in request.files:
        file = request.files['attachment']
        if file.filename != '':
            print(f"Received file: {file.filename}")

    def generate_and_save():
        with app.app_context():
            global current_key_index
            
            chat_session = None
            if not is_temporary:
                # Support lookup by numeric id (legacy) or by UUID (preferred for shareable links)
                if chat_uuid_str:
                    chat_session = Chat.query.filter_by(uuid=chat_uuid_str).first()
                    if not chat_session or chat_session.user_id != user.id:
                        yield "Error: Chat not found or access denied."
                        return
                elif chat_id:
                    chat_session = db.session.get(Chat, chat_id)
                    if not chat_session or chat_session.user_id != user.id:
                        yield "Error: Chat not found or access denied."
                        return
                else:
                    title = (user_message_content[:50] + '...') if len(user_message_content) > 50 else user_message_content
                    chat_session = Chat(title=title, user_id=user.id)
                    db.session.add(chat_session)
                    db.session.commit()
                    # Provide both numeric id and uuid for backward compatibility on the frontend
                    yield f"new_chat_id:{chat_session.id}\n"
                    yield f"new_chat_uuid:{chat_session.uuid}\n"
                    yield f"chat_title:{chat_session.title}\n"

                user_msg = Message(role='user', content=user_message_content, chat_id=chat_session.id)
                db.session.add(user_msg)
                db.session.commit()

            full_response_content = []
            for _ in range(len(POE_API_KEYS)):
                try:
                    key_to_use = POE_API_KEYS[current_key_index]
                    client.api_key = key_to_use
                    print(f"Attempting to use API key index {current_key_index}...")

                    stream = client.chat.completions.create(
                        model=model_name,
                        messages=api_messages,
                        stream=True
                    )
                    
                    for chunk in stream:
                        content = chunk.choices[0].delta.content
                        if content:
                            full_response_content.append(content)
                            yield content
                    
                    final_response = "".join(full_response_content)
                    if final_response and not is_temporary:
                        assistant_msg = Message(role='assistant', content=final_response, chat_id=chat_session.id)
                        db.session.add(assistant_msg)
                        db.session.commit()
                    return 

                except Exception as e:
                    print(f"API key at index {current_key_index} failed. Error: {e}")
                    current_key_index = (current_key_index + 1) % len(POE_API_KEYS)
                    print(f"Rotated to key index {current_key_index}.")

            yield "Error: Could not get response from AI. All keys failed."

    return Response(generate_and_save(), mimetype='text/plain')

# Flask handles 404 errors automatically for undefined routes.

# --- Server Execution ---
if __name__ == '__main__':
    # Using Waitress, a production-grade WSGI server.
    # To run, first install it: pip install waitress
    serve(app, host='0.0.0.0', port=PORT)