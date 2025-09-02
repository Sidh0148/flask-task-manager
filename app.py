from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError

# ---------------------------
# App Config
# ---------------------------
app = Flask(__name__)

# MySQL Database URI → user:password@host/db_name
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://flaskuser:flaskpass@localhost/task_manager"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "supersecret"  # change this to a strong secret!

# Init extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ---------------------------
# Models
# ---------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.Enum("admin", "user", name="role_enum"), default="user")

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.Enum("pending", "in_progress", "done", name="status_enum"), default="pending")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))

# ---------------------------
# Routes
# ---------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Task Manager API is running!"})

# Register user
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    new_user = User(username=data["username"], password=hashed_pw, role="user")
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": f"User {data['username']} created successfully!"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 400

# Login -> returns JWT token
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=user.id)
        return jsonify({"token": access_token}), 200
    return jsonify({"error": "Invalid username or password"}), 401

# Add Task (protected route)
@app.route("/tasks", methods=["POST"])
@jwt_required()
def add_task():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_task = Task(title=data["title"], description=data.get("description"), user_id=user_id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task created!"}), 201

# Get all tasks (only for logged in user)
@app.route("/tasks", methods=["GET"])
@jwt_required()
def get_tasks():
    user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=user_id).all()
    return jsonify([
        {"id": t.id, "title": t.title, "description": t.description, "status": t.status, "user_id": t.user_id}
        for t in tasks
    ])

# Update Task
@app.route("/tasks/<int:task_id>", methods=["PUT"])
@jwt_required()
def update_task(task_id):
    user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json()
    task.title = data.get("title", task.title)
    task.description = data.get("description", task.description)
    task.status = data.get("status", task.status)
    db.session.commit()
    return jsonify({"message": "Task updated!"})

# Delete Task (role-based access)
@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@jwt_required()
def delete_task(task_id):
    user_id = get_jwt_identity()
    task = Task.query.get(task_id)

    if not task:
        return jsonify({"error": "Task not found"}), 404

    # If the user is an admin, they can delete any task
    # If the user is a regular user, they can only delete their own tasks
    current_user = User.query.get(user_id)
    if current_user.role == "admin" or task.user_id == user_id:
        db.session.delete(task)
        db.session.commit()
        return jsonify({"message": "Task deleted!"})
    
    return jsonify({"error": "You do not have permission to delete this task."}), 403

# ---------------------------
# Run App
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
