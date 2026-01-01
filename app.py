from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

# 1. Configuración de la App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_super_secreta_aura' # Cambia esto en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aura.db' # Usamos un solo archivo DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 2. Inicialización de extensiones
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# 3. MODELOS DE BASE DE DATOS

# Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Aquí podríamos añadir una relación con los grupos en el futuro

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo de Grupo (NUEVO: Integrado con SQLAlchemy)
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    # Por ahora guardamos los miembros como texto simple, luego lo mejoraremos
    members = db.Column(db.Text, default="") 

# 4. Helpers (Funciones de ayuda)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_group_code():
    """Genera un código aleatorio tipo 'X7Z9A'"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(6))

# --- RUTAS DE VISTAS (HTML) ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html') # Asumiendo que index.html es la portada

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Nota: Asegúrate de que los inputs de tu register.html tengan name="username" y name="password"
        # Si usas JSON desde JS, esto cambiaría, pero asumo formulario estándar por ahora.
        # Si tu register.html usa fetch/JSON, avísame para ajustar esto.
        # Asumiendo formulario HTML clásico:
        username = request.form.get('username') 
        password = request.form.get('password')

        # Si tu formulario usa fetch/JSON como en el dashboard, usa esto:
        if not username: 
             data = request.get_json()
             if data:
                 username = data.get('username')
                 password = data.get('password')

        user_exists = User.query.filter_by(username=username).first()
        
        if user_exists:
            flash('El usuario ya existe.', 'error')
        elif not username or not password:
            flash('Rellena todos los campos.', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Cuenta creada. Inicia sesión.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Compatibilidad si envías JSON
        if not username and request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Datos incorrectos.', 'error')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- RUTAS DE API (LÓGICA AURA) ---

@app.route('/create_group', methods=['POST'])
@login_required # Solo usuarios logueados pueden crear grupos
def create_group():
    data = request.get_json()
    group_name = data.get('name')
    
    if not group_name:
        return jsonify({'success': False, 'message': 'Falta el nombre'})

    # Generamos código único
    code = generate_group_code()
    
    # Nos aseguramos de que el código no exista ya (aunque es improbable)
    while Group.query.filter_by(code=code).first():
        code = generate_group_code()
    
    try:
        # CREACIÓN USANDO SQLALCHEMY (Mucho más limpio)
        new_group = Group(name=group_name, code=code, members=current_user.username)
        db.session.add(new_group)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'GRUPO CREADO!', 
            'code': code
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    data = request.get_json()
    code = data.get('code')
    
    if not code:
        return jsonify({'success': False, 'message': 'Falta el código'})

    group = Group.query.filter_by(code=code).first()
    
    if group:
        # Aquí lógica simple para añadir usuario a la cadena de texto
        # En el futuro haremos una tabla de relación real
        if current_user.username not in group.members:
            group.members += f",{current_user.username}"
            db.session.commit()
            return jsonify({'success': True, 'message': f'Te has unido a {group.name}'})
        else:
            return jsonify({'success': False, 'message': 'Ya estás en este grupo'})
    else:
        return jsonify({'success': False, 'message': 'El grupo no existe'})

# Inicializar DB al arrancar
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Esto creará las tablas 'user' y 'group' en aura.db
    print("--- AURA SYSTEM ONLINE (CON SQLALCHEMY) ---")
    app.run(debug=True)