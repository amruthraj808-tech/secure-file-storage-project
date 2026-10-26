#!/usr/bin/env python3
"""
Flask API Backend for Hybrid Cryptographic Secure Cloud File Storage System
"""

import sys
import os
import logging
import functools
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.backend.coordinator import BackendCoordinator, BackendCoordinatorError
from src.config import Config
from src.auth.auth_db import AuthDB, AuthError

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Initialize backend coordinator
coordinator = BackendCoordinator()

# Initialise SQLite3 auth database
AuthDB.init_db()

# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------

def require_auth(f):
    """Decorator: reject requests that don't carry a valid Bearer token."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        token = auth_header[7:]  # strip 'Bearer '
        user = AuthDB.get_user_from_token(token)
        if user is None:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        # Make user available to the route via Flask g
        request.current_user = user
        return f(*args, **kwargs)
    return wrapper

@app.route('/api/health', methods=['GET'])
def health_check():
    """Get system health status."""
    try:
        health = coordinator.validate_system_health()
        stats = coordinator.get_system_statistics()
        
        cloud_config = Config.get_storage_config()
        
        return jsonify({
            'status': 'success',
            'health': health,
            'statistics': stats,
            'cloud_config': {
                'mode': 'aws_s3',
                'bucket_name': cloud_config.get('bucket_name', 'N/A')
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/files', methods=['GET'])
@require_auth
def list_files():
    """Get list of uploaded files."""
    try:
        files = coordinator.list_files()
        return jsonify({
            'status': 'success',
            'files': files
        })
    except BackendCoordinatorError as e:
        logger.error(f"Failed to list files: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload and encrypt a file."""
    try:
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        sensitivity_level = request.form.get('sensitivity', 'medium')
        
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No file selected'
            }), 400
        
        if sensitivity_level not in ['low', 'medium', 'high']:
            return jsonify({
                'status': 'error',
                'message': 'Invalid sensitivity level'
            }), 400
        
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        file_bytes = file.read()
        
        if len(file_bytes) > Config.MAX_FILE_SIZE_BYTES:
            return jsonify({
                'status': 'error',
                'message': f'File size exceeds maximum limit of {Config.MAX_FILE_SIZE_MB}MB'
            }), 400
        
        result = coordinator.process_file_upload(file_bytes, filename, sensitivity_level)
        
        return jsonify({
            'status': 'success',
            'message': 'File uploaded and encrypted successfully',
            'data': result
        })
        
    except BackendCoordinatorError as e:
        logger.error(f"Upload failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    except Exception as e:
        logger.error(f"Unexpected upload error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/api/retrieve', methods=['POST'])
@require_auth
def retrieve_file():
    """Retrieve and decrypt a file."""
    try:
        data = request.get_json()
        
        if not data or 'file_id' not in data:
            return jsonify({
                'status': 'error',
                'message': 'File ID is required'
            }), 400
        
        file_id = data['file_id']
        result = coordinator.download_and_decrypt_file(file_id)
        
        if result['success']:
            file_data_b64 = base64.b64encode(result['file_data']).decode('utf-8')
            
            filename = result['original_filename'].lower()
            is_image = any(filename.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'])
            
            return jsonify({
                'status': 'success',
                'message': 'File retrieved and decrypted successfully',
                'data': {
                    'file_id': result['file_id'],
                    'original_filename': result['original_filename'],
                    'file_data': file_data_b64,
                    'file_size_bytes': result['file_size_bytes'],
                    'encryption_algorithm': result['encryption_algorithm'],
                    'sensitivity_level': result['sensitivity_level'],
                    'is_image': is_image,
                    'checksum_verified': result['checksum_verified']
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to retrieve file'
            }), 500
            
    except BackendCoordinatorError as e:
        logger.error(f"Retrieval failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    except Exception as e:
        logger.error(f"Unexpected retrieval error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred'
        }), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404


# ------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user account."""
    data = request.get_json(force=True) or {}
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    try:
        user = AuthDB.create_user(username, email, password)
        token = AuthDB.generate_token(user['id'])
        return jsonify({
            'status': 'success',
            'message': 'Account created successfully',
            'token': token,
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}
        })
    except AuthError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f'Register error: {e}')
        return jsonify({'status': 'error', 'message': 'Registration failed'}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Log in with username + password, receive a session token."""
    data = request.get_json(force=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    try:
        user = AuthDB.verify_login(username, password)
        token = AuthDB.generate_token(user['id'])
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'token': token,
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}
        })
    except AuthError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 401
    except Exception as e:
        logger.error(f'Login error: {e}')
        return jsonify({'status': 'error', 'message': 'Login failed'}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Revoke the current session token."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        AuthDB.revoke_token(auth_header[7:])
    return jsonify({'status': 'success', 'message': 'Logged out'})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    """Return the current authenticated user's info."""
    return jsonify({'status': 'success', 'user': request.current_user})

@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

if __name__ == '__main__':
    Config.ensure_directories_exist()
    logger.info("Starting Hybrid Cryptographic Secure Cloud File Storage API")
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_FILE_SIZE_BYTES
    
    app.run(
        host='0.0.0.0',
        port=5002,
        debug=True,
        threaded=True,
        # Restrict reloader to project source only (avoids scanning all site-packages)
        extra_files=None,
        reloader_type='stat',
        use_reloader=True,
        reloader_interval=1,
    )