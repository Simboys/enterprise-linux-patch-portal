from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import hashlib
import subprocess
import json
from datetime import datetime
import re

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://patchuser:secure_password@db:5432/patchportal')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/data/uploads'
app.config['REPOSITORY_FOLDER'] = '/data/repository'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max

db = SQLAlchemy(app)

# Database Models
class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(100), nullable=False)
    architecture = db.Column(db.String(50), nullable=False)
    os_version = db.Column(db.String(50), nullable=False)
    advisory = db.Column(db.String(100))
    release_date = db.Column(db.DateTime)
    severity = db.Column(db.String(20))
    size = db.Column(db.String(50))
    sha256 = db.Column(db.String(64))
    file_path = db.Column(db.String(500))
    package_type = db.Column(db.String(10))  # rpm or deb
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True, nullable=False)
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(200))
    description = db.Column(db.Text)
    published_date = db.Column(db.DateTime)
    severity = db.Column(db.String(20))
    
class PackageCVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'))
    cve_id = db.Column(db.Integer, db.ForeignKey('cve.id'))
    
class Dependency(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'))
    dependency_name = db.Column(db.String(255))
    dependency_version = db.Column(db.String(100))

# Helper Functions
def calculate_sha256(file_path):
    """Calculate SHA256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def validate_rpm(file_path):
    """Validate RPM package and extract metadata"""
    try:
        # Check RPM signature
        result = subprocess.run(
            ['rpm', '-K', file_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return None, "Invalid RPM signature"
        
        # Extract metadata
        query_format = '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SIZE}|%{SUMMARY}'
        result = subprocess.run(
            ['rpm', '-qp', '--queryformat', query_format, file_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return None, "Failed to extract RPM metadata"
        
        parts = result.stdout.strip().split('|')
        metadata = {
            'name': parts[0],
            'version': parts[1],
            'architecture': parts[2],
            'size': f"{int(parts[3]) / (1024 * 1024):.2f} MB",
            'summary': parts[4]
        }
        
        # Extract dependencies
        dep_result = subprocess.run(
            ['rpm', '-qpR', file_path],
            capture_output=True,
            text=True
        )
        
        dependencies = []
        if dep_result.returncode == 0:
            for line in dep_result.stdout.strip().split('\n'):
                if line and not line.startswith('rpmlib'):
                    dependencies.append(line.strip())
        
        metadata['dependencies'] = dependencies[:10]  # Limit to first 10
        
        return metadata, None
        
    except Exception as e:
        return None, str(e)

def validate_deb(file_path):
    """Validate DEB package and extract metadata"""
    try:
        # Extract control file
        result = subprocess.run(
            ['dpkg-deb', '-f', file_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return None, "Invalid DEB package"
        
        metadata = {}
        dependencies = []
        
        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'Package':
                    metadata['name'] = value
                elif key == 'Version':
                    metadata['version'] = value
                elif key == 'Architecture':
                    metadata['architecture'] = value
                elif key == 'Description':
                    metadata['summary'] = value
                elif key == 'Depends':
                    dependencies = [d.strip().split()[0] for d in value.split(',')]
        
        # Get package size
        result = subprocess.run(
            ['dpkg-deb', '-I', file_path],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.split('\n'):
            if 'size' in line.lower():
                try:
                    size_bytes = int(re.search(r'\d+', line).group())
                    metadata['size'] = f"{size_bytes / (1024 * 1024):.2f} MB"
                except:
                    metadata['size'] = "Unknown"
                break
        
        metadata['dependencies'] = dependencies[:10]
        
        return metadata, None
        
    except Exception as e:
        return None, str(e)

# API Routes
@app.route('/api/packages', methods=['GET'])
def get_packages():
    """Get all packages with optional filtering"""
    os_version = request.args.get('os_version', 'ol8.10')
    severity = request.args.get('severity')
    search = request.args.get('search', '')
    
    query = Package.query.filter_by(os_version=os_version)
    
    if severity and severity != 'all':
        query = query.filter_by(severity=severity)
    
    if search:
        query = query.filter(
            db.or_(
                Package.name.ilike(f'%{search}%'),
                Package.advisory.ilike(f'%{search}%')
            )
        )
    
    packages = query.all()
    
    result = []
    for pkg in packages:
        # Get associated CVEs
        cves = db.session.query(CVE).join(PackageCVE).filter(
            PackageCVE.package_id == pkg.id
        ).all()
        
        # Get dependencies
        deps = Dependency.query.filter_by(package_id=pkg.id).all()
        
        result.append({
            'id': pkg.id,
            'name': pkg.name,
            'version': pkg.version,
            'arch': pkg.architecture,
            'size': pkg.size,
            'advisory': pkg.advisory,
            'releaseDate': pkg.release_date.isoformat() if pkg.release_date else None,
            'severity': pkg.severity,
            'sha256': pkg.sha256,
            'cves': [{
                'id': cve.cve_id,
                'score': cve.cvss_score,
                'vector': cve.cvss_vector,
                'description': cve.description,
                'published': cve.published_date.isoformat() if cve.published_date else None
            } for cve in cves],
            'dependencies': [dep.dependency_name for dep in deps]
        })
    
    return jsonify(result)

@app.route('/api/upload', methods=['POST'])
def upload_package():
    """Upload and validate a package"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file extension
    allowed_extensions = {'.rpm', '.deb'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        return jsonify({'error': 'Invalid file type. Only .rpm and .deb allowed'}), 400
    
    # Secure filename and save
    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(upload_path)
    
    try:
        # Calculate checksum
        sha256 = calculate_sha256(upload_path)
        
        # Validate and extract metadata based on type
        if file_ext == '.rpm':
            metadata, error = validate_rpm(upload_path)
            package_type = 'rpm'
        else:
            metadata, error = validate_deb(upload_path)
            package_type = 'deb'
        
        if error:
            os.remove(upload_path)
            return jsonify({'error': error}), 400
        
        # Move to repository
        repo_path = os.path.join(app.config['REPOSITORY_FOLDER'], filename)
        os.makedirs(app.config['REPOSITORY_FOLDER'], exist_ok=True)
        os.rename(upload_path, repo_path)
        
        # Save to database
        package = Package(
            name=metadata['name'],
            version=metadata['version'],
            architecture=metadata['architecture'],
            os_version=request.form.get('os_version', 'ol8.10'),
            size=metadata['size'],
            sha256=sha256,
            file_path=repo_path,
            package_type=package_type,
            severity='Moderate'  # Default, can be updated later
        )
        
        db.session.add(package)
        db.session.commit()
        
        # Save dependencies
        for dep in metadata.get('dependencies', []):
            dependency = Dependency(
                package_id=package.id,
                dependency_name=dep
            )
            db.session.add(dependency)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'package': {
                'id': package.id,
                'name': package.name,
                'version': package.version,
                'sha256': sha256
            }
        })
        
    except Exception as e:
        if os.path.exists(upload_path):
            os.remove(upload_path)
        return jsonify({'error': str(e)}), 500

@app.route('/api/bundle', methods=['POST'])
def create_bundle():
    """Create offline installation bundle"""
    data = request.get_json()
    package_ids = data.get('package_ids', [])
    
    if not package_ids:
        return jsonify({'error': 'No packages selected'}), 400
    
    packages = Package.query.filter(Package.id.in_(package_ids)).all()
    
    manifest = {
        'metadata': {
            'generatedAt': datetime.utcnow().isoformat(),
            'osVersion': data.get('os_version', 'ol8.10'),
            'totalPackages': len(packages),
            'generator': 'Enterprise Linux Patch Portal v1.0'
        },
        'packages': []
    }
    
    for pkg in packages:
        cves = db.session.query(CVE).join(PackageCVE).filter(
            PackageCVE.package_id == pkg.id
        ).all()
        
        deps = Dependency.query.filter_by(package_id=pkg.id).all()
        
        manifest['packages'].append({
            'name': pkg.name,
            'version': pkg.version,
            'architecture': pkg.architecture,
            'advisory': pkg.advisory,
            'size': pkg.size,
            'sha256': pkg.sha256,
            'downloadUrl': f'/api/download/{pkg.id}',
            'dependencies': [dep.dependency_name for dep in deps],
            'cves': [{
                'id': cve.cve_id,
                'cvssScore': cve.cvss_score,
                'cvssVector': cve.cvss_vector,
                'description': cve.description
            } for cve in cves]
        })
    
    manifest['installationInstructions'] = {
        'offline': [
            "1. Extract the bundle: tar -xzf patch-bundle.tar.gz",
            "2. Navigate to directory: cd patch-bundle",
            "3. Verify checksums: sha256sum -c checksums.txt",
            "4. Install packages: sudo rpm -Uvh *.rpm (or sudo dpkg -i *.deb)",
            "5. Verify installation: rpm -qa | grep -f package-list.txt"
        ]
    }
    
    return jsonify(manifest)

@app.route('/api/download/<int:package_id>', methods=['GET'])
def download_package(package_id):
    """Download a specific package"""
    package = Package.query.get_or_404(package_id)
    
    if not os.path.exists(package.file_path):
        return jsonify({'error': 'Package file not found'}), 404
    
    return send_file(
        package.file_path,
        as_attachment=True,
        download_name=f"{package.name}-{package.version}.{package.architecture}.{package.package_type}"
    )

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get portal statistics"""
    os_version = request.args.get('os_version', 'ol8.10')
    
    total = Package.query.filter_by(os_version=os_version).count()
    critical = Package.query.filter_by(os_version=os_version, severity='Critical').count()
    important = Package.query.filter_by(os_version=os_version, severity='Important').count()
    moderate = Package.query.filter_by(os_version=os_version, severity='Moderate').count()
    
    return jsonify({
        'total': total,
        'critical': critical,
        'important': important,
        'moderate': moderate
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'database': 'connected'})
    except:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
```

**File: `backend/requirements.txt`**
```
Flask==3.0.0
Flask-CORS==4.0.0
Flask-SQLAlchemy==3.1.1
psycopg2-binary==2.9.9
werkzeug==3.0.1
requests==2.31.0
celery==5.3.4
redis==5.0.1
python-dotenv==1.0.0
