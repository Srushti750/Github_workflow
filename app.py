import os
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
from pathlib import Path
from bson import ObjectId
import shutil
import platform
from model_predictor import predict_vulnerability

load_dotenv()
app = Flask(__name__)

# MongoDB setup
client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017/"))
db = client.VulnerabilityDB

def cleanup_repo(path):
    """Remove cloned repository after scanning"""
    try:
        if platform.system() == 'Windows':
            subprocess.run(f"rd /s /q {path}", shell=True, timeout=10)
        else:
            subprocess.run(f"rm -rf {path}", shell=True, timeout=10)
    except Exception as e:
        print(f"Cleanup failed: {str(e)}")

def convert_objectid(obj):
    """Convert MongoDB ObjectId to string for JSON response"""
    if isinstance(obj, list):
        return [convert_objectid(o) for o in obj]
    elif isinstance(obj, dict):
        return {k: convert_objectid(v) for k, v in obj.items()}
    elif isinstance(obj, ObjectId):
        return str(obj)
    return obj

@app.route('/api/scan', methods=['POST', 'GET'])
def scan_repo():
    """Endpoint to scan a GitHub repository"""
    try:
        # Handle both POST and GET requests
        if request.method == 'POST':
            data = request.get_json()
            if not data or 'repo_url' not in data:
                return jsonify({"error": "Missing repo_url"}), 400
            repo_url = data['repo_url'].strip()
            mode = data.get('mode', 'sql')
        else:  # GET request
            repo_url = request.args.get('repo_url')
            if not repo_url:
                return jsonify({"error": "Missing repo_url parameter"}), 400
            mode = request.args.get('mode', 'sql')

        print(f"Scanning repository: {repo_url} for {mode} vulnerabilities")

        # Clone repository
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        clone_path = Path(f"temp_repos/{repo_name}")
        clone_path.mkdir(parents=True, exist_ok=True)

        # Authenticated cloning if credentials exist
        username = os.getenv("GITHUB_USERNAME")
        token = os.getenv("GITHUB_TOKEN")
        if username and token:
            repo_url = repo_url.replace("https://", f"https://{username}:{token}@")

        subprocess.run(["git", "clone", repo_url, str(clone_path)], check=True)

        # Scan files
        results = []
        for root, _, files in os.walk(clone_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                        result = predict_vulnerability(code, mode)
                        if result['is_vulnerable']:
                            results.append({
                                "repo_url": repo_url,
                                "file_path": str(Path(file_path).relative_to(clone_path)),
                                "vulnerability_type": result['type'],
                                "confidence": result['confidence'],
                                "detection_method": result.get('detection_method', 'model'),
                                "timestamp": datetime.now()
                            })

        # Store results
        if results:
            db.scan_results.insert_many(results)

        return jsonify({
            "status": "success",
            "results": convert_objectid(results),
            "metrics": {
                "files_scanned": len(results),
                "vulnerabilities_found": sum(1 for r in results)
            }
        })

    except subprocess.CalledProcessError:
        return jsonify({"error": "Failed to clone repository"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cleanup_repo(clone_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)