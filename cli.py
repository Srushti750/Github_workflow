#!/usr/bin/env python3
import requests
import sys
import json
import argparse
from model_predictor import predict_vulnerability
import os
from datetime import datetime

def scan_via_api(repo_url, mode='sql', api_url="http://localhost:5000/api/scan"):
    """Scan repository via Flask API"""
    try:
        payload = {"repo_url": repo_url, "mode": mode}
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}

def scan_locally(repo_path, mode='sql'):
    """Scan local repo directory without API"""
    results = []
    files_scanned = 0

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                files_scanned += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                        result = predict_vulnerability(code, mode)
                        if result['is_vulnerable']:
                            results.append({
                                "file_path": os.path.relpath(file_path, repo_path),
                                "vulnerability_type": result['type'],
                                "confidence": result['confidence'],
                                "detection_method": result.get('detection_method', 'model'),
                                "timestamp": datetime.now().isoformat()
                            })
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}", file=sys.stderr)

    return {
        "status": "success",
        "results": results,
        "metrics": {
            "files_scanned": files_scanned,
            "vulnerabilities_found": len(results)
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner CLI")
    parser.add_argument("repo_url", help="GitHub repository URL or local path")
    parser.add_argument("--mode", choices=['sql', 'command_injection'], default='sql',
                        help="Type of vulnerability to scan for")
    parser.add_argument("--local", action='store_true',
                        help="Scan local directory instead of GitHub repo")
    parser.add_argument("--api", default="http://localhost:5000/api/scan",
                        help="API endpoint URL")
    
    args = parser.parse_args()

    if args.local:
        results = scan_locally(args.repo_url, args.mode)
    else:
        results = scan_via_api(args.repo_url, args.mode, args.api)

    print(json.dumps(results, indent=2))

    found = results.get("metrics", {}).get("vulnerabilities_found", 0)
    print(f"\n📦 Files Scanned: {results.get('metrics', {}).get('files_scanned', 'N/A')}")
    print(f"⚠️ Vulnerabilities Found: {found}")

    # Exit with error code if vulnerabilities found
    if found > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
