#!/usr/bin/env python3
import requests
import sys
import json
import argparse
from model_predictor import predict_vulnerability

def scan_via_api(repo_url, mode='sql', api_url="http://localhost:5000/api/scan"):
    """Scan repository via API"""
    try:
        payload = {"repo_url": repo_url, "mode": mode}
        response = requests.post(api_url, json=payload)
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}

def scan_locally(repo_path, mode='sql'):
    """Scan repository locally without API"""
    import os
    from datetime import datetime
    
    results = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    result = predict_vulnerability(code, mode)
                    if result['is_vulnerable']:
                        results.append({
                            "file_path": file_path,
                            "vulnerability_type": result['type'],
                            "confidence": result['confidence'],
                            "detection_method": result.get('detection_method', 'model'),
                            "timestamp": datetime.now().isoformat()
                        })
    return {"results": results}

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
    
    # Exit with error code if vulnerabilities found
    if results.get('results') and len(results['results']) > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()