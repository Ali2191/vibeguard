import os

SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.env', '.json', '.yaml', '.yml'}
SUPPORTED_FILENAMES = {'.env', '.env.example', '.env.local', '.env.production', '.env.staging', '.env.development'}

def parse_directory(path: str) -> list[dict]:
    results = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {'node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build'}]
        for file in files:
            ext = os.path.splitext(file)[1]
            full_path = os.path.join(root, file)
            relative = os.path.relpath(full_path, path)
            if ext not in SUPPORTED_EXTENSIONS and file not in SUPPORTED_FILENAMES:
                continue
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                lines = content.splitlines()
                results.append({
                    'file': full_path,
                    'relative_path': relative,
                    'extension': ext,
                    'content': content,
                    'lines': lines
                })
            except Exception:
                continue
    return results
