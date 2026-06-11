import os
import re
import shutil
import subprocess

def main():
    print("Starting backup extraction...")
    
    # 1. Create rag_backup directory
    os.makedirs("rag_backup", exist_ok=True)
    
    # 2. Extract rules_generator.js from changes.diff
    diff_path = "changes.diff"
    extracted_js = False
    if os.path.exists(diff_path):
        with open(diff_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        # Look for rules_generator.js diff
        match = re.search(r"diff --git a/frontend/rules_generator\.js b/frontend/rules_generator\.js[\s\S]*?\+\+\+ b/frontend/rules_generator\.js\n([\s\S]*?)(?:diff --git|$)", content)
        if match:
            lines = match.group(1).split("\n")
            js_content = []
            for line in lines:
                if line.startswith("+") and not line.startswith("+++"):
                    js_content.append(line[1:])
                elif line.startswith(" ") or line == "":
                    js_content.append(line[1:] if len(line) > 0 else "")
            
            with open("rag_backup/rules_generator.js", "w", encoding="utf-8") as out:
                out.write("\n".join(js_content))
            print("Extracted rules_generator.js to rag_backup/rules_generator.js")
            extracted_js = True
            
    # 3. Move other RAG files
    files_to_move = [
        ("backend/rule_generator.py", "rag_backup/rule_generator.py"),
        ("backend/wazuh_rag.db", "rag_backup/wazuh_rag.db"),
        ("wazuh_rag_readme.md", "rag_backup/wazuh_rag_readme.md"),
        ("changes.diff", "rag_backup/changes.diff")
    ]
    
    for src, dst in files_to_move:
        if os.path.exists(src):
            try:
                shutil.move(src, dst)
                print(f"Moved {src} to {dst}")
            except Exception as e:
                print(f"Error moving {src}: {e}")
                
    # 4. Tar/gzip the backup directory
    try:
        subprocess.check_call(["tar", "-czf", "rag_backup.tar.gz", "rag_backup"])
        print("Successfully compressed backup into rag_backup.tar.gz")
        
        # 5. Clean up backup directory
        shutil.rmtree("rag_backup")
        print("Cleaned up temporary rag_backup directory")
    except Exception as e:
        print(f"Error compressing backup: {e}")

if __name__ == "__main__":
    main()
