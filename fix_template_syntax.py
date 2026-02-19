import os
import re

def fix_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pattern: a line ending with a single '}' within a Jinja block, followed by '};' on its own line
    # (The [\s\n]+ part covers the line break and any indentation)
    # This specifically targets the common mistake of breaking the line before '};'
    pattern = re.compile(r"(\{\{[^}]+)\}\s*\n\s*\};")
    
    new_content, count = pattern.subn(r"\1}};", content)
    
    if count > 0:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"FIXED: {file_path} ({count} occurrences)")
        return True
    return False

def main():
    templates_dir = 'templates'
    if not os.path.exists(templates_dir):
        print(f"Error: {templates_dir} directory not found.")
        return

    fixed_count = 0
    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.html'):
                full_path = os.path.join(root, file)
                if fix_file(full_path):
                    fixed_count += 1

    if fixed_count == 0:
        print("No syntax errors found to fix.")
    else:
        print(f"Done. Fixed {fixed_count} files.")

if __name__ == "__main__":
    main()
