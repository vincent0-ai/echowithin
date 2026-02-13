import os

filepath = 'templates/shared_note.html'
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
skip_next = False
for i, line in enumerate(lines):
    if skip_next:
        skip_next = False
        continue

    # Identify the broken block
    if "const IS_AUTHENTICATED = {{ 'true' if current_user.is_authenticated else 'false' }" in line and "}}" not in line:
        # Check if the next line is the stray closure
        if i + 1 < len(lines) and lines[i+1].strip() in ["}", "};"]:
            # Found the broken pair!
            new_lines.append(f"            const SHARE_ID = '{{{{ share_id }}}}';\n")
            new_lines.append(f"            const IS_AUTHENTICATED = {{{{ 'true' if current_user.is_authenticated else 'false' }}}};\n")
            new_lines.append(f"            const CSRF_TOKEN = '{{{{ csrf_token() }}}}';\n")
            skip_next = True # Skip the stray closure
            print(f"Fixed broken block at line {i+1}")
            continue
    
    new_lines.append(line)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print("File update attempted.")
