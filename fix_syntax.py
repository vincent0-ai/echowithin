import os

filepath = 'templates/shared_note.html'
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
fixed_authenticated = False
for line in lines:
    # Fix unclosed Jinja2 tag for IS_AUTHENTICATED
    if "const IS_AUTHENTICATED = {{ 'true' if current_user.is_authenticated else 'false' }" in line and "}}" not in line:
        line = line.replace("else 'false' }", "else 'false' }};")
        new_lines.append(line)
        fixed_authenticated = True
        print("Fixed IS_AUTHENTICATED unclosed tag")
        continue
    
    # Fix stray closure }; after IS_AUTHENTICATED
    if fixed_authenticated and line.strip() == "}":
        # Maybe it's just } or };
        # If the previous line was IS_AUTHENTICATED, this is likely the stray one
        fixed_authenticated = False # reset
        print("Skipped stray closing brace '}'")
        continue

    if fixed_authenticated and line.strip() == "};":
        fixed_authenticated = False # reset
        print("Skipped stray closing brace '};'")
        continue
    
    new_lines.append(line)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print("File updated.")
