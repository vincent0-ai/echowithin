import os

file_path = r'c:\Users\ADMIN\Desktop\Projects\echowithin\templates\base.html'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Look for the specific broken pattern around line 722
found = False
for i in range(len(lines)):
    if "const isLoggedIn = {{ 'true' if current_user.is_authenticated else 'false' }" in lines[i] and not "}}" in lines[i]:
        print(f"Found broken line at {i+1}: {lines[i].strip()}")
        # Check if next line is a stray curly brace
        if i + 1 < len(lines) and lines[i+1].strip() == "};":
            print(f"Found stray brace at {i+2}: {lines[i+1].strip()}")
            lines[i] = lines[i].replace("else 'false' }", "else 'false' }};\n")
            lines[i+1] = "" # Remove the stray brace line
            found = True
            break
        else:
            # Just fix the line if no stray brace is found exactly as expected
            lines[i] = lines[i].replace("else 'false' }", "else 'false' }};\n")
            found = True
            break

if found:
    with open(file_path, 'w', encoding='utf-8') as f:
        # Filter out empty strings from removed lines
        f.writelines([line for line in lines if line])
    print("SUCCESS: Fixed base.html syntax error.")
else:
    print("ERROR: Patterns not found. Checking absolute line 722...")
    # Fallback to absolute line 722 if pattern matching failed but line matches
    if 721 < len(lines) and "isLoggedIn =" in lines[721]:
        lines[721] = "        const isLoggedIn = {{ 'true' if current_user.is_authenticated else 'false' }};\n"
        if 722 < len(lines) and lines[722].strip() == "};":
            lines[722] = ""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines([line for line in lines if line])
        print("SUCCESS: Fixed base.html by line number.")
    else:
        print("FAILED: Could not find the expected code at line 722.")
