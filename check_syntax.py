import re

def check_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check Jinja2 tags
    jinja_expr_open = len(re.findall(r'\{\{', content))
    jinja_expr_close = len(re.findall(r'\}\}', content))
    jinja_block_open = len(re.findall(r'\{%', content))
    jinja_block_close = len(re.findall(r'%\}', content))
    
    print(f"Jinja2 Expressions: Found {jinja_expr_open} '{{{{', {jinja_expr_close} '}}}}'")
    print(f"Jinja2 Blocks: Found {jinja_block_open} '{{%', {jinja_block_close} '%}}'")
    
    # Check braces, brackets, parentheses
    stack = []
    pairs = {'(': ')', '[': ']', '{': '}'}
    lines = content.split('\n')
    
    # Simple line-by-line check might be better for reporting
    for i, line in enumerate(lines):
        line_num = i + 1
        # Check for unclosed Jinja on current line (simplified)
        if '{{' in line and '}}' not in line:
            print(f"Line {line_num}: Potentially unclosed '{{{{'")
        if '{%' in line and '%}' not in line:
            print(f"Line {line_num}: Potentially unclosed '{{%'")
            
        # Bracket matching (ignoring strings/regex for now, just a rough check)
        for char in line:
            if char in '([{':
                stack.append((char, line_num))
            elif char in ')]}':
                if not stack:
                    print(f"Line {line_num}: Unexpected closing '{char}'")
                else:
                    top_char, top_line = stack.pop()
                    if pairs[top_char] != char:
                        print(f"Line {line_num}: Mismatched '{char}' for '{top_char}' from line {top_line}")

    while stack:
        char, line = stack.pop()
        print(f"Unclosed '{char}' from line {line}")

check_file('templates/shared_note.html')
