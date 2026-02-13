import sys

filepath = 'templates/shared_note.html'
with open(filepath, 'r', encoding='utf-8') as f:
    text = f.read()

# Targeted replacement for the broken segment
broken = """            const SHARE_ID = '{{ share_id }}';
            const IS_AUTHENTICATED = {{ 'true' if current_user.is_authenticated else 'false' }
        };
        const CSRF_TOKEN = '{{ csrf_token() }}';"""

fixed = """            const SHARE_ID = '{{ share_id }}';
            const IS_AUTHENTICATED = {{ 'true' if current_user.is_authenticated else 'false' }};
            const CSRF_TOKEN = '{{ csrf_token() }}';"""

if broken in text:
    text = text.replace(broken, fixed)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(text)
    print("SUCCESS: Fixed broken block.")
else:
    print("WARNING: Could not find the exact broken block. Printing current state of lines 1150-1170:")
    lines = text.split('\n')
    for i in range(1150, min(1170, len(lines))):
        print(f"{i}: {lines[i]}")

