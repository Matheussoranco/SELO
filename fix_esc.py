# Fix the _ESC dictionary in jcs.py
with open('selo/jcs.py', 'rb') as f:
    content = f.read()

# Find the 0x0A line
idx = content.find(b'0x0A:')
if idx >= 0:
    line_end = content.find(b'\r\n', idx)
    # Replace with correct line:     0x0A: '\\n',
    # The value should be '\\n' (four chars in source: \ \ n)
    # In file bytes: ' (27) \ (5c) \ (5c) n (6e) ' (27)
    new_line = b"    0x0A: '\\\\n',\r\n"
    
    new_content = content[:idx] + new_line + content[line_end+2:]
    
    with open('selo/jcs.py', 'wb') as f:
        f.write(new_content)
    
    print('Done - replaced 0x0A line')
else:
    print('Could not find 0x0A line')