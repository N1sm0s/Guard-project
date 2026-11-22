path = 'integrityguard/gui.py'
src = open(path, encoding='utf-8').read()
lines = src.splitlines()

# Find _page_check and surrounding methods
for i, line in enumerate(lines):
    if '_page_check' in line or '_check_load_events' in line or '_check_nn' in line or '_show_event_nn' in line:
        print(f"{i+1}: {line[:100]}")
