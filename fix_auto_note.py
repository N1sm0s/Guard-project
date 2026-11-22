path = 'integrityguard/gui.py'
src = open(path, encoding='utf-8').read()

# Replace all occurrences of self.auto_note. with self.e_auto_note.
# but NOT self.e_auto_note (already correct)
fixed = src.replace('self.auto_note.', 'self.e_auto_note.')

count = src.count('self.auto_note.') 
print(f"Replaced {count} occurrences of 'self.auto_note.'")

open(path, 'w', encoding='utf-8').write(fixed)
print("Done.")
