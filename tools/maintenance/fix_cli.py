# -*- coding: utf-8 -*-
path = r'F:\New\integrityguard\integrityguard\cli.py'
with open(path, 'r', encoding='utf-8') as f:
    c = f.read()

# Fix build_corpus call: remove workers and _progress args
old4 = 'build_corpus(a.projects, a.seed, a.workers, _progress)'
new4 = 'build_corpus(a.projects, a.seed)'
n = c.count(old4)
print('workers+progress found:', n)
if n:
    c = c.replace(old4, new4)

# Also fix if only workers is passed without _progress
old4b = 'build_corpus(a.projects, a.seed, a.workers)'
new4b = 'build_corpus(a.projects, a.seed)'
n2 = c.count(old4b)
print('workers-only found:', n2)
if n2:
    c = c.replace(old4b, new4b)

with open(path, 'w', encoding='utf-8') as f:
    f.write(c)
print('done')

# Show context around build_corpus call
idx = c.find('build_corpus(')
print('context:', repr(c[idx:idx+80]))
