import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
lines = open(r'F:\New\integrityguard\integrityguard\gui.py', encoding='utf-8').readlines()
keywords = ['_page_check', 'package_check', 'manifest', 'PathEdit', '_check_', 'OSV', 'osv', 
            'Автопроверка', 'Что проверить', 'Проверка пакета', 'Стадия', 'на проверку',
            'assess_network', 'network_classifier', '_run_check', '_on_check']
for i, l in enumerate(lines):
    for kw in keywords:
        if kw in l:
            print(f"{i+1}: {l.rstrip()}")
            break
