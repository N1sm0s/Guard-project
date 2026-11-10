# -*- coding: utf-8 -*-
path = r'F:\New\integrityguard\integrityguard\train.py'
with open(path, 'r', encoding='utf-8') as f:
    c = f.read()

old = u'ax[0].set_xticks(x, ["\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438", "\u0432\u0435\u0441\u0430", "\u0431\u044d\u043a\u0434\u043e\u0440", "\u043e\u0442\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435", "\u043f\u043e\u0434\u043c\u0435\u043d\u0430 \u043c\u0435\u0442\u043e\u043a"])'
new = u'ax[0].set_xticks(x, ["\u0437\u0430\u0432\u0438\u0441\u0438\u043c.", "\u0432\u0435\u0441\u0430", "\u0431\u044d\u043a\u0434\u043e\u0440", "\u043e\u0442\u0440\u0430\u0432\u043b.", "\u043c\u0435\u0442\u043a\u0438", "\u0441\u043e\u0441\u0442\u044f\u0437.", "\u0438\u0437\u0432\u043b\u0435\u0447.", "\u0434\u043e\u0441\u0442\u0443\u043f\u043d."], rotation=20, ha=\'right\')'

n = c.count(old)
print('found:', n)
if n:
    c2 = c.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(c2)
    print('patched ok')
else:
    # fallback: show surrounding context
    idx = c.find('set_xticks')
    print('set_xticks context:', repr(c[idx:idx+120]))
