import importlib.util
for m in ["numpy", "sklearn", "torch"]:
    print(m, importlib.util.find_spec(m) is not None)
