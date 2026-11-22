import sys, subprocess
print(sys.executable)
try:
    import torch
    print("torch:", torch.__version__)
    print("cuda:", torch.cuda.is_available())
except ImportError:
    print("torch: NOT FOUND")
