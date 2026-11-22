import torch, json
c = torch.load('F:/New/integrityguard/data/models/network_classifier.pt', weights_only=False)
skip = {'state_dict', 'mean', 'std', 'feature_names'}
print(json.dumps({k: v for k, v in c.items() if k not in skip}, indent=2, default=str))
