import numpy as np, csv
BENIGN=['Background','LEGITIMATE']; ATTACK=['Botnet']
atk_rows=[]; ben_rows=[]
with open('F:/New/integrityguard/outputs/network-eval/official-ctu13/capture20110815-3_ctu54.binetflow','r') as f:
    for row in csv.DictReader(f):
        label=row.get('Label','')
        is_a=any(x in label for x in ATTACK); is_b=any(x in label for x in BENIGN)
        if not(is_a or is_b): continue
        try: dur=float(row.get('Dur',0))
        except: continue
        try: pkts=int(row.get('TotPkts','0'))
        except: pkts=0
        try: bytes_=int(row.get('TotBytes','0'))
        except: bytes_=0
        try: sbytes=int(row.get('SrcBytes','0'))
        except: sbytes=0
        dbytes=max(0,bytes_-sbytes)
        asym=abs(sbytes-dbytes)/max(bytes_,1) if bytes_>0 else 0.0
        proto=row.get('Proto','').lower()
        if proto=='udp' and dur<0.001:
            d={'pkts':pkts,'bytes':bytes_,'asym':asym,'dbytes':dbytes}
            if is_a: atk_rows.append(d)
            elif is_b: ben_rows.append(d)

print('CTU-54 very_ephemeral UDP:')
atk_a1=sum(1 for r in atk_rows if r['asym']==1.0)
ben_a1=sum(1 for r in ben_rows if r['asym']==1.0)
print(f'atk asym==1.0: {atk_a1}/{len(atk_rows)} ({100*atk_a1/max(1,len(atk_rows)):.1f}%)')
print(f'ben asym==1.0: {ben_a1}/{len(ben_rows)} ({100*ben_a1/max(1,len(ben_rows)):.1f}%)')
# Check how many CTU-54 attack very_ephemeral have asym<0.9 (bidirectional)
atk_low_asym=sum(1 for r in atk_rows if r['asym']<0.9)
print(f'atk asym<0.9 (has response): {atk_low_asym}/{len(atk_rows)} ({100*atk_low_asym/max(1,len(atk_rows)):.1f}%)')
# asym distribution
avs=[r['asym'] for r in atk_rows]; bvs=[r['asym'] for r in ben_rows]
print(f'atk asym: p10={np.percentile(avs,10):.2f} p50={np.percentile(avs,50):.2f} p90={np.percentile(avs,90):.2f}')
print(f'ben asym: p10={np.percentile(bvs,10):.2f} p50={np.percentile(bvs,50):.2f} p90={np.percentile(bvs,90):.2f}')
