import numpy as np, csv
BENIGN=['Background','LEGITIMATE']; ATTACK=['Botnet']
atk_rows=[]; ben_rows=[]
with open('F:/New/integrityguard/outputs/network-eval/official-ctu13/capture20110819_ctu53.binetflow','r') as f:
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
        bpp=bytes_/max(pkts,1)
        proto=row.get('Proto','').lower()
        if proto=='udp' and dur<0.001:
            d={'pkts':pkts,'bytes':bytes_,'bpp':bpp,'asym':asym,'sbytes':sbytes,'dbytes':dbytes}
            if is_a: atk_rows.append(d)
            elif is_b: ben_rows.append(d)

print('CTU-53 very_ephemeral UDP:')
for key in ['pkts','bytes','bpp','asym']:
    av=[r[key] for r in atk_rows]; bv=[r[key] for r in ben_rows]
    print(f'  {key}: atk p10={np.percentile(av,10):.2f} p50={np.percentile(av,50):.2f} p90={np.percentile(av,90):.2f}')
    print(f'  {key}: ben p10={np.percentile(bv,10):.2f} p50={np.percentile(bv,50):.2f} p90={np.percentile(bv,90):.2f}')

atk_b0 = sum(1 for r in atk_rows if r['bytes']==0)
ben_b0 = sum(1 for r in ben_rows if r['bytes']==0)
atk_a1 = sum(1 for r in atk_rows if r['asym']==1.0)
ben_a1 = sum(1 for r in ben_rows if r['asym']==1.0)
atk_db0 = sum(1 for r in atk_rows if r['dbytes']==0)
ben_db0 = sum(1 for r in ben_rows if r['dbytes']==0)
print(f'atk bytes==0: {atk_b0} / {len(atk_rows)} ({100*atk_b0/max(1,len(atk_rows)):.1f}%)')
print(f'ben bytes==0: {ben_b0} / {len(ben_rows)} ({100*ben_b0/max(1,len(ben_rows)):.1f}%)')
print(f'atk asym==1 (one-directional): {atk_a1} / {len(atk_rows)} ({100*atk_a1/max(1,len(atk_rows)):.1f}%)')
print(f'ben asym==1: {ben_a1} / {len(ben_rows)} ({100*ben_a1/max(1,len(ben_rows)):.1f}%)')
print(f'atk dbytes==0 (no response): {atk_db0} / {len(atk_rows)} ({100*atk_db0/max(1,len(atk_rows)):.1f}%)')
print(f'ben dbytes==0: {ben_db0} / {len(ben_rows)} ({100*ben_db0/max(1,len(ben_rows)):.1f}%)')
# bytes distribution buckets
for thresh in [0,28,40,60]:
    atk_gt=sum(1 for r in atk_rows if r['bytes']>thresh)
    ben_gt=sum(1 for r in ben_rows if r['bytes']>thresh)
    print(f'bytes>{thresh}: atk={atk_gt}/{len(atk_rows)} ({100*atk_gt/max(1,len(atk_rows)):.1f}%) ben={ben_gt}/{len(ben_rows)} ({100*ben_gt/max(1,len(ben_rows)):.1f}%)')
