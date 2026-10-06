"""Report-only remeasurement: one fresh process/model, no training, 4096 rows."""
import sys, json, time, gc, resource, platform
from pathlib import Path
import numpy as np
import pandas as pd
import psutil
import torch
sys.path.insert(0, str(Path.cwd() / 'scripts'))
import benchmark_model_memory as b

name=sys.argv[1]
torch.set_num_threads(1)
torch.set_num_interop_threads(1)
gc.collect()
mem={'baseline_rss_mb': b.rss_mb()}
# DNN scaler applies only to DNN. LightGBM receives raw Top40 values.
features=pd.read_csv(b.TOP40_PATH)['feature'].tolist()
import pyarrow.parquet as pq
raw=next(pq.ParquetFile(b.VALID_PATH).iter_batches(batch_size=4096,columns=features)).to_pandas().to_numpy(dtype=np.float32)
if name=='lightgbm':
    raw[~np.isfinite(raw)]=np.nan
    X=raw
else:
    import joblib
    X=b.preprocess_batch(raw,joblib.load(b.SCALER_PATH))
del raw
gc.collect()
mem['after_input_rss_mb']=b.rss_mb()
model={'fp32':b.load_fp32,'int8':b.load_int8,'lightgbm':lambda:b.lgb.Booster(model_file=str(b.LGBM_PATH))}[name]()
mem['after_model_rss_mb']=b.rss_mb()
rows=[]
with torch.inference_mode():
 for size in [1,32,256,4096]:
  inp=X[:size] if name=='lightgbm' else torch.from_numpy(X[:size])
  def infer():
   return model.predict(inp,num_threads=1) if name=='lightgbm' else model(inp)
  for _ in range(2):infer()
  values=[]
  runs=3 if name=='lightgbm' else 30
  for _ in range(runs):
   t=time.perf_counter_ns(); infer(); values.append((time.perf_counter_ns()-t)/1e6)
  median=float(np.median(values))
  rows.append(dict(model=name,batch_size=size,median_latency_ms=median,throughput_flows_s=size*1000/median,runs=runs,warmup=2,min_latency_ms=min(values),max_latency_ms=max(values)))
  print(name,size,median,flush=True)
mem['after_inference_rss_mb']=b.rss_mb()
mem['peak_rss_mb']=b.peak_rss_mb()
mem['model_load_delta_mb']=mem['after_model_rss_mb']-mem['after_input_rss_mb']
mem['peak_delta_from_baseline_mb']=mem['peak_rss_mb']-mem['baseline_rss_mb']
out=Path('results/final_report')
pd.DataFrame(rows).to_csv(out/f'benchmark_{name}.csv',index=False)
(out/f'memory_{name}.json').write_text(json.dumps(dict(model=name,**mem),indent=2))
(out/'benchmark_environment.json').write_text(json.dumps(dict(platform=platform.platform(),torch=torch.__version__,cpu_threads=1,preprocessing='excluded from latency; raw Top40 for LightGBM; Train scaler for DNN',memory_unit='MiB (bytes / 1024**2)',protocol='report verification run; 2 warmups, 3 LightGBM repeats / 30 DNN repeats; 4096-row input; sequential fresh processes'),indent=2))
