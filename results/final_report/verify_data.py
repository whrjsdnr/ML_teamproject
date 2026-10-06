"""Bounded-memory hash audit; no full pandas load; reads existing Split V2."""
import json
from pathlib import Path
import duckdb, pandas as pd, pyarrow.parquet as pq
out=Path('results/final_report')
base=Path('data/processed/network_ml_split_v2')
features=[c for c in pq.ParquetFile(base/'train.parquet').schema.names if c not in ['Label','label_id','source_file','Timestamp','hour','day_of_week']]
assert len(features)==78
con=duckdb.connect()
con.execute("SET memory_limit='1GB'")
con.execute('SET threads=1')
con.execute("SET temp_directory='/tmp/report-duckdb-audit'")
expr=', '.join('"'+f+'"' for f in features)
sql=' UNION ALL '.join(f"SELECT hash({expr}) h,label_id,{i} split_id FROM read_parquet('{base/p}')" for i,p in enumerate(['train.parquet','valid.parquet','test.parquet']))
print('Auditing feature hashes across 16M existing Parquet rows',flush=True)
con.execute(f'CREATE TEMP TABLE patterns AS SELECT h,label_id,split_id,COUNT(*) n FROM ({sql}) GROUP BY h,label_id,split_id')
over=con.execute('SELECT COUNT(*) FROM (SELECT h FROM patterns GROUP BY h HAVING COUNT(DISTINCT split_id)>1)').fetchone()[0]
conf=con.execute('SELECT h,COUNT(DISTINCT label_id) labels,SUM(n) affected_rows FROM patterns GROUP BY h HAVING COUNT(DISTINCT label_id)>1').df()
conf.to_csv(out/'conflicting_hash_patterns.csv',index=False)
pairs=con.execute('SELECT a.label_id class_a,b.label_id class_b,COUNT(*) patterns,SUM(a.n+b.n) affected_pair_rows FROM (SELECT h,label_id,SUM(n) n FROM patterns GROUP BY h,label_id) a JOIN (SELECT h,label_id,SUM(n) n FROM patterns GROUP BY h,label_id) b ON a.h=b.h AND a.label_id<b.label_id GROUP BY a.label_id,b.label_id ORDER BY affected_pair_rows DESC').df()
pairs.to_csv(out/'label_conflict_pairs_verified.csv',index=False)
checks={}
for a,b in [(0,1),(0,2),(1,2)]:
 checks[f'{a}_{b}_overlap']=con.execute(f'SELECT COUNT(*) FROM (SELECT DISTINCT h FROM patterns WHERE split_id={a}) a JOIN (SELECT DISTINCT h FROM patterns WHERE split_id={b}) b USING(h)').fetchone()[0]
summary=dict(rows={p:pq.ParquetFile(base/p).metadata.num_rows for p in ['train.parquet','valid.parquet','test.parquet']},features=features,conflicting_patterns=len(conf),affected_rows=int(conf.affected_rows.sum()),max_labels=int(conf.labels.max()),**checks,method='DuckDB 64-bit hash of all 78 model features; overlap counts refer to hashes; collision risk is not mathematically excluded')
(out/'data_verification.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
print(summary,flush=True)
