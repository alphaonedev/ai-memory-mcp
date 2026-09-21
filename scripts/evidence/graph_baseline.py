#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Produce source/executable-bound raw native graph latency evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/native'))
from federation import Cluster, Failure, MAX_COMMAND_OUTPUT, certify, command, interrupted, redact

# Preserve production deadlines while allowing short real-process lifecycle tests.
READY_SECONDS=30
RUN_SECONDS=1300
STOP_SECONDS=10

EXPECTED={(f'kg_query_depth_{depth}',engine):rows for engine in ['cte','age'] for depth,rows in [(1,4),(2,20),(3,84)]}
EXPECTED.update({('kg_timeline','cte'):4,('kg_timeline','age'):4,('projection_drain','age'):64})

def summarize(records):
    keys=[(row.get('operation'),row.get('engine')) for row in records]
    if len(keys)!=len(EXPECTED) or set(keys)!=set(EXPECTED):
        raise Failure('missing or duplicate measurement scenario')
    result=[]
    for row in records:
        key=(row['operation'],row['engine']);samples=row.get('samples_us',[])
        if (row.get('rows')!=EXPECTED[key] or row.get('nodes')!=1024 or row.get('edges')!=1023
                or row.get('warmup')!=10 or len(samples)!=200
                or any(type(value) is not int or value<=0 for value in samples)):
            raise Failure('measurement has wrong cardinality or invalid/incomplete raw samples')
        values=sorted(samples)
        result.append(dict(operation=key[0],engine=key[1],rows=row['rows'],n=len(values),
            **{f'p{q}_us':values[(len(values)*q+99)//100-1] for q in [50,95,99]}))
    return result

FIXTURE_TESTS={'missing_deep_relationship_refuses_baseline',
               'vertices_without_restored_relationships_refuse_drain'}

def complete_fixture_controls(listing,output):
    listed=re.findall(r'^(\S+): test$',listing,re.MULTILINE)
    passed=re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE)
    summaries=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',output,re.MULTILINE)
    if (len(listed)<2 or len(listed)!=len(set(listed)) or not FIXTURE_TESTS<=set(listed)
            or sorted(passed)!=sorted(listed) or len(summaries)!=1
            or summaries[0]!=('ok',str(len(listed)),'0','0')
            or re.search(r'(?im)(?:^|\s)skip(?:ped)?(?::|\s)',output)):
        raise Failure('native fixture controls must execute every listed pin without skips')
    return len(listed)

def digest(path):
    with open(path,'rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def resource_gate(env):
    if sys.platform=='darwin':
        code,_=command(['python3','scripts/native/resource_gate.py'],env,1300)
        if code:raise Failure('resource floor prevented a build')

def extensions(cluster,url):
    cluster.sql(url,'CREATE EXTENSION age; CREATE EXTENSION vector;')
    value=cluster.sql(url,"SELECT ssl::text || '|' || split_part(current_setting('server_version'),' ',1) || '|' || (SELECT extversion FROM pg_extension WHERE extname='age') || '|' || (SELECT extversion FROM pg_extension WHERE extname='vector') FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
    certify(value.replace('true|','t|',1))

def read_bounded(process,deadline,budget,readiness=False):
    """The shared 32MiB diagnostic budget also bounds this 1800-sample producer."""
    data=bytearray()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([process.stdout],[],[],remaining)[0]:
            raise Failure('benchmark readiness timed out' if readiness else 'benchmark output timed out')
        # A readiness line is tiny. Read one byte until its newline so no buffered
        # readline can block past the deadline or consume later measurement bytes.
        chunk=os.read(process.stdout.fileno(),1 if readiness else 65536)
        if not chunk:
            if readiness:raise Failure('benchmark did not declare complete readiness')
            return bytes(data)
        if len(data)+len(chunk)>budget:raise Failure('benchmark output exceeded diagnostic budget')
        data.extend(chunk)
        if readiness and chunk==b'\n':return bytes(data)

def execute_bound(binary,env,sha,out):
    process=subprocess.Popen([binary],cwd=ROOT,env=env,stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        line=read_bounded(process,time.monotonic()+READY_SECONDS,MAX_COMMAND_OUTPUT,True)
        if not line.startswith(b'GRAPH_READY '):raise Failure('benchmark did not declare readiness')
        ready=json.loads(line.removeprefix(b'GRAPH_READY '))
        if ready.get('pid')!=process.pid or ready.get('source_commit')!=sha:
            raise Failure('compiled source/process binding mismatch')
        code,live_hash=command(['bash','-c','source scripts/evidence/lib.sh; evidence_sha256_of_pid "$1"','--',str(process.pid)],env,30)
        file_hash=digest(binary)
        if code or live_hash.strip()!=file_hash:raise Failure('live executable binding mismatch')
        process.stdin.write(b'RUN\n');process.stdin.flush();process.stdin.close()
        deadline=time.monotonic()+RUN_SECONDS
        output=read_bounded(process,deadline,MAX_COMMAND_OUTPUT-len(line))
        process.wait(timeout=max(0.001,deadline-time.monotonic()))
        text=(line+output).decode(errors='replace')
        (out/'benchmark.log').write_text(redact(text,[env['AI_MEMORY_TEST_AGE_URL']]))
        if process.returncode:raise Failure('native benchmark failed; no latency bundle published')
        if digest(binary)!=file_hash:raise Failure('executable changed during measurement')
        return file_hash,text
    finally:
        # Close capture before cleanup: a terminating child cannot grow memory.
        for stream in (process.stdin,process.stdout):
            try:stream.close()
            except OSError:pass  # A broken pipe must not bypass group cleanup.
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:pass
        finally:
            # A reaped leader says nothing about descendants in our own session.
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=STOP_SECONDS)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--psql',default=shutil.which('psql'))
    args=parser.parse_args(argv)
    previous={sig:signal.signal(sig,interrupted) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True,timeout=10).strip()
        dirty=subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True,timeout=10).strip()
        if dirty:raise Failure('commit the exact source before measuring')
        url=os.environ.get('AI_MEMORY_NATIVE_ADMIN_URL') or os.environ.get('AI_MEMORY_TEST_POSTGRES_URL')
        if not url or not args.psql:raise Failure('explicit native configuration and psql required')
        cluster=Cluster(url,args.psql);cluster.preflight()
        env=os.environ.copy()
        if not all(env.get(key) for key in ['CARGO_TARGET_DIR','TMPDIR']):
            raise Failure('explicit target and scratch directories required')
        env.update(CARGO_BUILD_JOBS='2',AI_MEMORY_GRAPH_BENCH_COMMIT=sha,
            AI_MEMORY_NO_CONFIG='1',AI_MEMORY_AGE_PROJECTION_MODE='sync',CARGO_TERM_COLOR='never',
            CARGO_PROFILE_GRAPH_BENCH_OPT_LEVEL='3',CARGO_PROFILE_GRAPH_BENCH_LTO='false',
            CARGO_PROFILE_GRAPH_BENCH_CODEGEN_UNITS='16',CARGO_PROFILE_GRAPH_BENCH_DEBUG='0')
        run_id=uuid.uuid4().hex;out=ROOT/'.local-runs/graph-baseline'/run_id
        out.mkdir(parents=True,mode=0o700)
        if not out.resolve().is_relative_to(ROOT/'.local-runs/graph-baseline'):
            raise Failure('evidence path escaped repository')
        started=datetime.now(timezone.utc).isoformat()
        # Establish E1 conformance in a DIFFERENT database so its fixture cannot
        # contaminate the measured 1024-node corpus or graph catalog cardinality.
        with cluster.database() as conformance_url:
            extensions(cluster,conformance_url)
            env.update(AI_MEMORY_TEST_POSTGRES_URL=conformance_url,AI_MEMORY_TEST_AGE_URL=conformance_url)
            resource_gate(env)
            print('CARGO_TARGET_DIR='+env['CARGO_TARGET_DIR'],flush=True)
            code,text=command([sys.executable,'scripts/check_graph_conformance_log.py'],env,2200)
            (out/'conformance.log').write_text(redact(text,[url,conformance_url]))
            if code or 'GRAPH_COMPLETE tests=5 cells=18' not in text:
                raise Failure('E1 conformance did not complete')
            print('GRAPH_CONFORMANCE tests=5 cells=18',flush=True)
        # Destructive fixture controls get their own database, never the latency corpus.
        with cluster.database() as control_url:
            extensions(cluster,control_url)
            env.update(AI_MEMORY_TEST_POSTGRES_URL=control_url,AI_MEMORY_TEST_AGE_URL=control_url)
            resource_gate(env)
            print('CARGO_TARGET_DIR='+env['CARGO_TARGET_DIR'],flush=True)
            cargo=['cargo','test','--features','sal-postgres','--test','graph_baseline_fixture']
            code,listing=command(cargo+['--','--ignored','--list'],env,1800)
            (out/'fixture-list.log').write_text(redact(listing,[url,control_url]))
            if code:raise Failure('native fixture control listing failed')
            code,output=command(cargo+['--','--ignored','--test-threads=1'],env,1800)
            (out/'fixture-controls.log').write_text(redact(output,[url,control_url]))
            if code:raise Failure('native fixture controls failed')
            controls=complete_fixture_controls(listing,output)
            print(f'GRAPH_FIXTURE_CONTROLS tests={controls} skip=0',flush=True)
        resource_gate(env)
        print('CARGO_TARGET_DIR='+env['CARGO_TARGET_DIR'],flush=True)
        code,build=command(['cargo','build','--profile','graph-bench','--features','sal-postgres',
            '--bench','graph_native_baseline','--message-format=json'],env,3600)
        (out/'build.log').write_text(redact(build,[url]))
        if code:raise Failure('optimized benchmark build failed')
        artifacts=[]
        for line in build.splitlines():
            try:item=json.loads(line)
            except json.JSONDecodeError:continue
            if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='graph_native_baseline' and item.get('executable'):
                artifacts.append(item['executable'])
        if len(artifacts)!=1:raise Failure('ambiguous cargo executable artifact')
        with cluster.database() as bench_url:
            extensions(cluster,bench_url)
            env.update(AI_MEMORY_TEST_POSTGRES_URL=bench_url,AI_MEMORY_TEST_AGE_URL=bench_url)
            binary_hash,text=execute_bound(artifacts[0],env,sha,out)
            text=redact(text,[url,bench_url]);(out/'benchmark.log').write_text(text)
            records=[json.loads(line.removeprefix('GRAPH_SAMPLES ')) for line in text.splitlines() if line.startswith('GRAPH_SAMPLES ')]
            if 'GRAPH_MEASURED scenarios=9 samples_per_scenario=200' not in text:
                raise Failure('benchmark completion marker missing')
            summary=summarize(records)
        raw=out/'raw.json';raw.write_text(json.dumps(records,indent=2)+'\n')
        bundle=dict(artifact_kind='native-graph-benchmark',producer_id='native-graph-baseline',
            run_id=run_id,source_commit=sha,
            source_tree_sha=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True,timeout=10).strip(),
            daemon_binary_sha256=binary_hash,addressed_exe_sha256=binary_hash,
            verdict='NOT_APPLICABLE',oracle_kind='descriptive-measurement',
            started_at_utc=started,finished_at_utc=datetime.now(timezone.utc).isoformat(),
            capacity={'p99_method':'pooled_raw','quantile':'nearest-rank'},
            profile={'name':'graph-bench','opt_level':3,'lto':False,'codegen_units':16},
            versions={'postgres':'18.6','age':'1.8.0','pgvector':'0.8.6'},
            host={'hostname':platform.node(),'platform':platform.platform(),'architecture':platform.machine(),'logical_cpus':os.cpu_count()},
            fixture={'nodes':1024,'edges':1023,'shape':'4-ary directed tree'},
            raw_samples_sha256=digest(raw),raw_samples_file='raw.json',metrics=summary,
            cleanup='verified',fixture_controls=controls,conformance='5 tests /18 cells on same source in separate database')
        path=out/'bundle.json';path.write_text(json.dumps(bundle,indent=2)+'\n')
        code,guard=command(['bash','scripts/check-evidence-bundle.sh','--bundle',str(path)],env,120)
        (out/'bundle-guard.log').write_text(guard)
        if code:raise Failure('evidence bundle guard rejected output')
        print('GRAPH_BASELINE '+str(path.relative_to(ROOT)),flush=True)
        for row in summary:print(json.dumps(row),flush=True)
        return 0
    except (Failure,OSError,ValueError,subprocess.SubprocessError):
        print('GRAPH_BASELINE_FAILED no certified baseline published; inspect sanitized local evidence',flush=True)
        return 1
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)

if __name__=='__main__':sys.exit(main())
