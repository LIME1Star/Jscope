"""Passive candidate-host inventory and assessment-specific approvals; no network probing."""
from __future__ import annotations
import json, time, hashlib
from pathlib import Path
from jscope.workspace.assessment import normalize_domain
from jscope.workspace.common import WorkspaceError, _atomic_write

def discover_candidates(root_domain: str, host_files=(), existing=()):
    root=normalize_domain(root_domain); candidates={}
    def add(value,source):
        try:
            host=normalize_domain(value)
            if host != root and not host.endswith('.'+root):
                candidates.setdefault(str(value), {'hostname':host,'state':'excluded','reason':'outside-root-domain','provenance':source,'discovered_at':time.time()})
            else:
                candidates.setdefault(host, {'hostname':host,'state':'known','reason':None,'provenance':source,'discovered_at':time.time()})
        except WorkspaceError as e:
            candidates.setdefault(str(value), {'hostname':None,'state':'excluded','reason':'invalid-hostname','detail':str(e),'provenance':source,'discovered_at':time.time()})
    for h in existing: add(h,'workspace-knowledge')
    for filename in host_files:
        p=Path(filename)
        for line in p.read_text(encoding='utf-8').splitlines():
            val=line.strip()
            if val and not val.startswith('#'): add(val, f'host-file:{p.name}')
    add(root,'root-domain')
    return list(candidates.values())

def persist_candidates(manifest_path, candidates):
    p=Path(manifest_path)
    try: data=json.loads(p.read_text(encoding='utf-8'))
    except (OSError,ValueError) as e: raise WorkspaceError('assessment manifest missing or corrupt; refusing discovery update') from e
    if data.get('schema')!='jscope-assessment/1' or not data.get('assessment_id') or not data.get('root_domain'):
        raise WorkspaceError('invalid assessment manifest')
    hosts=data.setdefault('hosts',{})
    for c in candidates:
        h=c.get('hostname')
        if not h or c.get('state') != 'known': continue
        prior=hosts.get(h)
        if prior:
            prior.setdefault('provenance',[])
            if c['provenance'] not in prior['provenance']: prior['provenance'].append(c['provenance'])
        else:
            hosts[h]={'state':'known','discovery_source':c['provenance'],'discovered_at':c['discovered_at']}
    data.setdefault('discovery',[]).append({'at':time.time(),'candidate_count':len(candidates),'candidates':candidates})
    _atomic_write(p,data); return data

def approve_hosts(manifest_path, hostnames):
    p=Path(manifest_path)
    try: data=json.loads(p.read_text(encoding='utf-8'))
    except (OSError,ValueError) as e: raise WorkspaceError('assessment manifest missing or corrupt; approval denied') from e
    if data.get('schema')!='jscope-assessment/1' or not data.get('assessment_id'): raise WorkspaceError('invalid assessment manifest; approval denied')
    root=normalize_domain(data['root_domain']); normalized=[]
    for raw in hostnames:
        h=normalize_domain(raw)
        if h != root and not h.endswith('.'+root): raise WorkspaceError(f'approval denied: {h} is outside root domain')
        if h not in data.get('hosts',{}): raise WorkspaceError(f'approval denied: {h} is not a known candidate')
        normalized.append(h)
    if not normalized: raise WorkspaceError('no hosts specified for approval')
    now=time.time(); decision={'at':now,'assessment_id':data['assessment_id'],'hosts':sorted(set(normalized)),'decision':'approved'}
    data.setdefault('approval_history',[]).append(decision)
    auth=data.setdefault('authorization',{}); auth['approved_hosts']=sorted(set(auth.get('approved_hosts',[]))|set(normalized)); auth['approved_at']=now; auth['fresh_for_this_run']=True
    for h in normalized: data['hosts'][h]['state']='approved'
    data['status']='approved'; _atomic_write(p,data); return decision
