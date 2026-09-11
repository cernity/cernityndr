"""Non-destructive audit probes. Run from repository root with python3."""
import importlib.util, pathlib, sys, json, subprocess, os
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'shared'))
def module(name, path):
    sys.path.insert(0,str((ROOT/path).parent))
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod
sm=module('sm','services/finding-service/state_machine.py')
store=module('store','shared/store.py')
agent=module('agent','services/capture-agent/agent.py')
ewapp=module('ewapp','services/east-west-detectors/app.py')
beh=module('beh','services/behavioral-detectors/app.py')
adapters=module('adapters','services/findings-forwarder/adapters.py')
class Producer:
    def __init__(self): self.sent=[]
    def send(self,topic,msg): self.sent.append(msg)
    def flush(self): pass
results={}
c={'finding_id':'audit-signature','detector_id':'ids_signature','category':'c2','severity':9,'confidence':.99,'entities':'[]'}
f,route=sm.build_finding(c)
results['confirmed_signature']={'route':route,'state':f['state']}
results['capture_request_agent_validation']=agent.validate({'finding_id':f['finding_id'],'entities':f['entities']})
# Active TTL refresh retains old members and counts beyond the alleged window.
clock=[0.0]; s=store.InMemoryStore(clock=lambda:clock[0])
s.counter_add('x','bytes',100,600); s.set_add('targets','old',600)
clock[0]=599;s.counter_add('x','bytes',1,600);s.set_add('targets','new',600)
clock[0]=601
results['window_after_601_seconds']={'counter':s.counter_get('x','bytes'),'members':sorted(s.set_members('targets'))}
# Stock documented DCERPC array and SMB pipe representation.
p=Producer(); ewapp._store=store.InMemoryStore()
for e in [dict(event_type='dcerpc',src_ip='10.0.0.1',dest_ip='10.0.0.2',dcerpc={'interfaces':[{'uuid':'367abb81-9844-35f1-ad32-98f038001003'}]}),dict(event_type='smb',src_ip='10.0.0.1',dest_ip='10.0.0.2',smb={'command':'SMB2_COMMAND_CREATE','share_type':'PIPE','filename':'svcctl'})]:
    ewapp._handle(e,p,0)
ewapp.evaluate(p,{0},{0},{0})
results['documented_rpc_pipe_candidates']=len(p.sent)
# A common CDN destination never enters either beacon window.
beh._store=store.InMemoryStore();beh._pending.clear()
beh._store.kv_set('i2d:default:104.16.1.2',['example.net',0],600)
beh._handle({'event_type':'flow','src_ip':'10.0.0.1','dest_ip':'104.16.1.2','flow':{'bytes_toserver':500}},p,0,0)
beh._flush_pending()
results['cdn_beacon_windows']={'ip':beh._store.keys_matching('bc:'),'domain':beh._store.keys_matching('bf:')}
# Admission filters only SUPPRESSED, not an explicit FINAL allowlist.
results['forwarder_accepts_candidate']=len(adapters._live([{'state':'CANDIDATE'}]))
results['duplicate_builds_identical_no_admission_state']=sm.build_finding(c)==sm.build_finding(c)
# Compose interpolates only declared values into container environments.
env=dict(os.environ,CERNITY_SINK='splunk',SPLUNK_HEC_URL='https://audit.invalid',SPLUNK_HEC_TOKEN='audit-placeholder')
conf=json.loads(subprocess.check_output(['docker','compose','-f','deploy/central/docker-compose.yml','config','--format','json'],cwd=ROOT,env=env))
fe=conf['services']['findings-forwarder']['environment']
results['forwarder_env_keys']=sorted(fe)
results['central_state_backend']=conf['services']['behavioral-detectors']['environment']['NDR_STATE_BACKEND']
# Real producer candidate fails the declared finding schema.
import jsonschema
promote=module('promote','services/ids-alerts/promote.py')
alert={'event_type':'alert','src_ip':'10.0.0.1','dest_ip':'203.0.113.1','alert':{'signature_id':1,'signature':'audit','severity':1}}
cand=promote.to_candidate(alert)
errors=list(jsonschema.Draft202012Validator(json.loads((ROOT/'contracts/finding.schema.json').read_text())).iter_errors(cand))
results['ids_candidate_schema_errors']=[e.message for e in errors]
code="import sys;sys.path.insert(0,'services/ids-alerts');import promote;print(promote.to_candidate("+repr(alert)+")[\"finding_id\"])"
results['ids_ids_different_process_seeds']=[subprocess.check_output([sys.executable,'-c',code],cwd=ROOT,env=dict(os.environ,PYTHONHASHSEED=seed),text=True).strip() for seed in ['1','2']]
print(json.dumps(results,indent=2))
