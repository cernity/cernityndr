import pathlib,json
from kafka import KafkaProducer
p=pathlib.Path('/tmp/cernity-audit')
base=dict(bootstrap_servers='127.0.0.1:19092',api_version_auto_timeout_ms=3000,request_timeout_ms=4000,max_block_ms=4000,value_serializer=lambda v:json.dumps(v).encode())
out={}
for name,extra in [('unauthenticated',{}),('authenticated',dict(security_protocol='SASL_SSL',sasl_mechanism='SCRAM-SHA-512',sasl_plain_username='cernity-sensor',sasl_plain_password=(p/'secrets/bus_password.txt').read_text(),ssl_cafile=str(p/'secrets/ca.crt')))]:
 try:
  producer=KafkaProducer(**base,**extra)
  out[name]='connected'
  if name=='authenticated':
   producer.send('ndr.finding.final.v1',{'finding_id':'audit-sensor-forged-final','category':'discovery','state':'FINAL','severity':9}).get(timeout=10)
   out['sensor_can_publish_final']='yes'
  producer.close()
 except Exception as e:out[name]=type(e).__name__
print(json.dumps(out,indent=2))
