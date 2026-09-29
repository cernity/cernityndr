"""Sensor health daemon; shared Kafka security settings, bounded delivery wait."""
import json
import os
import signal
import threading

from agent import Agent, EveRates, Resources, TOPIC
from ndr_runtime import make_producer, setup_logging


def main():
    setup_logging('sensor-agent')
    agent = Agent(os.environ['NDR_SENSOR_UUID'], os.environ['NDR_TENANT'],
                  os.environ['NDR_SITE'],
                  versions=json.loads(os.environ.get('SENSOR_VERSIONS', '{}')),
                  resources=Resources(os.environ.get('HOST_PROC', '/proc'),
                                      os.environ.get('SENSOR_DISK_PATH', '/')),
                  eve=EveRates([p for p in os.environ.get('SENSOR_EVE_PATHS', '').split(',') if p]),
                  metrics_path=os.environ.get('SENSOR_METRICS_PATH'))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    # JSON array gives an unambiguous tenant + immutable sensor partition key.
    key = json.dumps([agent.tenant, agent.sensor_uuid], separators=(',', ':')).encode()
    producer = None

    def publish(record):
        nonlocal producer
        if producer is None:
            producer = make_producer(acks='all', compression_type=None, max_block_ms=5000,
                                     value_serializer=lambda v: json.dumps(v, allow_nan=False).encode())
        producer.send(TOPIC, key=key, value=record).get(timeout=5)

    try:
        agent.run(publish, stop, float(os.environ.get('SENSOR_HEARTBEAT_SECONDS', '30')))
    finally:
        if producer is not None:
            producer.close(timeout=5)


if __name__ == '__main__':
    main()
