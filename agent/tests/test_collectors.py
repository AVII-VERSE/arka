from arka_agent.collectors.linux_syslog import LinuxSyslogCollector
from arka_agent.collectors.windows_event_log import WindowsEventLogCollector


def test_windows_collector():
    collector = WindowsEventLogCollector(agent_id="test-agent", tenant_id="tenant-1")
    events = collector.collect()
    assert len(events) > 0
    event = events[0]
    assert event["source_type"] == "windows_event_log"
    assert event["tenant_id"] == "tenant-1"
    assert "event_id" in event


def test_linux_collector():
    collector = LinuxSyslogCollector(agent_id="test-agent", tenant_id="tenant-1")
    events = collector.collect()
    assert len(events) > 0
    event = events[0]
    assert event["source_type"] == "linux_syslog"
    assert event["tenant_id"] == "tenant-1"
