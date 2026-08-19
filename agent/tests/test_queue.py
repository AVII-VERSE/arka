import os
import uuid

from arka_agent.buffer.sqlite_queue import SQLiteQueue


def test_sqlite_queue_push_pop(tmp_path):
    db_file = os.path.join(tmp_path, "test_queue.db")
    queue = SQLiteQueue(db_path=db_file)

    event1 = {"event_id": str(uuid.uuid4()), "message": "Test Event 1"}
    event2 = {"event_id": str(uuid.uuid4()), "message": "Test Event 2"}

    queue.push(event1)
    queue.push(event2)

    assert queue.size() == 2

    batch = queue.pop_batch(batch_size=1)
    assert len(batch) == 1
    assert batch[0]["message"] == "Test Event 1"

    queue.delete_batch(batch_size=1)
    assert queue.size() == 1
