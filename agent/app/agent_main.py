from __future__ import annotations

import logging
import time

from agent.app.commands.poller import CommandPoller
from agent.app.config import config_fingerprint, load_config
from agent.app.queue.sqlite_queue import SQLiteQueue
from agent.app.sender.batch_sender import BatchSender
from agent.app.telemetry.heartbeat import agent_boot_event, heartbeat_event


def run(max_loops: int | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = load_config()
    queue = SQLiteQueue(cfg.queue_path, cfg.queue_max_size)
    sender = BatchSender(queue=queue, batch_size=cfg.batch_size)
    poller = CommandPoller()

    queue.enqueue(heartbeat_event(cfg.tenant_id, cfg.agent_id))
    queue.enqueue(agent_boot_event(cfg.tenant_id, cfg.agent_id, cfg.agent_version, config_fingerprint(cfg)))

    loops = 0
    while True:
        try:
            sender_result = sender.flush_once()
            poller.poll_once()
            if loops % 12 == 0:
                logging.info(
                    "agent_health queue_depth=%s last_success_at=%s rate_limited=%s sender_status=%s",
                    queue.size(),
                    sender.last_success_at,
                    sender.rate_limited_count,
                    sender_result.get("status"),
                )
        except Exception as exc:  # crash guard
            logging.exception("agent_loop_error: %s", exc)
        finally:
            time.sleep(max(0.2, cfg.flush_interval_s))
        loops += 1
        if max_loops is not None and loops >= max_loops:
            return


if __name__ == "__main__":
    run()
