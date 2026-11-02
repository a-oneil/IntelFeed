"""How Celery obeys the engine switch (``app/services/engine_switch.py``).

- ``EngineSwitchStep`` runs inside every worker. It reads the setting every
  ``POLL_SECONDS`` and stops or resumes taking tasks off the queues the
  worker was started with. On a start it runs one process at a time at
  first and adds one back every ``RAMP_SECONDS``, so a backlog drains
  gradually.
- ``GatedTask`` is the base class of every task. It catches tasks a worker
  had already taken before it noticed the stop: a scheduled job is dropped
  (beat sends it again next time); any other task goes back to the end of
  its queue.
- ``EngineScheduler`` is beat's scheduler. It sends nothing while the engine
  is stopped, so a missed job runs at its next normal time instead of all at
  once.

Tasks and queues added later are covered without any change here.
"""

import logging
import time

from celery import Task, bootsteps
from celery.beat import PersistentScheduler
from celery.exceptions import Ignore

from app.services import engine_switch

logger = logging.getLogger(__name__)

#: Seconds between a worker's reads of the setting: how soon it stops taking tasks.
POLL_SECONDS = 10.0
#: After a start, seconds between each process a worker adds back.
RAMP_SECONDS = 60.0


class GatedTask(Task):
    def __call__(self, *args, **kwargs):
        req = self.request
        if req.called_directly or req.is_eager or not engine_switch.is_stopped():
            return super().__call__(*args, **kwargs)
        from app.workers.task_tracking import KNOWN_JOB_TASKS

        if self.name in KNOWN_JOB_TASKS:
            logger.info("Engine stopped: dropped scheduled job %s", self.name)
        else:
            # Same id and options, like a retry. Until the consumer cancels its
            # queues (within POLL_SECONDS) the task can come straight back and
            # go round again; each pass logs once.
            self.signature_from_request().apply_async()
            logger.info("Engine stopped: put %s back on its queue", self.name)
        raise Ignore()


class EngineSwitchStep(bootsteps.StartStopStep):
    requires = {"celery.worker.consumer.tasks:Tasks"}

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.queues: list[str] | None = None
        self.full_size: int | None = None
        self.stopped = False
        self.ramp_at = 0.0
        self.tref = None

    def start(self, c):
        # Taken once: after a stop the queues drop out of the consumer's own
        # list, and a reconnect calls start again.
        if self.queues is None:
            self.queues = [q.name for q in c.task_consumer.queues]
            self.full_size = c.pool.num_processes
        self.check(c)
        self.tref = c.timer.call_repeatedly(POLL_SECONDS, self.check, (c,), priority=10)

    def stop(self, c):
        if self.tref is not None:
            self.tref.cancel()
            self.tref = None

    def check(self, c):
        try:
            stopped = engine_switch.is_stopped(fresh=True)
            if stopped == self.stopped:
                if not stopped:
                    self.ramp_up(c)
                return
            if not stopped:
                self.scale_down(c)
            for queue in self.queues:
                if stopped:
                    c.cancel_task_queue(queue)
                else:
                    c.add_task_queue(queue)
            self.stopped = stopped
            logger.warning("Engine %s: %s", "stopped" if stopped else "started", ", ".join(self.queues))
        except Exception:
            logger.exception("Engine switch check failed")

    def scale_down(self, c):
        """Start on one process, so the backlog a stop left behind doesn't
        all hit the database at once. ``ramp_up`` adds the rest back."""
        while c.pool.num_processes > 1:
            try:
                c.pool.shrink(1)
            except (ValueError, NotImplementedError):
                # The rest are still busy, or the pool (solo, threads) doesn't resize.
                break
            c._update_prefetch_count(-1)
        self.ramp_at = time.monotonic() + RAMP_SECONDS

    def ramp_up(self, c):
        """Add a process back every ``RAMP_SECONDS`` until the worker is at
        the size it was started with."""
        if c.pool.num_processes >= self.full_size:
            return
        if time.monotonic() < self.ramp_at:
            return
        c.pool.grow(1)
        c._update_prefetch_count(1)
        self.ramp_at = time.monotonic() + RAMP_SECONDS
        logger.info("Engine starting: %d of %d processes", c.pool.num_processes, self.full_size)


class EngineScheduler(PersistentScheduler):
    def apply_entry(self, entry, producer=None):
        if engine_switch.is_stopped():
            logger.info("Engine stopped: not sending %s", entry.name)
            return
        super().apply_entry(entry, producer=producer)
