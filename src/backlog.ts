// One model call at a time, with a hard cap on what may wait. Under a flood of alerts the
// board answers "AI skipped" at once instead of queueing hours of model calls; the rule's
// alert is never delayed or dropped, only the advisory reading.

export const MAX_WAITING_MODEL_CALLS = 16;

export class Backlog {
  private tail: Promise<void> = Promise.resolve();
  private waiting = 0;

  constructor(readonly max = MAX_WAITING_MODEL_CALLS) {}

  get size() {
    return this.waiting;
  }

  /** Queue `task`, or call `skip` right away when `max` calls are already waiting. Returns false when skipped. */
  run(task: () => Promise<void>, skip: () => void): boolean {
    if (this.waiting >= this.max) {
      skip();
      return false;
    }
    this.waiting += 1;
    this.tail = this.tail.then(task).catch(() => {}).finally(() => { this.waiting -= 1; });
    return true;
  }

  /** Resolves when every queued call has finished. */
  idle(): Promise<void> {
    return this.tail;
  }
}
