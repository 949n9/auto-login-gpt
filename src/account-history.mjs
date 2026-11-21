// History uses the existing authenticated, encrypted record store.
export function createAccountHistory(database) {
  function read(job) {
    return database.get('account-history', job.id) || {
      firstAddedAt: database.getJob(job.id)?.created_at || null,
      recordedSince: new Date().toISOString(),
      legacy: true,
      events: [],
    };
  }
  function save(job, history) {
    if (!job.deleted) database.put('account-history', job.id, history);
  }
  return {
    initialize(job) {
      if (!database.get('account-history', job.id)) save(job, {
        firstAddedAt: job.createdAt, recordedSince: job.createdAt, legacy: false, events: [],
      });
    },
    start(job, id, mode, source) {
      const history = read(job);
      if (history.events.some((event) => event.id === id)) return;
      for (const event of history.events) if (event.status === 'running') event.status = 'unknown';
      history.events.push({ id, mode, source, startedAt: new Date().toISOString(), completedAt: null, status: 'running' });
      save(job, history);
      job.historyRunId = id;
    },
    finish(job) {
      if (!job.historyRunId || !['completed', 'failed', 'canceled', 'reauth_required', 'resume_available'].includes(job.status)) return;
      const history = read(job);
      const event = history.events.find((item) => item.id === job.historyRunId);
      if (event && event.status === 'running') {
        event.status = job.status;
        event.completedAt = new Date().toISOString();
        save(job, history);
      }
    },
    detail(job, page = 1) {
      const history = read(job);
      const total = history.events.length;
      const pages = Math.max(1, Math.ceil(total / 50));
      page = Math.min(pages, Math.max(1, Number.parseInt(page, 10) || 1));
      return { ...history, events: history.events.slice().reverse().slice((page - 1) * 50, page * 50), total, page, pages };
    },
  };
}
