/* Spammy Web UI – minimal vanilla JS */

// Auto-poll for pending/running jobs (fallback if meta-refresh is off)
(function () {
  const jobId = document.body.dataset.jobId;
  if (!jobId) return;
  const state = document.body.dataset.jobState;
  if (state !== 'pending' && state !== 'running') return;

  setTimeout(() => location.reload(), 2000);
})();
