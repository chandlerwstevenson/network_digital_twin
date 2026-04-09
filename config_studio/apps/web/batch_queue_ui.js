(function (global) {
  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function buildBatchQueueControlsMarkup({
    existingFilter = 'attention',
    existingSearch = '',
    orderedReviewCount = 0,
    filteredReviewCount = 0,
    filteredCriticalCount = 0,
    filteredFailingCount = 0,
    filteredPendingCount = 0,
    filteredReadyCount = 0,
    filteredExportIssueCount = 0,
    filteredVisibleCount = 0,
    actionableCount = 0,
    severityLabel = 'All findings',
    severityMode = 'all',
    currentTargetLabel = 'Jira Cloud',
    disableOpenHighestRisk = true,
    disableOpenFirstFail = true,
    disableOpenFirstCritical = true,
    disableOpenNextPending = true,
    disableOpenFirstReady = true,
    disableExportNextPending = true,
    disableExportFirstReady = true,
    disableDuplicateNextPending = true,
    disableRetryFirstFailedExport = true,
    disableCopyFirstFailSummary = true,
    disableCopyFirstFallback = true,
    disableDownloadFirstFallback = true,
  } = {}) {
    const option = (value, label) => `<option value="${escapeHtml(value)}" ${existingFilter === value ? 'selected' : ''}>${escapeHtml(label)}</option>`;
    const button = (id, label, disabled) => `<button class="secondary-action" id="${escapeHtml(id)}" ${disabled ? 'disabled' : ''}>${escapeHtml(label)}</button>`;

    return `
      <div class="row" style="margin-top:12px;">
        <label>
          <span class="muted">Queue filter</span>
          <select id="batchQueueFilter">
            ${option('attention', 'Needs attention')}
            ${option('all', 'All reviews')}
            ${option('critical', 'Critical findings')}
            ${option('failing', 'Failing reviews')}
            ${option('pending', 'Pending handoff')}
            ${option('ready', 'Ready to hand off')}
            ${option('export-issues', 'Export issues')}
            ${option('exported', 'Already exported')}
            ${option('done', 'Marked done')}
            ${option('pass-only', 'Pass-only reviews')}
          </select>
        </label>
        <label>
          <span class="muted">Search by filename, hostname, vendor, finding, or destination</span>
          <input id="batchQueueSearch" value="${escapeHtml(existingSearch)}" placeholder="e.g. edge-a, NET-123, branch-r1, ospf" />
        </label>
      </div>
      <p><strong>Visible queue:</strong> ${filteredReviewCount} of ${orderedReviewCount} review${orderedReviewCount === 1 ? '' : 's'} · ${filteredCriticalCount} critical · ${filteredFailingCount} failing · ${filteredPendingCount} pending · ${filteredReadyCount} ready to hand off · ${filteredExportIssueCount} with export issues</p>
      ${severityMode === 'all' ? '' : `<p><strong>Threshold-visible reviews:</strong> ${filteredVisibleCount} review${filteredVisibleCount === 1 ? '' : 's'} currently surface at least one ${escapeHtml(String(severityLabel).toLowerCase())} finding.</p>`}
      <p><strong>Actionable now:</strong> ${actionableCount} visible review${actionableCount === 1 ? '' : 's'} still need work under the current threshold or have an export failure and are not marked done.</p>
      <p class="history-meta"><strong>Workspace severity threshold:</strong> ${escapeHtml(severityLabel)}. This now also drives queue ranking, card previews, and attention shortcuts instead of only changing the detail view after a review is opened.</p>
      <p class="history-meta"><strong>Needs attention</strong> now means actionable under the current threshold (or blocked by export failure), while <strong>Pending handoff</strong> remains the full not-done sweep for end-of-window cleanup.</p>
      <p class="history-meta"><strong>Ready to hand off</strong> isolates clean not-done reviews with nothing visible under the current threshold and no export problem, so you can separate export-ready devices from fix-first devices without losing the session threshold.</p>
      <p class="history-meta">Queue quick actions below now follow the current filter/search, so “next pending” and similar actions only touch what you can actually see in the visible slice.</p>
      <div class="finding-toolbar">
        ${button('batchOpenWorstBtn', 'Open highest-risk visible review', disableOpenHighestRisk)}
        ${button('batchOpenFirstFailBtn', 'Open first visible failing review', disableOpenFirstFail)}
        ${button('batchOpenFirstCriticalBtn', 'Open first visible critical review', disableOpenFirstCritical)}
        ${button('batchOpenNextPendingBtn', 'Open next visible pending handoff', disableOpenNextPending)}
        ${button('batchOpenFirstReadyBtn', 'Open first visible handoff-ready review', disableOpenFirstReady)}
        ${button('batchExportNextPendingBtn', `Export next visible pending to ${currentTargetLabel}`, disableExportNextPending)}
        ${button('batchExportFirstReadyBtn', 'Export first visible handoff-ready review', disableExportFirstReady)}
        ${button('batchDuplicateNextPendingBtn', 'Duplicate last successful handoff to next visible pending', disableDuplicateNextPending)}
        ${button('batchRetryFirstFailedExportBtn', 'Retry first visible failed export', disableRetryFirstFailedExport)}
        ${button('batchCopyFirstFailSummaryBtn', 'Copy first visible failing summary', disableCopyFirstFailSummary)}
        ${button('batchCopyFirstFallbackBtn', 'Copy first visible manual fallback', disableCopyFirstFallback)}
        ${button('batchDownloadFirstFallbackBtn', 'Download first visible fallback bundle', disableDownloadFirstFallback)}
      </div>
    `;
  }

  function wireBatchQueueControls(root, handlers = {}) {
    if (!root || typeof root.querySelector !== 'function') return;
    const on = (selector, eventName, handler) => {
      if (typeof handler !== 'function') return;
      const element = root.querySelector(selector);
      if (!element || typeof element.addEventListener !== 'function') return;
      element.addEventListener(eventName, handler);
    };

    on('#batchQueueFilter', 'change', handlers.onFilterChange);
    on('#batchQueueSearch', 'input', handlers.onSearchInput);
    on('#batchOpenWorstBtn', 'click', handlers.onOpenHighestRisk);
    on('#batchOpenFirstFailBtn', 'click', handlers.onOpenFirstFailing);
    on('#batchOpenFirstCriticalBtn', 'click', handlers.onOpenFirstCritical);
    on('#batchOpenNextPendingBtn', 'click', handlers.onOpenNextPending);
    on('#batchOpenFirstReadyBtn', 'click', handlers.onOpenFirstReady);
    on('#batchExportNextPendingBtn', 'click', handlers.onExportNextPending);
    on('#batchExportFirstReadyBtn', 'click', handlers.onExportFirstReady);
    on('#batchDuplicateNextPendingBtn', 'click', handlers.onDuplicateNextPending);
    on('#batchRetryFirstFailedExportBtn', 'click', handlers.onRetryFirstFailedExport);
    on('#batchCopyFirstFailSummaryBtn', 'click', handlers.onCopyFirstFailSummary);
    on('#batchCopyFirstFallbackBtn', 'click', handlers.onCopyFirstFallback);
    on('#batchDownloadFirstFallbackBtn', 'click', handlers.onDownloadFirstFallback);
  }

  const api = {
    buildBatchQueueControlsMarkup,
    wireBatchQueueControls,
  };

  global.ConfigStudioBatchQueueUi = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
