const test = require('node:test');
const assert = require('node:assert/strict');
const { buildBatchQueueControlsMarkup, wireBatchQueueControls } = require('./batch_queue_ui.js');

function createFakeElement() {
  const listeners = new Map();
  return {
    listeners,
    addEventListener(eventName, handler) {
      listeners.set(eventName, handler);
    },
    dispatch(eventName, payload = {}) {
      const handler = listeners.get(eventName);
      if (handler) handler(payload);
    },
  };
}

function createFakeRoot(selectors) {
  const elements = new Map(Object.entries(selectors));
  return {
    querySelector(selector) {
      return elements.get(selector) || null;
    },
  };
}

test('buildBatchQueueControlsMarkup keeps ready-to-hand-off filter and quick action visible', () => {
  const html = buildBatchQueueControlsMarkup({
    existingFilter: 'ready',
    existingSearch: 'edge-a',
    orderedReviewCount: 6,
    filteredReviewCount: 2,
    filteredCriticalCount: 0,
    filteredFailingCount: 0,
    filteredPendingCount: 2,
    filteredReadyCount: 2,
    filteredExportIssueCount: 0,
    filteredVisibleCount: 0,
    actionableCount: 0,
    severityLabel: 'Critical only',
    severityMode: 'critical',
    currentTargetLabel: 'ServiceNow',
    disableOpenFirstReady: false,
    disableExportFirstReady: false,
    disableOpenHighestRisk: false,
    disableOpenFirstFail: true,
    disableOpenFirstCritical: true,
    disableOpenNextPending: false,
    disableExportNextPending: false,
    disableDuplicateNextPending: true,
    disableRetryFirstFailedExport: true,
    disableCopyFirstFailSummary: true,
    disableCopyFirstFallback: true,
    disableDownloadFirstFallback: true,
  });

  assert.match(html, /<option value="ready" selected>Ready to hand off<\/option>/);
  assert.match(html, /Open first visible handoff-ready review/);
  assert.match(html, /Export first visible handoff-ready review/);
  assert.match(html, /Actionable now:<\/strong> 0 visible reviews? still need work/);
  assert.match(html, /Critical only/);
  assert.match(html, /value="edge-a"/);
});

test('wireBatchQueueControls hooks filter change and ready quick action handlers', () => {
  const filter = createFakeElement();
  const search = createFakeElement();
  const openFirstReady = createFakeElement();
  const exportFirstReady = createFakeElement();
  const root = createFakeRoot({
    '#batchQueueFilter': filter,
    '#batchQueueSearch': search,
    '#batchOpenFirstReadyBtn': openFirstReady,
    '#batchExportFirstReadyBtn': exportFirstReady,
  });

  const calls = [];
  wireBatchQueueControls(root, {
    onFilterChange: () => calls.push('filter-change'),
    onSearchInput: () => calls.push('search-input'),
    onOpenFirstReady: () => calls.push('open-first-ready'),
    onExportFirstReady: () => calls.push('export-first-ready'),
  });

  filter.dispatch('change');
  search.dispatch('input');
  openFirstReady.dispatch('click');
  exportFirstReady.dispatch('click');

  assert.deepEqual(calls, [
    'filter-change',
    'search-input',
    'open-first-ready',
    'export-first-ready',
  ]);
});
