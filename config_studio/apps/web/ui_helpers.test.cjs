const test = require('node:test');
const assert = require('node:assert/strict');
const {
  getConfigSearchMatches,
  hasExportIssue,
  getBatchQueueActionability,
  getBatchQueueHandoffReadiness,
  matchesBatchQueueFilter,
  buildBatchQueueSearchCorpus,
} = require('./ui_helpers.js');

test('getConfigSearchMatches returns matching line numbers case-insensitively', () => {
  const lines = [
    'interface GigabitEthernet0/0',
    ' description Uplink to core',
    ' ip access-group ACL-IN in',
    'router ospf 1',
  ];
  assert.deepEqual(getConfigSearchMatches(lines, 'acl-in'), [3]);
  assert.deepEqual(getConfigSearchMatches(lines, 'INTERFACE'), [1]);
  assert.deepEqual(getConfigSearchMatches(lines, 'missing-term'), []);
  assert.deepEqual(getConfigSearchMatches(lines, '   '), []);
});

test('hasExportIssue only flags non-successful concrete export states', () => {
  assert.equal(hasExportIssue('success'), false);
  assert.equal(hasExportIssue('unknown'), false);
  assert.equal(hasExportIssue('partial'), true);
  assert.equal(hasExportIssue('failed'), true);
  assert.equal(hasExportIssue(null), false);
});

test('getBatchQueueActionability matches needs-attention semantics', () => {
  assert.equal(getBatchQueueActionability({ progressDone: false, visibleFindingCount: 2, latestExportStatus: 'success' }), true);
  assert.equal(getBatchQueueActionability({ progressDone: false, visibleFindingCount: 0, latestExportStatus: 'partial' }), true);
  assert.equal(getBatchQueueActionability({ progressDone: true, visibleFindingCount: 3, latestExportStatus: 'failed' }), false);
  assert.equal(getBatchQueueActionability({ progressDone: false, visibleFindingCount: 0, latestExportStatus: 'success' }), false);
});

test('getBatchQueueHandoffReadiness only flags clean pending reviews that are not already exported', () => {
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: false, exported: false, visibleFindingCount: 0, latestExportStatus: 'success' }), true);
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: false, exported: false, visibleFindingCount: 0, latestExportStatus: null }), true);
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: false, exported: false, visibleFindingCount: 2, latestExportStatus: 'success' }), false);
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: false, exported: false, visibleFindingCount: 0, latestExportStatus: 'partial' }), false);
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: false, exported: true, visibleFindingCount: 0, latestExportStatus: 'success' }), false);
  assert.equal(getBatchQueueHandoffReadiness({ progressDone: true, exported: false, visibleFindingCount: 0, latestExportStatus: 'success' }), false);
});

test('matchesBatchQueueFilter keeps attention focused on actionable-now items', () => {
  const base = {
    passFail: false,
    progressDone: false,
    exported: false,
    visibleSummary: { critical: 0, warning: 1, info: 0, total: 1 },
    latestExportStatus: 'success',
  };
  assert.equal(matchesBatchQueueFilter('attention', base), true);
  assert.equal(matchesBatchQueueFilter('pending', base), true);
  assert.equal(matchesBatchQueueFilter('failing', base), true);
  assert.equal(matchesBatchQueueFilter('critical', base), false);
  assert.equal(matchesBatchQueueFilter('done', base), false);
  assert.equal(matchesBatchQueueFilter('pass-only', base), false);
});

test('matchesBatchQueueFilter includes export issues even when no visible findings remain', () => {
  const exportIssueOnly = {
    passFail: true,
    progressDone: false,
    exported: true,
    visibleSummary: { critical: 0, warning: 0, info: 0, total: 0 },
    latestExportStatus: 'partial',
  };
  assert.equal(matchesBatchQueueFilter('attention', exportIssueOnly), true);
  assert.equal(matchesBatchQueueFilter('export-issues', exportIssueOnly), true);
  assert.equal(matchesBatchQueueFilter('pass-only', exportIssueOnly), true);
  assert.equal(matchesBatchQueueFilter('ready', exportIssueOnly), false);
});

test('matchesBatchQueueFilter exposes handoff-ready clean reviews separately from pending', () => {
  const cleanPending = {
    passFail: true,
    progressDone: false,
    exported: false,
    visibleSummary: { critical: 0, warning: 0, info: 0, total: 0 },
    latestExportStatus: 'success',
  };
  assert.equal(matchesBatchQueueFilter('ready', cleanPending), true);
  assert.equal(matchesBatchQueueFilter('pending', cleanPending), true);
  assert.equal(matchesBatchQueueFilter('attention', cleanPending), false);

  const alreadyExported = { ...cleanPending, exported: true };
  assert.equal(matchesBatchQueueFilter('ready', alreadyExported), false);
  assert.equal(matchesBatchQueueFilter('exported', alreadyExported), true);
});

test('buildBatchQueueSearchCorpus includes queue metadata and finding titles', () => {
  const corpus = buildBatchQueueSearchCorpus({
    filename: 'edge-router-1.cfg',
    hostname: 'EDGE-RTR-1',
    vendor: 'Cisco IOS-XE',
    osVersion: '17.9',
    latestExportTarget: 'ServiceNow',
    latestExportDestination: 'CHG123456',
    findingTitles: ['HTTP server enabled without HTTPS', 'ACL shadowing detected'],
  });
  assert.match(corpus, /edge-router-1\.cfg/);
  assert.match(corpus, /chg123456/);
  assert.match(corpus, /acl shadowing detected/);
});
