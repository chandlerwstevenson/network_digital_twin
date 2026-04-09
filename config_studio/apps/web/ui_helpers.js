(function (global) {
  function normalizeSearchTerm(term) {
    return String(term || '').trim().toLowerCase();
  }

  function getConfigSearchMatches(linesOrText, term) {
    const normalizedTerm = normalizeSearchTerm(term);
    if (!normalizedTerm) return [];
    const lines = Array.isArray(linesOrText)
      ? linesOrText.map(line => String(line || ''))
      : String(linesOrText || '').split(/\r?\n/);
    return lines.reduce((matches, line, index) => {
      if (String(line || '').toLowerCase().includes(normalizedTerm)) {
        matches.push(index + 1);
      }
      return matches;
    }, []);
  }

  function hasExportIssue(exportStatus) {
    return Boolean(exportStatus && !['success', 'unknown'].includes(String(exportStatus)));
  }

  function getBatchQueueActionability({ progressDone = false, visibleFindingCount = 0, latestExportStatus = null } = {}) {
    return Boolean(!progressDone && (Number(visibleFindingCount || 0) > 0 || hasExportIssue(latestExportStatus)));
  }

  function getBatchQueueHandoffReadiness({ progressDone = false, exported = false, visibleFindingCount = 0, latestExportStatus = null } = {}) {
    return Boolean(!progressDone && !exported && Number(visibleFindingCount || 0) === 0 && !hasExportIssue(latestExportStatus));
  }

  function matchesBatchQueueFilter(filter, {
    passFail = true,
    progressDone = false,
    exported = false,
    visibleSummary = {},
    latestExportStatus = null,
  } = {}) {
    const summary = {
      critical: Number(visibleSummary.critical || 0),
      warning: Number(visibleSummary.warning || 0),
      info: Number(visibleSummary.info || 0),
      total: Number(visibleSummary.total || 0),
    };
    const exportIssue = hasExportIssue(latestExportStatus);
    const actionableNow = getBatchQueueActionability({
      progressDone,
      visibleFindingCount: summary.total,
      latestExportStatus,
    });
    const handoffReady = getBatchQueueHandoffReadiness({
      progressDone,
      exported,
      visibleFindingCount: summary.total,
      latestExportStatus,
    });
    if (filter === 'critical') return summary.critical > 0;
    if (filter === 'failing') return !passFail && summary.total > 0;
    if (filter === 'pending') return !progressDone;
    if (filter === 'ready') return handoffReady;
    if (filter === 'export-issues') return exportIssue;
    if (filter === 'exported') return Boolean(exported);
    if (filter === 'done') return Boolean(progressDone);
    if (filter === 'pass-only') return Boolean(passFail);
    if (filter === 'attention') return actionableNow;
    return true;
  }

  function buildBatchQueueSearchCorpus({
    filename,
    hostname,
    vendor,
    osVersion,
    latestExportTarget,
    latestExportDestination,
    findingTitles = [],
  } = {}) {
    return [
      filename,
      hostname,
      vendor,
      osVersion,
      latestExportTarget,
      latestExportDestination,
      ...findingTitles,
    ].filter(Boolean).join(' ').toLowerCase();
  }

  const api = {
    normalizeSearchTerm,
    getConfigSearchMatches,
    hasExportIssue,
    getBatchQueueActionability,
    getBatchQueueHandoffReadiness,
    matchesBatchQueueFilter,
    buildBatchQueueSearchCorpus,
  };

  global.ConfigStudioUiHelpers = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
