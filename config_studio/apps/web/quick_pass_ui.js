(function (global) {
  function setVisible(element, visible) {
    if (!element) return;
    element.style.display = visible ? '' : 'none';
  }

  function getQuickPassFindingsToolbarNote(active) {
    return active
      ? 'Quick-pass is active: the UI is locked to critical findings only and hides export, compliance, query, and config-navigation detail so the answer fits on one screen.'
      : 'This threshold is remembered for the current browser session and now carries through the workspace so engineers can keep the same triage posture during a change window.';
  }

  function applyQuickPassUiMode(doc, { active = false, hasReview = false } = {}) {
    const enabled = Boolean(active && hasReview);
    const sectionIds = ['templateAuthoringSection', 'configNavigatorSection', 'multiConfigSection', 'compareSection'];
    const panelIds = ['reportHeaderPanel', 'templateCompliancePanel', 'changeScriptPanel', 'worklistPanel', 'exportPanel', 'batchWorkspaceNavigator', 'queryPanel', 'findingsToolbarRow'];

    sectionIds.forEach((id) => setVisible(doc?.getElementById?.(id), !enabled));
    panelIds.forEach((id) => setVisible(doc?.getElementById?.(id), !enabled));

    const findingsNote = doc?.getElementById?.('findingsToolbarNote');
    if (findingsNote) {
      findingsNote.textContent = getQuickPassFindingsToolbarNote(enabled);
    }

    return {
      active: enabled,
      hiddenSectionIds: enabled ? sectionIds : [],
      hiddenPanelIds: enabled ? panelIds : [],
      findingsToolbarNote: getQuickPassFindingsToolbarNote(enabled),
    };
  }

  const api = {
    applyQuickPassUiMode,
    getQuickPassFindingsToolbarNote,
  };

  global.ConfigStudioQuickPassUi = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
