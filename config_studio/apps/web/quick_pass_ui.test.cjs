const test = require('node:test');
const assert = require('node:assert/strict');
const { applyQuickPassUiMode, getQuickPassFindingsToolbarNote } = require('./quick_pass_ui.js');

function createFakeDocument(ids) {
  const nodes = new Map(ids.map((id) => [id, { id, style: { display: '' }, textContent: '' }]));
  return {
    getElementById(id) {
      return nodes.get(id) || null;
    },
    nodes,
  };
}

test('getQuickPassFindingsToolbarNote explains both quick-pass and normal states', () => {
  assert.match(getQuickPassFindingsToolbarNote(true), /Quick-pass is active/);
  assert.match(getQuickPassFindingsToolbarNote(false), /remembered for the current browser session/);
});

test('applyQuickPassUiMode hides nonessential workspace sections when quick-pass is active for a loaded review', () => {
  const doc = createFakeDocument([
    'templateAuthoringSection',
    'configNavigatorSection',
    'multiConfigSection',
    'compareSection',
    'reportHeaderPanel',
    'templateCompliancePanel',
    'changeScriptPanel',
    'worklistPanel',
    'exportPanel',
    'batchWorkspaceNavigator',
    'queryPanel',
    'findingsToolbarRow',
    'findingsToolbarNote',
  ]);

  const result = applyQuickPassUiMode(doc, { active: true, hasReview: true });

  assert.equal(result.active, true);
  assert.deepEqual(result.hiddenSectionIds, [
    'templateAuthoringSection',
    'configNavigatorSection',
    'multiConfigSection',
    'compareSection',
  ]);
  assert.equal(doc.getElementById('templateAuthoringSection').style.display, 'none');
  assert.equal(doc.getElementById('configNavigatorSection').style.display, 'none');
  assert.equal(doc.getElementById('queryPanel').style.display, 'none');
  assert.equal(doc.getElementById('findingsToolbarRow').style.display, 'none');
  assert.match(doc.getElementById('findingsToolbarNote').textContent, /Quick-pass is active/);
});

test('applyQuickPassUiMode restores full workspace when quick-pass is off or no review is loaded', () => {
  const doc = createFakeDocument([
    'templateAuthoringSection',
    'configNavigatorSection',
    'multiConfigSection',
    'compareSection',
    'reportHeaderPanel',
    'templateCompliancePanel',
    'changeScriptPanel',
    'worklistPanel',
    'exportPanel',
    'batchWorkspaceNavigator',
    'queryPanel',
    'findingsToolbarRow',
    'findingsToolbarNote',
  ]);

  applyQuickPassUiMode(doc, { active: true, hasReview: true });
  const restored = applyQuickPassUiMode(doc, { active: false, hasReview: true });
  assert.equal(restored.active, false);
  assert.equal(doc.getElementById('templateAuthoringSection').style.display, '');
  assert.equal(doc.getElementById('queryPanel').style.display, '');
  assert.match(doc.getElementById('findingsToolbarNote').textContent, /remembered for the current browser session/);

  const noReview = applyQuickPassUiMode(doc, { active: true, hasReview: false });
  assert.equal(noReview.active, false);
  assert.equal(doc.getElementById('exportPanel').style.display, '');
});
