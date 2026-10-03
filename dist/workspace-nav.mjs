const main = document.querySelector('main');
const intro = main.querySelector('.intro-grid');
const historyPanel = intro.querySelector('.history-panel');
const results = document.getElementById('results');
const batchPanel = main.querySelector('.batch-panel');
const scanPanel = main.querySelector('.local-scan-panel');
const methodNote = main.querySelector('.method-note');

const definitions = [
  ['investigate', 'Investigate', 'Public IP, domain, map, and evidence'],
  ['history', 'History', 'Previous investigations'],
  ['scanner', 'Local scanner', 'Connected devices and ports'],
  ['compare', 'Compare', 'Small target sets']
];
const nav = document.createElement('nav');
nav.className = 'workspace-menu';
nav.setAttribute('aria-label', 'Workspace menu');
const navTitle = document.createElement('span');
navTitle.className = 'eyebrow';
navTitle.textContent = 'MENU / WORKSPACES';
nav.append(navTitle);
const panes = new Map();
const buttons = new Map();
for (const [key, title, description] of definitions) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'workspace-menu-button';
  button.dataset.workspace = key;
  button.setAttribute('aria-controls', `workspace-${key}`);
  button.innerHTML = `<strong>${title}</strong><small>${description}</small>`;
  nav.append(button);
  buttons.set(key, button);
  const pane = document.createElement('div');
  pane.className = 'workspace-pane';
  pane.id = `workspace-${key}`;
  pane.hidden = true;
  panes.set(key, pane);
}
intro.classList.add('solo-intro');
panes.get('investigate').append(intro, results, methodNote);
panes.get('history').append(historyPanel);
panes.get('scanner').append(scanPanel);
panes.get('compare').append(batchPanel);
main.replaceChildren(nav, ...panes.values());

function showWorkspace(key, scroll = true) {
  if (!panes.has(key)) key = 'investigate';
  for (const [name, pane] of panes) {
    const active = name === key;
    pane.hidden = !active;
    buttons.get(name).classList.toggle('active', active);
    buttons.get(name).setAttribute('aria-current', active ? 'page' : 'false');
  }
  if (scroll) nav.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (key === 'investigate') window.dispatchEvent(new Event('workspace-map-visible'));
}
for (const [key, button] of buttons) button.addEventListener('click', () => {
  showWorkspace(key);
  history.replaceState(null, '', `#${key}`);
});
window.addEventListener('hashchange', () => showWorkspace(location.hash.slice(1), false));
showWorkspace(location.hash.slice(1), false);

const heading = results.querySelector('.result-heading');
const resultNav = document.createElement('nav');
resultNav.className = 'result-menu';
resultNav.setAttribute('aria-label', 'Investigation sections');
const resultGroups = [
  ['map', 'Map & network', [results.querySelector('.map-panel'), results.querySelector('#ips-body').closest('section'), results.querySelector('#network-content').closest('.two-column')]],
  ['recon', 'Recon & hostnames', [results.querySelector('.recon-grid'), results.querySelector('#web-heading').closest('section'), results.querySelector('#hosts-heading').closest('section')]],
  ['case', 'Evidence & export', [results.querySelector('#evidence-heading').closest('section'), results.querySelector('.export-panel')]]
];
const resultButtons = new Map();
for (const [key, label, sections] of resultGroups) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.className = 'result-menu-button';
  button.addEventListener('click', () => showResultGroup(key));
  resultNav.append(button);
  resultButtons.set(key, button);
  for (const section of sections) section.dataset.resultGroup = key;
}
heading.after(resultNav);
function showResultGroup(key) {
  for (const [name, , sections] of resultGroups) {
    const active = key === name;
    resultButtons.get(name).classList.toggle('active', active);
    resultButtons.get(name).setAttribute('aria-current', active ? 'page' : 'false');
    for (const section of sections) section.hidden = !active;
  }
  if (key === 'map') window.dispatchEvent(new Event('workspace-map-visible'));
}
showResultGroup('map');

document.getElementById('history-list').addEventListener('click', event => {
  if (!event.target.closest('.history-item')) return;
  showWorkspace('investigate', false);
  showResultGroup('map');
  history.replaceState(null, '', '#investigate');
}, true);
document.getElementById('investigate-form').addEventListener('submit', () => showResultGroup('map'), true);
document.getElementById('example-button').addEventListener('click', () => showResultGroup('map'), true);
