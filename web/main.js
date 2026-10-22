import { createHelia } from 'helia';
import { unixfs } from '@helia/unixfs';
import repoFiles from 'virtual:repo-files';

let heliaNode = null;
let heliaUnixfs = null;
let rootCid = null;

const statusEl = document.getElementById('status');
const cidEl = document.getElementById('root-cid');
const treeEl = document.getElementById('file-tree');

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function init() {
  statusEl.textContent = 'Starting Helia node...';
  heliaNode = await createHelia();
  heliaUnixfs = unixfs(heliaNode);
  statusEl.textContent = 'Adding registry files to IPFS...';

  const candidates = Object.entries(repoFiles).map(([p, b64]) => ({
    path: p,
    content: base64ToUint8Array(b64)
  }));

  let lastCid = null;
  for await (const entry of heliaUnixfs.addAll(candidates, { wrapWithDirectory: true })) {
    lastCid = entry.cid;
    if (entry.path) {
      // track per-file CIDs
    }
  }
  rootCid = lastCid;
  cidEl.textContent = rootCid ? rootCid.toString() : 'none';
  statusEl.textContent = 'Online — all files added to IPFS';

  // Announce
  if (heliaNode.routing && typeof heliaNode.routing.provide === 'function') {
    heliaNode.routing.provide(rootCid).catch(() => {});
  }

  // Render file tree
  const paths = Object.keys(repoFiles).sort();
  const ul = document.createElement('ul');
  for (const p of paths) {
    const li = document.createElement('li');
    li.textContent = p;
    li.style.cursor = 'pointer';
    li.addEventListener('click', async () => {
      const bytes = base64ToUint8Array(repoFiles[p]);
      const text = new TextDecoder().decode(bytes);
      document.getElementById('file-content').textContent = text.slice(0, 2000);
    });
    ul.appendChild(li);
  }
  treeEl.appendChild(ul);
}

init().catch(err => {
  statusEl.textContent = 'Error: ' + err.message;
  console.error(err);
});