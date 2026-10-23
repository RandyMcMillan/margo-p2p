import { createHelia } from "helia";
import { unixfs } from "@helia/unixfs";
import repoFiles from "virtual:repo-files";

let heliaNode = null;
let heliaUnixfs = null;
let rootCid = null;

const statusEl = document.getElementById("status");
const cidEl = document.getElementById("root-cid");
const treeEl = document.getElementById("file-tree");
const contentEl = document.getElementById("file-content");
const crateTableBody = document.querySelector("#crate-table tbody");

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Custom element: copy button
class MgCopy extends HTMLElement {
  connectedCallback() {
    const button = this.querySelector('[data-target="copy"]');
    const state0 = this.querySelector('[data-target="state0"]');
    const state1 = this.querySelector('[data-target="state1"]');
    if (!button || !state0 || !state1) return;
    const swapState = () => {
      state0.classList.toggle("invisible");
      state1.classList.toggle("invisible");
    };
    button.addEventListener("click", (evt) => {
      evt.preventDefault();
      const content = this.querySelector('[data-target="content"]');
      const text = content?.textContent;
      if (!text) return;
      navigator.clipboard.writeText(text);
      swapState();
      setTimeout(swapState, 1000);
    });
    button.classList.remove("hidden");
  }
}
window.customElements.define("mg-copy", MgCopy);

async function init() {
  statusEl.textContent = "Starting Helia node...";
  heliaNode = await createHelia();
  heliaUnixfs = unixfs(heliaNode);
  statusEl.textContent = "Adding registry files to IPFS...";

  const candidates = Object.entries(repoFiles).map(([p, b64]) => ({
    path: p,
    content: base64ToUint8Array(b64),
  }));

  let lastCid = null;
  for await (const entry of heliaUnixfs.addAll(candidates, {
    wrapWithDirectory: true,
  })) {
    lastCid = entry.cid;
  }
  rootCid = lastCid;
  cidEl.textContent = rootCid ? rootCid.toString() : "none";
  statusEl.textContent = "Online — all files added to IPFS";

  // Announce
  if (heliaNode.routing && typeof heliaNode.routing.provide === "function") {
    heliaNode.routing.provide(rootCid).catch(() => {});
    for (const cidStr of new Set([...Object.values(repoFiles)]).values()) {
    } // noop
  }

  // Render file tree
  const paths = Object.keys(repoFiles).sort();
  const ul = document.createElement("ul");
  for (const p of paths) {
    const li = document.createElement("li");
    li.textContent = "📄 " + p;
    li.addEventListener("click", () => {
      const bytes = base64ToUint8Array(repoFiles[p]);
      const text = new TextDecoder().decode(bytes);
      contentEl.textContent = text.slice(0, 5000);
    });
    ul.appendChild(li);
  }
  treeEl.appendChild(ul);

  // Parse and render crate list from index entries
  const crateMap = new Map();
  for (const p of paths) {
    if (
      p.includes("/crates/") ||
      p === "config.json" ||
      p.endsWith(".html") ||
      p.endsWith(".css") ||
      p.endsWith(".js")
    )
      continue;
    // Index entries are at de/mo/demo-crate etc.
    try {
      const bytes = base64ToUint8Array(repoFiles[p]);
      const text = new TextDecoder().decode(bytes);
      for (const line of text.trim().split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          if (entry.name && entry.vers) {
            if (!crateMap.has(entry.name)) crateMap.set(entry.name, []);
            crateMap.get(entry.name).push(entry.vers);
          }
        } catch {}
      }
    } catch {}
  }
  for (const [name, versions] of crateMap) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = name;
    const tdVer = document.createElement("td");
    const select = document.createElement("select");
    for (const v of versions) {
      const opt = document.createElement("option");
      opt.textContent = v;
      select.appendChild(opt);
    }
    tdVer.appendChild(select);
    tr.appendChild(tdName);
    tr.appendChild(tdVer);
    crateTableBody.appendChild(tr);
  }

  // Fetch by CID
  document.getElementById("fetch-btn").addEventListener("click", async () => {
    const cidStr = document.getElementById("cid-input").value.trim();
    if (!cidStr) return;
    const resultEl = document.getElementById("fetch-result");
    resultEl.textContent = "Fetching...";
    try {
      const cid = (await import("multiformats/cid")).CID.parse(cidStr);
      const bytes = await heliaUnixfs.cat(cid);
      const chunks = [];
      for await (const chunk of bytes) chunks.push(chunk);
      const data = new Uint8Array(chunks.reduce((a, b) => a + b.length, 0));
      let off = 0;
      for (const c of chunks) {
        data.set(c, off);
        off += c.length;
      }
      const text = new TextDecoder().decode(data);
      resultEl.textContent = `Fetched ${data.length} bytes:\n${text.slice(0, 500)}`;
    } catch (err) {
      resultEl.textContent = "Error: " + err.message;
    }
  });
}

init().catch((err) => {
  statusEl.textContent = "Error: " + err.message;
  console.error(err);
});
