import { defineConfig } from "vite";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

function repoFilesPlugin() {
  const virtualId = "virtual:repo-files";
  const resolvedId = "\0" + virtualId;
  return {
    name: "repo-files",
    resolveId(id) {
      if (id === virtualId) return resolvedId;
    },
    load(id) {
      if (id !== resolvedId) return;
      const root = process.env.REPO_ROOT
        ? path.resolve(process.env.REPO_ROOT)
        : process.cwd();
      let files = [];
      try {
        const out = execSync("git ls-files -z", {
          cwd: root,
          stdio: ["ignore", "pipe", "ignore"],
        });
        files = out.toString("utf8").split("\0").filter(Boolean);
      } catch (e) {
        const walk = (dir) => {
          for (const name of fs.readdirSync(dir)) {
            if (
              name === "node_modules" ||
              name === ".git" ||
              name === "dist" ||
              name === ".vite"
            )
              continue;
            const full = path.join(dir, name);
            const st = fs.statSync(full);
            if (st.isDirectory()) walk(full);
            else files.push(path.relative(root, full));
          }
        };
        walk(root);
      }
      const entries = files
        .filter((f) => {
          try {
            return fs.statSync(path.join(root, f)).isFile();
          } catch {
            return false;
          }
        })
        .map((f) => {
          const full = path.join(root, f);
          const buf = fs.readFileSync(full);
          return `${JSON.stringify(f)}: ${JSON.stringify(buf.toString("base64"))}`;
        });
      return `export default { ${entries.join(",\n")} };`;
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: [repoFilesPlugin()],
  build: { target: "esnext" },
  optimizeDeps: { esbuildOptions: { target: "esnext" } },
});
