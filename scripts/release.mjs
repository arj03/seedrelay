// Cuts a release: tags HEAD as v<package.json version> and opens a draft GitHub release
// carrying bundle/relay.skb, for review and publish. There is nothing to compile, so unlike
// seedkernel's there is no workflow: the bundle is signed here by relay.key, and the
// release is that committed, signed file.
//
// It refuses unless the tree is clean, relay.skb is the bundle of this checkout (build.mjs
// --check), the tests pass, and the sibling seedkernel the bundle was
// built from is clean, whose version the notes name as the oldest a native node may be.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const kernel = resolve(root, "../seedkernel");
const tag = "v" + JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).version;
const run = (cmd, ...args) => execFileSync(cmd, args, { cwd: root, stdio: "inherit", shell: process.platform === "win32" && cmd === "npm" });
const read = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();

if (read(root, "status", "--porcelain", "--untracked-files=no")) throw new Error("working tree is not clean; commit first");
if (read(kernel, "status", "--porcelain", "--untracked-files=no")) throw new Error("../seedkernel is not clean; the bundle must be built from a commit");
const kernelVersion = read(kernel, "describe", "--tags");
// Only a published tag is binding: a local one left by a failed run is moved to HEAD.
const published = read(root, "ls-remote", "origin", `refs/tags/${tag}`).split("\t")[0];
if (published && published !== read(root, "rev-parse", "HEAD")) throw new Error(`${tag} is already published on another commit`);

run("node", "scripts/build.mjs", "--check");
run("npm", "test");

const notes = `Built with seedkernel ${kernelVersion}. A native node runs \`relay.skb\` with a seedkernel binary from that release or later:

\`\`\`sh
seedkernel --transport relay.skb --key relay-id.key --listen ws=0.0.0.0:8080 --transport-config relay.json
\`\`\`
`;
run("git", "tag", "-f", tag);
run("git", "push", "origin", tag);
run("gh", "release", "create", tag, "--draft", "--verify-tag", "--title", tag, "--notes", notes, "--generate-notes", "bundle/relay.skb");
console.log(`\n${tag}: draft release created; review and publish it (gh release view ${tag} --web)`);
