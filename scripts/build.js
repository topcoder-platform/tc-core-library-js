"use strict";
const {readdirSync, mkdirSync} = require("node:fs");
const {join} = require("node:path");
const {execFileSync} = require("node:child_process");

/** Walk a source directory and syntax-check distributable JavaScript; throws on invalid source. */
function check(directory) {
  for (const entry of readdirSync(directory, {withFileTypes: true})) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) check(path);
    else if (entry.name.endsWith(".js")) execFileSync(process.execPath, ["--check", path], {stdio: "inherit"});
  }
}
check("lib");
execFileSync(process.execPath, ["--check", "index.js"], {stdio: "inherit"});
mkdirSync("dist", {recursive: true});
execFileSync("npm", ["pack", "--pack-destination", "dist", "--ignore-scripts"], {stdio: "inherit"});
