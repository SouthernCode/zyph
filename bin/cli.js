#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const esprima = require("esprima");
const chalk = require("chalk");
const heuristics = require("../heuristics");

const NODE_MODULES_PATH = path.join(process.cwd(), "node_modules");

/**
 * Recursively traverse the AST and execute a callback on every node.
 * @param {object} node - The AST node.
 * @param {function} callback - Callback to execute for each node.
 */
function traverse(node, callback) {
  callback(node);
  for (const key in node) {
    if (node.hasOwnProperty(key)) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => {
          if (c && typeof c.type === "string") {
            traverse(c, callback);
          }
        });
      } else if (child && typeof child.type === "string") {
        traverse(child, callback);
      }
    }
  }
}

/**
 * Recursively gathers all JavaScript files within a directory.
 * @param {string} dirPath - Directory path.
 * @returns {string[]} List of .js file paths.
 */
function getJavaScriptFiles(dirPath) {
  let results = [];
  try {
    const files = fs.readdirSync(dirPath);
    for (const file of files) {
      const fullPath = path.join(dirPath, file);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          results = results.concat(getJavaScriptFiles(fullPath));
        } else if (fullPath.endsWith(".js")) {
          results.push(fullPath);
        }
      } catch (error) {
        // Silently ignore files that cannot be accessed
      }
    }
  } catch (error) {
    console.error(chalk.red(`Error reading directory ${dirPath}: ${error.message}`));
  }
  return results;
}

/**
 * Scans JavaScript files for suspicious patterns based on heuristics.
 */
function scanNodeModules() {
  console.log(chalk.cyan("🔍 Scanning node_modules/ for suspicious code..."));

  if (!fs.existsSync(NODE_MODULES_PATH)) {
    console.error(chalk.red("❌ node_modules/ folder not found. Run 'npm install' first."));
    process.exit(1);
  }

  const jsFiles = getJavaScriptFiles(NODE_MODULES_PATH);
  if (jsFiles.length === 0) {
    console.log(chalk.green("✅ No JavaScript files found to scan."));
    return;
  }

  let issuesFound = 0;
  jsFiles.forEach((filePath) => {
    // Optional: Skip whitelisted modules (e.g., axios)
    if (filePath.includes(path.join("node_modules", "axios"))) {
      return;
    }

    let fileIssues = [];
    let code = "";
    try {
      code = fs.readFileSync(filePath, "utf8");
    } catch (readError) {
      console.error(chalk.red(`Error reading file ${filePath}: ${readError.message}`));
      return;
    }

    let ast;
    try {
      ast = esprima.parseScript(code, { tolerant: true });
    } catch (parseError) {
      console.error(chalk.yellow(`⚠️  Parsing error in ${filePath}: ${parseError.message}`));
      return;
    }

    // Use AST traversal and evaluate each heuristic against nodes
    traverse(ast, (node) => {
      heuristics.forEach((heuristic) => {
        try {
          // Check if the node's structure matches the heuristic’s intended type.
          // For example, heuristics designed for CallExpressions:
          if (
            (node.type === "CallExpression" ||
             node.type === "MemberExpression" ||
             node.type === "Identifier") &&
            heuristic.detection(node, filePath, code)
          ) {
            fileIssues.push({
              id: heuristic.id,
              description: heuristic.description,
              severity: heuristic.severity
            });
          }
        } catch (heuristicError) {
          // If a heuristic throws, log it and continue
          console.error(chalk.red(`Error applying heuristic ${heuristic.id} in ${filePath}: ${heuristicError.message}`));
        }
      });
    });

    // Additional file-level check for obfuscation markers
    if (code.includes("\\x") || code.includes("\\u")) {
      fileIssues.push({
        id: "OBFUSCATION_HEX",
        description: "Possible obfuscation detected based on hexadecimal/unicode escape sequences.",
        severity: "medium"
      });
    }

    // Report findings for the file if any issues were found
    if (fileIssues.length > 0) {
      console.log(chalk.red(`\n🚨 Issues found in ${filePath}:`));
      fileIssues.forEach(issue => {
        console.log(chalk.red(`  [${issue.severity.toUpperCase()}] ${issue.id}: ${issue.description}`));
        issuesFound++;
      });
    }
  });

  if (issuesFound === 0) {
    console.log(chalk.green("✅ No suspicious code found."));
  } else {
    console.log(chalk.red(`\n⚠️ Total issues detected: ${issuesFound}`));
  }
}

/**
 * Entry point: run the scan command.
 */
function run() {
  console.log(chalk.blue("\nRunning Zyph Security Scan...\n"));
  scanNodeModules();
  console.log(chalk.blue("\n✅ Scan complete.\n"));
}

run();
