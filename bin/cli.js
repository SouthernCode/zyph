#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const chalkLib = require("chalk");
const chalk = chalkLib.default || chalkLib;  // Fallback in case chalk is exported as default
const babelParser = require("@babel/parser");
const cliProgress = require("cli-progress");
const heuristics = require(path.join(__dirname, "heuristics"));

const NODE_MODULES_PATH = path.join(process.cwd(), "node_modules");
const BASELINE_PATH = path.join(process.cwd(), "zyph_baseline.json");

// Known safe modules to avoid unnecessary warnings.
const safeModules = ["axios", "node-fetch", "isomorphic-fetch", "@babeel/parser"];

// Severity levels and their corresponding weights for risk scoring.
const severityMap = { low: 1, medium: 3, high: 5 };
// Only report issues that are at or above this aggregated risk threshold.
const riskThreshold = parseInt(process.env.ZYPH_THRESHOLD, 10) || 5;

// Minimum severity level to consider for reporting.
const severityLevels = ["low", "medium", "high"];
const minSeverity = process.env.ZYPH_SEVERITY || "medium";

// Optionally exclude heuristics (e.g. via environment variable ZYPH_EXCLUDE=PROCESS_ENV_ACCESS,XMLHTTPREQUEST)
const excludedWarnings = (process.env.ZYPH_EXCLUDE || "").split(",");

/**
 * Recursively traverse the AST and execute a callback on every node.
 */
function traverse(node, callback) {
  callback(node);
  for (const key in node) {
    if (node.hasOwnProperty(key)) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach((c) => {
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
        // Ignore files that cannot be accessed.
      }
    }
  } catch (error) {
    console.error(chalk.red(`Error reading directory ${dirPath}: ${error.message}`));
  }
  return results;
}

/**
 * Traverse upward from a file to find its package.json and parse metadata.
 */
function getPackageMetadata(filePath) {
  let dir = path.dirname(filePath);
  while (dir !== path.parse(dir).root) {
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        return JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      } catch (e) {
        console.error(chalk.yellow(`⚠️  Could not parse package.json at ${pkgPath}: ${e.message}`));
        return null;
      }
    }
    dir = path.dirname(dir);
  }
  return null;
}

/**
 * Calculate a risk score from a list of issues.
 */
function calculateRiskScore(issues) {
  return issues.reduce((score, issue) => {
    return score + (severityMap[issue.severity] || 0);
  }, 0);
}

/**
 * Save the aggregated scan results as a baseline.
 */
function saveBaseline(results) {
  try {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(results, null, 2), "utf8");
    console.log(chalk.green(`Baseline updated and saved to ${BASELINE_PATH}`));
  } catch (error) {
    console.error(chalk.red(`Error saving baseline: ${error.message}`));
  }
}

/**
 * Load the baseline scan results if available.
 */
function loadBaseline() {
  if (fs.existsSync(BASELINE_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
    } catch (error) {
      console.error(chalk.yellow(`⚠️  Could not load baseline: ${error.message}`));
    }
  }
  return {};
}

/**
 * Scans JavaScript files for suspicious patterns based on heuristics.
 * Aggregates issues per file, calculates risk scores, and applies package metadata.
 * Includes a progress bar for user feedback.
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
    return {};
  }

  // Initialize the progress bar.
  const progressBar = new cliProgress.SingleBar({
    format: 'Scanning [{bar}] {percentage}% | {value}/{total} files',
    hideCursor: true
  }, cliProgress.Presets.shades_classic);
  progressBar.start(jsFiles.length, 0);

  const aggregatedResults = {}; // { filePath: { issues: [...], riskScore: number, pkgMetadata: {} } }

  jsFiles.forEach((filePath) => {
    // Skip safe modules.
    if (safeModules.some((module) => filePath.includes(module))) {
      progressBar.increment();
      return;
    }

    const pkgMetadata = getPackageMetadata(filePath);
    let issues = [];
    let code = "";
    try {
      code = fs.readFileSync(filePath, "utf8");
    } catch (readError) {
      console.error(chalk.red(`Error reading file ${filePath}: ${readError.message}`));
      progressBar.increment();
      return;
    }

    let ast;
    try {
      ast = babelParser.parse(code, {
        sourceType: "unambiguous",
        plugins: [
          "jsx",
          "typescript",
          "classProperties",
          "objectRestSpread",
          "optionalChaining",
          "nullishCoalescingOperator",
          // Add more plugins if needed.
        ]
      });
    } catch (parseError) {
      console.error(chalk.yellow(`⚠️  Parsing error in ${filePath}: ${parseError.message}`));
      progressBar.increment();
      return;
    }

    // Evaluate each heuristic against AST nodes.
    traverse(ast, (node) => {
      heuristics.forEach((heuristic) => {
        try {
          if (excludedWarnings.includes(heuristic.id)) return;
          if (
            (node.type === "CallExpression" ||
              node.type === "MemberExpression" ||
              node.type === "Identifier" ||
              node.type === "ImportExpression") &&
            heuristic.detection(node, filePath, code, pkgMetadata)
          ) {
            issues.push({
              id: heuristic.id,
              description: heuristic.description,
              severity: heuristic.severity,
            });
          }
        } catch (heuristicError) {
          console.error(chalk.red(`Error applying heuristic ${heuristic.id} in ${filePath}: ${heuristicError.message}`));
        }
      });
    });

    // File-level check for obfuscation markers.
    if (code.includes("\\x") || code.includes("\\u")) {
      issues.push({
        id: "OBFUSCATION_HEX",
        description: "Possible obfuscation detected based on hexadecimal/unicode escape sequences.",
        severity: "medium",
      });
    }

    // Example: adjust risk for math libraries.
    if (pkgMetadata && pkgMetadata.keywords && pkgMetadata.keywords.includes("math")) {
      issues = issues.map(issue => {
        if (issue.id === "UNEXPECTED_NETWORK_ACTIVITY") {
          issue.severity = "high";
        }
        return issue;
      });
    }

    // Aggregate issues if any were found.
    if (issues.length > 0) {
      const uniqueIssues = [...new Map(issues.map((item) => [item.id, item])).values()];
      const riskScore = calculateRiskScore(uniqueIssues);
      aggregatedResults[filePath] = {
        issues: uniqueIssues,
        riskScore,
        pkgMetadata,
      };
    }
    progressBar.increment();
  });

  progressBar.stop();
  return aggregatedResults;
}

/**
 * Generates a report string from the aggregated scan results.
 * The report includes the module (file) name, risk score, module metadata (if available),
 * and a list of issues that triggered the flag.
 */
function generateReportString(results, baseline = {}) {
  let reportLines = [];
  reportLines.push("Zyph Scan Report");
  reportLines.push("Timestamp: " + new Date().toISOString());
  reportLines.push("");
  
  for (const [file, data] of Object.entries(results)) {
    // Only include files whose risk score meets the threshold.
    if (data.riskScore >= riskThreshold) {
      reportLines.push("-------------------------------------------------");
      reportLines.push("File: " + file);
      reportLines.push("Risk Score: " + data.riskScore);
      if (baseline[file]) {
        const diff = data.riskScore - baseline[file].riskScore;
        if (diff !== 0) {
          reportLines.push("Change from baseline: " + (diff > 0 ? "+" : "") + diff);
        }
      }
      if (data.pkgMetadata) {
        if (data.pkgMetadata.name) {
          reportLines.push("Module Name: " + data.pkgMetadata.name);
        }
        if (data.pkgMetadata.description) {
          reportLines.push("Description: " + data.pkgMetadata.description);
        }
      }
      reportLines.push("Issues:");
      data.issues.forEach((issue) => {
        if (severityLevels.indexOf(issue.severity) >= severityLevels.indexOf(minSeverity)) {
          reportLines.push("   [" + issue.severity.toUpperCase() + "] " + issue.id + ": " + issue.description);
        }
      });
      reportLines.push("");
    }
  }
  reportLines.push("-------------------------------------------------");
  reportLines.push("Total files flagged: " + Object.keys(results).length);
  let totalRiskScore = Object.values(results).reduce((sum, data) => sum + data.riskScore, 0);
  reportLines.push("Total aggregated risk score: " + totalRiskScore);
  
  return reportLines.join("\n");
}

/**
 * Writes the report string to a file.
 * The file is named using the pattern "zyph-scan-report-<timestamp>.txt".
 */
function writeReport(reportString) {
  // Replace characters not allowed in Windows filenames (like ":")
  const timestamp = new Date().toISOString().replace(/:/g, "-");
  const filename = `zyph-scan-report-${timestamp}.txt`;
  fs.writeFileSync(filename, reportString, "utf8");
  console.log("Report written to: " + filename);
}

/**
 * Entry point: run the scan command.
 */
function run() {
  console.log(chalk.blue("\n🚀 Running Zyph Security Scan...\n"));

  const results = scanNodeModules();
  const baseline = loadBaseline();

  // If the --update-baseline flag is provided, update and save the baseline.
  if (process.argv.includes("--update-baseline")) {
    saveBaseline(results);
    console.log(chalk.green("\nBaseline updated. Exiting scan.\n"));
    process.exit(0);
  }

  // Generate the report string and write it to a file.
  const reportString = generateReportString(results, baseline);
  writeReport(reportString);

  console.log(chalk.blue("\n✅ Scan complete.\n"));
}

run();
