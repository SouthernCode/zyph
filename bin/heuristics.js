/**
 * heuristics.js
 *
 * Advanced Heuristics for Zyph Dependency Scanner.
 *
 * This file defines an array of heuristic objects that describe patterns and contexts
 * which might indicate malicious or risky behavior in JavaScript code.
 *
 * Each heuristic includes:
 * - id: A unique identifier for the heuristic.
 * - pattern: The pattern(s) or keyword(s) to detect.
 * - description: A detailed explanation of the risk.
 * - severity: A level indicator (e.g., "low", "medium", "high").
 * - context: Additional context or conditions that might affect the interpretation.
 * - detection: An optional function to perform additional validation on a given AST node.
 *
 * Developers can update the `detection` functions with custom logic to make the scan
 * more context-sensitive (for instance, checking arguments, dynamic code generation, etc.).
 */

const heuristics = [
    {
      id: "EVAL_USAGE",
      pattern: "eval",
      description:
        "Direct use of eval() can execute arbitrary code. Unsanitized input can lead to remote code execution.",
      severity: "high",
      context:
        "Any code invoking eval() without strict input validation is flagged for further review.",
      detection: (node, filePath, code) => {
        // Basic check: if the callee is exactly 'eval'
        return true;
      }
    },
    {
      id: "FUNCTION_CONSTRUCTOR",
      pattern: "Function",
      description:
        "Usage of the Function constructor allows dynamic code creation, which poses severe security risks if misused.",
      severity: "high",
      context:
        "Look for instantiation patterns that generate functions from string input.",
      detection: (node, filePath, code) => true
    },
    {
      id: "DYNAMIC_TIMEOUT_INTERVAL",
      pattern: ["setTimeout", "setInterval"],
      description:
        "Using setTimeout or setInterval with string arguments may execute dynamically generated code, leading to deferred execution of malicious code.",
      severity: "medium",
      context:
        "If the first argument is a string literal rather than a function, it is considered unsafe.",
      detection: (node, filePath, code) => {
        // If the argument is a string literal, flag it
        return node.arguments && node.arguments[0] && node.arguments[0].type === "Literal" &&
               typeof node.arguments[0].value === "string";
      }
    },
    {
      id: "DOCUMENT_WRITE",
      pattern: "document.write",
      description:
        "Using document.write() can inject scripts into a page, potentially leading to cross-site scripting (XSS) vulnerabilities.",
      severity: "high",
      context:
        "Mainly applies to client-side code and legacy systems; verify if output is properly escaped.",
      detection: (node, filePath, code) => true
    },
    {
      id: "XMLHTTPREQUEST",
      pattern: "XMLHttpRequest",
      description:
        "XMLHttpRequest is used for making network calls. If used to send data to untrusted endpoints, it could be used to exfiltrate sensitive information.",
      severity: "medium",
      context:
        "Scrutinize the destination URL and request methods to ensure they align with the module's purpose.",
      detection: (node, filePath, code) => true
    },
    {
      id: "FETCH_USAGE",
      pattern: "fetch",
      description:
        "The fetch() API is modern and widely used for HTTP requests; however, unexpected use may indicate data exfiltration or command-and-control callbacks.",
      severity: "medium",
      context:
        "Verify the request URL and parameters. Unexpected domains or HTTP methods may raise the alert level.",
      detection: (node, filePath, code) => true
    },
    {
      id: "ENCODED_PAYLOAD",
      pattern: ["atob", "btoa"],
      description:
        "atob() and btoa() are used for Base64 encoding/decoding, which might indicate attempts to hide encoded payloads or obfuscate strings.",
      severity: "medium",
      context:
        "Common in obfuscation techniques. Check if encoded strings are used in dangerous contexts.",
      detection: (node, filePath, code) => true
    },
    {
      id: "CHILD_PROCESS_REQUIRE",
      pattern: "require",
      description:
        "Requiring the 'child_process' module can allow execution of shell commands, which poses a critical security risk if exploited.",
      severity: "high",
      context:
        "Specifically check if the argument to require() is the string 'child_process'.",
      detection: (node, filePath, code) => {
        if (node.arguments && node.arguments.length > 0 && node.arguments[0].type === "Literal") {
          return node.arguments[0].value === "child_process";
        }
        return false;
      }
    },
    {
      id: "PROCESS_ENV_ACCESS",
      pattern: "process.env",
      description:
        "Accessing process.env may expose sensitive environmental variables. This is risky if the values are logged, transmitted, or improperly sanitized.",
      severity: "medium",
      context:
        "Commonly used in configuration; flag when used in contexts where data leakage could occur.",
      detection: (node, filePath, code) => true
    },
    {
      id: "OBFUSCATION_HEX",
      pattern: ["\\x", "\\u"],
      description:
        "The presence of hexadecimal or Unicode escape sequences may indicate that the code is obfuscated to hide malicious behavior.",
      severity: "medium",
      context:
        "Detection here is based on a raw string search, suggesting that the code may be intentionally obscured.",
      detection: (node, filePath, code) => {
        // This check might not rely on AST nodes but on raw code strings.
        return code.includes("\\x") || code.includes("\\u");
      }
    },
    {
      id: "DYNAMIC_PROPERTY_ACCESS",
      pattern: "[]",
      description:
        "Dynamic property access using bracket notation may be used to obfuscate code or bypass static analysis. Although not inherently malicious, it should be reviewed in sensitive contexts.",
      severity: "low",
      context:
        "Often seen in cases where property names are constructed at runtime.",
      detection: (node, filePath, code) => true
    },
    {
      id: "INDIRECT_EVAL",
      pattern: "indirect eval",
      description:
        "Indirect invocation of eval (e.g., via window['eval']) is a common obfuscation tactic to hide dynamic code execution.",
      severity: "high",
      context:
        "This pattern is frequently used to bypass static analysis; review its usage carefully.",
      detection: (node, filePath, code) => true
    },
    {
      id: "SUSPICIOUS_IMPORT_EXPORT",
      pattern: "import/export anomalies",
      description:
        "Unusual patterns in module import/export, such as dynamically constructing module paths, may be used to load malicious code.",
      severity: "medium",
      context:
        "Check for dynamically generated module names or unexpected re-exports that could hide vulnerabilities.",
      detection: (node, filePath, code) => true
    },
    {
      id: "DYNAMIC_REQUIRE",
      pattern: "dynamic require",
      description:
        "Using variables or expressions within require() calls can obscure which module is being loaded, potentially masking malicious code.",
      severity: "medium",
      context:
        "This is especially concerning if the variable is influenced by external inputs or is not properly sanitized.",
      detection: (node, filePath, code) => {
        if (node.arguments && node.arguments.length > 0) {
          return node.arguments[0].type !== "Literal";
        }
        return false;
      }
    },
    {
      id: "INLINE_EVENT_HANDLER",
      pattern: "onerror|onclick|onload",
      description:
        "Inline event handlers (e.g., onerror, onclick, onload) in HTML or JavaScript may be exploited for injecting malicious scripts, particularly in unsanitized contexts.",
      severity: "low",
      context:
        "Often found in client-side code; verify that the inline handlers are properly secured.",
      detection: (node, filePath, code) => true
    },
    {
      id: "DYNAMIC_EVAL_CONCAT",
      pattern: "dynamic eval concatenation",
      description:
        "Using eval() with dynamically concatenated strings can hide the true intent of the code by assembling it at runtime, making it harder to analyze statically.",
      severity: "high",
      context:
        "Particularly dangerous if parts of the string originate from external sources.",
      detection: (node, filePath, code) => {
        // Check if the argument to eval is a BinaryExpression (indicative of concatenation)
        return node.arguments &&
               node.arguments[0] &&
               node.arguments[0].type === "BinaryExpression";
      }
    },
    {
      id: "SUSPICIOUS_REGEX",
      pattern: "regex anomalies",
      description:
        "Overly complex or obfuscated regular expressions might be used to bypass input validation or hide filtering logic, potentially facilitating injection attacks.",
      severity: "low",
      context:
        "Pay attention to dynamically constructed regex patterns that seem more complex than needed.",
      detection: (node, filePath, code) => true
    }
  ];
  
  module.exports = heuristics;
  