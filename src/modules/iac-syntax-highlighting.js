// ============================================================
// SYNTAX HIGHLIGHTING
// ============================================================

/**
 * Basic HCL syntax highlighter for Terraform.
 */
export function highlightHCL(code) {
  code = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return code.split('\n').map(line => {
    if (line.match(/^\s*#/)) return '<span class="hcl-cmt">' + line + '</span>';
    line = line.replace(/"([^"]*)"/g, function(_, s) { return '"<span class="hcl-str">' + s + '</span>"'; });
    line = line.replace(/\b(resource|variable|data|module|provider|output|terraform|required_providers|import|locals|dynamic|param)\b/g, '<span class="hcl-kw">$1</span>');
    line = line.replace(/\b(string|number|bool|list|map|set|object|any)\b/g, '<span class="hcl-type">$1</span>');
    line = line.replace(/= (\d+)$/g, '= <span class="hcl-num">$1</span>');
    line = line.replace(/\b(true|false|null)\b/g, '<span class="hcl-num">$1</span>');
    line = line.replace(/(azurerm_[a-z_]+\.[a-z_0-9]+\.[a-z_]+)/g, '<span class="hcl-ref">$1</span>');
    return line;
  }).join('\n');
}

/**
 * Basic JSON/ARM Template syntax highlighter.
 */
export function highlightJSON(code) {
  code = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return code.split('\n').map(line => {
    line = line.replace(/"([^"]*)":/g, '"<span class="hcl-kw">$1</span>":');
    line = line.replace(/: "([^"]*)"/g, ': "<span class="hcl-str">$1</span>"');
    line = line.replace(/: (\d+)/g, ': <span class="hcl-num">$1</span>');
    line = line.replace(/: (true|false|null)\b/g, ': <span class="hcl-num">$1</span>');
    line = line.replace(/(Microsoft\.[A-Za-z./]+)/g, '<span class="hcl-type">$1</span>');
    return line;
  }).join('\n');
}

/**
 * Basic Bicep syntax highlighter.
 */
export function highlightBicep(code) {
  code = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return code.split('\n').map(line => {
    if (line.match(/^\s*\/\//)) return '<span class="hcl-cmt">' + line + '</span>';
    line = line.replace(/'([^']*)'/g, "'<span class=\"hcl-str\">$1</span>'");
    line = line.replace(/\b(resource|param|var|output|module|targetScope|existing|if|for|in)\b/g, '<span class="hcl-kw">$1</span>');
    line = line.replace(/\b(string|int|bool|array|object)\b/g, '<span class="hcl-type">$1</span>');
    line = line.replace(/\b(true|false|null)\b/g, '<span class="hcl-num">$1</span>');
    line = line.replace(/(Microsoft\.[A-Za-z./@0-9-]+)/g, '<span class="hcl-type">$1</span>');
    return line;
  }).join('\n');
}

/**
 * Basic Python syntax highlighter for Checkov checks.
 */
export function highlightPython(code) {
  code = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return code.split('\n').map(line => {
    if (line.match(/^\s*#/)) return '<span class="hcl-cmt">' + line + '</span>';
    line = line.replace(/"([^"]*)"/g, '"<span class="hcl-str">$1</span>"');
    line = line.replace(/'([^']*)'/g, "'<span class=\"hcl-str\">$1</span>'");
    line = line.replace(/\b(class|def|import|from|return|if|else|elif|for|in|not|and|or|is|None|True|False|super|self)\b/g, '<span class="hcl-kw">$1</span>');
    line = line.replace(/\b(CheckResult|CheckCategories|BaseResourceCheck)\b/g, '<span class="hcl-type">$1</span>');
    return line;
  }).join('\n');
}

/**
 * YAML syntax highlighter (kept for backward compat).
 */
export function highlightYAML(code) {
  code = code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return code.split('\n').map(line => {
    if (line.match(/^\s*#/)) return '<span class="hcl-cmt">' + line + '</span>';
    line = line.replace(/'([^']*)'/g, "'<span class=\"hcl-str\">$1</span>'");
    line = line.replace(/\b(true|false|null)\b/g, '<span class="hcl-num">$1</span>');
    line = line.replace(/(Microsoft\.[A-Za-z./]+)/g, '<span class="hcl-type">$1</span>');
    return line;
  }).join('\n');
}
