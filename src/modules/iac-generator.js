// IaC lazy bundle facade. Domain generators live in format-specific modules.

let _iacType = "terraform";
let _iacOutput = "";

export function getIacType() { return _iacType; }
export function setIacType(v) { _iacType = v; }
export function getIacOutput() { return _iacOutput; }
export function setIacOutput(v) { _iacOutput = v; }

export { safeName } from "./iac-resource-formatters.js";
export { generateTerraform, _tfRef, getTfIdMap, setTfIdMap } from "./iac-terraform-generator.js";
export { generateARM } from "./iac-arm-template-generator.js";
export { generateBicep } from "./iac-bicep-generator.js";
export { generateCheckov, generateCheckovArm } from "./iac-checkov-generator.js";
export { generateAzCli } from "./iac-azure-cli-generator.js";
export { highlightHCL, highlightJSON, highlightBicep, highlightPython, highlightYAML } from "./iac-syntax-highlighting.js";
