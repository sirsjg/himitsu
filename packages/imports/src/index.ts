export interface DotenvEntry {
  readonly key: string;
  readonly value: string;
  readonly line: number;
}

export type DotenvIssueCode = "INVALID_ASSIGNMENT" | "INVALID_KEY" | "DUPLICATE_KEY" | "UNTERMINATED_QUOTE" | "TRAILING_CONTENT";

export interface DotenvIssue {
  readonly line: number;
  readonly code: DotenvIssueCode;
  readonly message: string;
  readonly key?: string;
}

export interface DotenvParseResult {
  readonly entries: readonly DotenvEntry[];
  readonly issues: readonly DotenvIssue[];
}

export interface DotenvPreviewEntry {
  readonly key: string;
  readonly line: number;
  readonly operation: "add" | "update";
}

export interface DotenvPreview {
  readonly entries: readonly DotenvPreviewEntry[];
  readonly conflicts: readonly DotenvIssue[];
  readonly summary: { readonly adds: number; readonly updates: number; readonly conflicts: number };
}

const keyPattern = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

export function parseDotenv(source: string): DotenvParseResult {
  const lines = source.replace(/^\uFEFF/, "").split(/\r?\n/);
  const entries: DotenvEntry[] = [];
  const issues: DotenvIssue[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < lines.length; index += 1) {
    const startLine = index + 1;
    let assignment = lines[index]?.trimStart() ?? "";
    if (assignment === "" || assignment.startsWith("#")) continue;
    if (assignment.startsWith("export ") || assignment.startsWith("export\t")) {
      assignment = assignment.slice(6).trimStart();
    }
    const equals = assignment.indexOf("=");
    if (equals < 0) {
      issues.push({ line: startLine, code: "INVALID_ASSIGNMENT", message: `Line ${startLine}: expected KEY=value` });
      continue;
    }
    const key = assignment.slice(0, equals).trim();
    if (!keyPattern.test(key)) {
      issues.push({ line: startLine, code: "INVALID_KEY", message: `Line ${startLine}: invalid dotenv key`, ...(key === "" ? {} : { key }) });
      continue;
    }
    if (seen.has(key)) {
      issues.push({ line: startLine, code: "DUPLICATE_KEY", message: `Line ${startLine}: duplicate key ${key}`, key });
      continue;
    }
    const initial = assignment.slice(equals + 1).trimStart();
    let parsed: { value: string; finalLine: number; trailing: string; terminated: boolean };
    if (initial.startsWith('"') || initial.startsWith("'") || initial.startsWith("`")) {
      parsed = parseQuoted(lines, index, initial, initial[0] as '"' | "'" | "`");
      index = parsed.finalLine;
      if (!parsed.terminated) {
        issues.push({ line: startLine, code: "UNTERMINATED_QUOTE", message: `Line ${startLine}: unterminated quoted value for ${key}`, key });
        continue;
      }
      const trailing = parsed.trailing.trim();
      if (trailing !== "" && !trailing.startsWith("#")) {
        issues.push({ line: startLine, code: "TRAILING_CONTENT", message: `Line ${startLine}: unexpected content after quoted value for ${key}`, key });
        continue;
      }
    } else {
      parsed = { value: unquotedValue(initial), finalLine: index, trailing: "", terminated: true };
    }
    seen.add(key);
    entries.push({ key, value: parsed.value, line: startLine });
  }
  return { entries, issues };
}

function parseQuoted(
  lines: readonly string[],
  startIndex: number,
  initial: string,
  quote: '"' | "'" | "`",
): { value: string; finalLine: number; trailing: string; terminated: boolean } {
  let value = "";
  let lineIndex = startIndex;
  let text = initial.slice(1);
  for (;;) {
    for (let cursor = 0; cursor < text.length; cursor += 1) {
      const character = text[cursor];
      if (character === "\\") {
        const next = text[cursor + 1];
        if (next === undefined) { value += "\\"; continue; }
        if (next === quote || next === "\\") { value += next; cursor += 1; continue; }
        if (quote === '"') {
          if (next === "n") { value += "\n"; cursor += 1; continue; }
          if (next === "r") { value += "\r"; cursor += 1; continue; }
          if (next === "t") { value += "\t"; cursor += 1; continue; }
        }
        value += `\\${next}`;
        cursor += 1;
        continue;
      }
      if (character === quote) {
        return { value, finalLine: lineIndex, trailing: text.slice(cursor + 1), terminated: true };
      }
      value += character;
    }
    lineIndex += 1;
    const nextLine = lines[lineIndex];
    if (nextLine === undefined) return { value, finalLine: lineIndex - 1, trailing: "", terminated: false };
    value += "\n";
    text = nextLine;
  }
}

function unquotedValue(input: string): string {
  let value = "";
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (character === "\\" && input[index + 1] === "#") { value += "#"; index += 1; continue; }
    if (character === "#") break;
    value += character;
  }
  return value.trimEnd();
}

export function buildDotenvPreview(
  parsed: DotenvParseResult,
  existingKeys: ReadonlySet<string>,
): DotenvPreview {
  const entries = parsed.entries.map(({ key, line }) => ({
    key,
    line,
    operation: existingKeys.has(key) ? "update" as const : "add" as const,
  }));
  const adds = entries.filter(({ operation }) => operation === "add").length;
  const updates = entries.length - adds;
  return {
    entries,
    conflicts: parsed.issues,
    summary: { adds, updates, conflicts: parsed.issues.length },
  };
}

export type JsonImportIssueCode =
  | "INVALID_JSON"
  | "ROOT_NOT_OBJECT"
  | "ARRAY_NOT_SUPPORTED"
  | "UNSUPPORTED_TYPE"
  | "INVALID_KEY"
  | "KEY_COLLISION"
  | "INVALID_DELIMITER"
  | "LIMIT_EXCEEDED";

export interface JsonImportEntry {
  readonly key: string;
  readonly value: string;
  readonly path: string;
}

export interface JsonImportIssue {
  readonly path: string;
  readonly code: JsonImportIssueCode;
  readonly message: string;
}

export interface JsonImportParseResult {
  readonly entries: readonly JsonImportEntry[];
  readonly issues: readonly JsonImportIssue[];
  readonly delimiter: string;
}

export interface JsonImportPreview {
  readonly entries: readonly { readonly key: string; readonly path: string; readonly operation: "add" | "update" }[];
  readonly conflicts: readonly JsonImportIssue[];
  readonly summary: { readonly adds: number; readonly updates: number; readonly conflicts: number };
}

export function parseJsonSecrets(source: string, delimiter = "__"): JsonImportParseResult {
  const entries: JsonImportEntry[] = [];
  const issues: JsonImportIssue[] = [];
  if (delimiter.length < 1 || delimiter.length > 10 || /[\s=\u0000-\u001f\u007f]/u.test(delimiter)) {
    return {
      entries,
      issues: [{ path: "$", code: "INVALID_DELIMITER", message: "Delimiter must be 1-10 visible characters without whitespace or equals" }],
      delimiter,
    };
  }
  let document: unknown;
  try {
    document = JSON.parse(source) as unknown;
  } catch (error) {
    return {
      entries,
      issues: [{ path: "$", code: "INVALID_JSON", message: error instanceof SyntaxError ? error.message : "JSON could not be parsed" }],
      delimiter,
    };
  }
  if (!isPlainObject(document)) {
    return {
      entries,
      issues: [{ path: "$", code: "ROOT_NOT_OBJECT", message: "JSON import must start with an object" }],
      delimiter,
    };
  }
  const keys = new Set<string>();
  const visit = (value: unknown, segments: readonly string[], path: string, depth: number) => {
    if (depth > 20) { issues.push({ path, code: "LIMIT_EXCEEDED", message: `${path}: nesting exceeds 20 levels` }); return; }
    if (Array.isArray(value)) { issues.push({ path, code: "ARRAY_NOT_SUPPORTED", message: `${path}: arrays are not supported` }); return; }
    if (isPlainObject(value)) {
      for (const [segment, child] of Object.entries(value)) {
        const childPath = `${path}.${jsonPathSegment(segment)}`;
        if (segment === "" || /[\s=\u0000-\u001f\u007f]/u.test(segment)) {
          issues.push({ path: childPath, code: "INVALID_KEY", message: `${childPath}: object keys cannot be empty or contain whitespace, controls, or equals` });
          continue;
        }
        visit(child, [...segments, segment], childPath, depth + 1);
      }
      return;
    }
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
      issues.push({ path, code: "UNSUPPORTED_TYPE", message: `${path}: expected a string, number, or boolean` });
      return;
    }
    const key = segments.join(delimiter);
    if (keys.has(key)) { issues.push({ path, code: "KEY_COLLISION", message: `${path}: flattened key ${key} is duplicated` }); return; }
    keys.add(key);
    entries.push({ key, value: typeof value === "string" ? value : String(value), path });
    if (entries.length > 100) {
      entries.pop();
      issues.push({ path, code: "LIMIT_EXCEEDED", message: "JSON imports are limited to 100 values" });
    }
  };
  visit(document, [], "$", 0);
  return { entries, issues, delimiter };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonPathSegment(segment: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(segment) ? segment : `[${JSON.stringify(segment)}]`;
}

export function buildJsonImportPreview(
  parsed: JsonImportParseResult,
  existingKeys: ReadonlySet<string>,
): JsonImportPreview {
  const entries = parsed.entries.map(({ key, path }) => ({
    key,
    path,
    operation: existingKeys.has(key) ? "update" as const : "add" as const,
  }));
  const adds = entries.filter(({ operation }) => operation === "add").length;
  return {
    entries,
    conflicts: parsed.issues,
    summary: { adds, updates: entries.length - adds, conflicts: parsed.issues.length },
  };
}
