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
