/**
 * `guarded()` accepts normally typed functions under `strict`.
 *
 * A `(...args: unknown[]) => Promise<unknown>` constraint would reject
 * `(cmd: string) => Promise<string>` (TS2345/TS2769), and the README
 * examples would need a cast. This suite runs the compiler on
 * fixtures/readme_strict.ts and expects zero diagnostics.
 */

import * as path from "path";
import * as ts from "typescript";

describe("strict type-check of the README examples", () => {
  it("compiles fixtures/readme_strict.ts with no errors", () => {
    const fixture = path.join(__dirname, "fixtures", "readme_strict.ts");
    const program = ts.createProgram([fixture], {
      strict: true,
      noEmit: true,
      target: ts.ScriptTarget.ES2020,
      module: ts.ModuleKind.CommonJS,
      lib: ["lib.es2020.d.ts"],
      types: ["node"],
      skipLibCheck: true,
    });
    const messages = ts.getPreEmitDiagnostics(program).map((d) => {
      const text = ts.flattenDiagnosticMessageText(d.messageText, "\n");
      if (!d.file || d.start === undefined) return `TS${d.code}: ${text}`;
      const { line } = d.file.getLineAndCharacterOfPosition(d.start);
      return `${path.basename(d.file.fileName)}:${line + 1} TS${d.code}: ${text}`;
    });
    expect(messages).toEqual([]);
  }, 60_000);
});
