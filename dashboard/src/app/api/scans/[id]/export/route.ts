// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { loadScan } from "@/lib/data";
import { execSync } from "child_process";
import path from "path";

export const dynamic = "force-dynamic";

const VALID_FORMATS = [
  "yeswehack",
  "hackerone",
  "bugcrowd",
  "intigriti",
  "immunefi",
  "markdown",
];

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const filename = decodeURIComponent(id);

  const url = new URL(request.url);
  const format = url.searchParams.get("format") || "markdown";

  if (!VALID_FORMATS.includes(format)) {
    return NextResponse.json(
      { error: `Invalid format. Valid: ${VALID_FORMATS.join(", ")}` },
      { status: 400 }
    );
  }

  const report = await loadScan(filename);
  if (!report) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  // Write temp input, call Python generator
  const fs = await import("fs");
  const os = await import("os");
  const tmpFile = path.join(os.tmpdir(), `report-export-${Date.now()}.json`);
  const outFile = path.join(os.tmpdir(), `report-export-${Date.now()}.md`);

  try {
    fs.writeFileSync(tmpFile, JSON.stringify(report));

    const scriptDir = path.resolve(process.cwd(), "..", "scripts");
    const cmd = `python3 "${path.join(scriptDir, "report_generators.py")}" --format ${format} --input "${tmpFile}" --output "${outFile}" --validated-only`;

    execSync(cmd, {
      timeout: 30000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    const content = fs.readFileSync(outFile, "utf-8");
    const exportName = filename
      .replace(/\.json$/i, "")
      .concat(`-${format}.md`);

    return new NextResponse(content, {
      status: 200,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${exportName}"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    console.error("Report generation failed:", err);
    return NextResponse.json(
      { error: "Report generation failed" },
      { status: 500 }
    );
  } finally {
    // Cleanup temp files
    try {
      fs.unlinkSync(tmpFile);
    } catch {}
    try {
      fs.unlinkSync(outFile);
    } catch {}
  }
}
