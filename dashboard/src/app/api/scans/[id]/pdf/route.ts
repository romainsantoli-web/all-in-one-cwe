// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { loadScan } from "@/lib/data";
import { generatePDF } from "@/lib/pdf-report";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const filename = decodeURIComponent(id);
  const report = await loadScan(filename);

  if (!report) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const pdfBytes = generatePDF(report, filename);
  const pdfName = filename.replace(/\.json$/i, ".pdf");

  return new NextResponse(Buffer.from(pdfBytes), {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${pdfName}"`,
      "Cache-Control": "no-store",
    },
  });
}
