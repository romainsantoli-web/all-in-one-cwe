// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { getJobSummary } from "@/lib/jobs";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const summary = await getJobSummary(id);
  if (!summary) {
    return NextResponse.json({ error: "Summary not found" }, { status: 404 });
  }
  return NextResponse.json(summary);
}
