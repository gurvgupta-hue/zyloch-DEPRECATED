import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get("type");

  const pdfMap = {
    cookies: "COOKIE POLICY.pdf",
    privacy: "PRIVACY POLICY.pdf",
    terms: "TERMS AND CONDITIONS.pdf",
  };

  const fileName = pdfMap[type?.toLowerCase()];

  if (!fileName) {
    return NextResponse.json(
      { error: "Invalid document type specified." },
      { status: 400 }
    );
  }

  const filePath = path.join(process.cwd(), "data", fileName);

  if (!fs.existsSync(filePath)) {
    return NextResponse.json(
      { error: "PDF file not found." },
      { status: 404 }
    );
  }

  try {
    const fileBuffer = fs.readFileSync(filePath);

    return new NextResponse(fileBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${fileName}"`,
        "Cache-Control": "public, max-age=3600",
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to read PDF document." },
      { status: 500 }
    );
  }
}
