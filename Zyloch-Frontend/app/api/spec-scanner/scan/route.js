import { NextResponse } from "next/server";

const SPEC_GENERATOR_URL = process.env.SPEC_GENERATOR_URL || "http://localhost:8000";
const SPEC_GENERATOR_ENDPOINT = "/v2/generate-and-validate";
const TIMEOUT_MS = 600_000; // 10 minutes — spec scans can be slow

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  const { path, scan_metadata } = body || {};

  if (typeof path !== "string" || !path.trim()) {
    return NextResponse.json({ error: "path is required" }, { status: 400 });
  }
  if (!scan_metadata || typeof scan_metadata !== "object") {
    return NextResponse.json({ error: "scan_metadata is required" }, { status: 400 });
  }

  const { organization, repository, branch, commit_hash } = scan_metadata;
  if (!organization || !repository || !branch || !commit_hash) {
    return NextResponse.json(
      { error: "scan_metadata must include organization, repository, branch, commit_hash" },
      { status: 400 }
    );
  }

  const targetUrl = `${SPEC_GENERATOR_URL.replace(/\/$/, "")}${SPEC_GENERATOR_ENDPOINT}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const upstream = await fetch(targetUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: path.trim(), scan_metadata }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const data = await upstream.json().catch(() => ({}));

    if (!upstream.ok) {
      const message =
        data?.detail || data?.error || data?.message || `Spec generator returned ${upstream.status}`;
      return NextResponse.json({ error: String(message) }, { status: upstream.status });
    }

    return NextResponse.json(data);
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return NextResponse.json({ error: "Spec generator request timed out" }, { status: 504 });
    }
    return NextResponse.json(
      { error: "Failed to reach spec generator service" },
      { status: 502 }
    );
  }
}
