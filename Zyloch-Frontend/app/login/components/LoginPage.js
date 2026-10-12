"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import Logo from "@/public/logo.png";
import LoginOptions from "./LoginOptions";
import { persistOrgLoginId, getStoredOrgLoginId } from "@/lib/authRedirect";

/**
 * Login redirect codes → human copy. The membership codes come from the backend
 * member-join gate (MT-02); without a mapping the page rendered the raw slug.
 */
const LOGIN_ERROR_MESSAGES = {
  invite_required:
    "You do not have an active invitation to this organization. Ask an administrator to invite you.",
  account_deactivated: "Your account has been deactivated for this organization.",
  org_inactive: "This organization is not active. Contact your administrator.",
  org_not_found: "We could not find that organization.",
  google_requires_org: "Select your organization before signing in with Google.",
  microsoft_requires_org: "Select your organization before signing in with Microsoft.",
  google_auth_failed: "Google sign-in failed. Please try again.",
  microsoft_auth_failed: "Microsoft sign-in failed. Please try again.",
};

export default function LoginPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();
  const searchParams = useSearchParams();
  // `org_id` is the current spelling. The older `orgid`/`orgId` are still read so
  // invite links already sitting in someone's inbox keep working.
  const orgIdFromUrl =
    searchParams.get("org_id") ||
    searchParams.get("orgid") ||
    searchParams.get("orgId") ||
    "";

  // Remember it. An organization cannot be looked up — the invite link is the only
  // place its id ever appears — so without this a member who bookmarks /login, or
  // simply returns tomorrow, would find the SSO buttons permanently disabled and
  // no way to re-supply the id short of digging the original email out.
  const [storedOrgId, setStoredOrgId] = useState("");
  useEffect(() => {
    if (orgIdFromUrl) {
      persistOrgLoginId(orgIdFromUrl);
      setStoredOrgId(orgIdFromUrl);
    } else {
      setStoredOrgId(getStoredOrgLoginId() || "");
    }
  }, [orgIdFromUrl]);

  const orgId = orgIdFromUrl || storedOrgId;

  /** Forget the remembered organization and fall back to admin (GitHub) sign-in. */
  const handleLeaveOrg = () => {
    persistOrgLoginId(null);
    setStoredOrgId("");
    router.replace("/login");
  };

  const canvasRef = useRef(null);
  const cardRef = useRef(null);
  const spotlightRef = useRef(null);
  const mouseRef = useRef({ x: 0, y: 0 });

  // ✅ Capture Redirect Errors
  useEffect(() => {
    const errorParam = searchParams.get("error");
    if (errorParam) {
      setError(LOGIN_ERROR_MESSAGES[errorParam] || "Sign-in failed. Please try again.");
    }
  }, [searchParams]);

  // ✅ GitHub Login Logic
  const handleGitHubLogin = () => {
    setIsLoading(true);
    setError("");
        window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/auth/github`;
  };

  // ✅ Canvas Background Animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const container = canvas.parentElement;
    const ctx = canvas.getContext("2d");
    let animId;
    let W, H;
    let nodes = [], edges = [], packets = [], rings = [], hexRings = [];

    function resize() {
      W = canvas.width = container.offsetWidth;
      H = canvas.height = container.offsetHeight;
      mouseRef.current = { x: W / 2, y: H / 2 };
      build();
    }

    function build() {
      nodes = []; edges = []; packets = []; rings = []; hexRings = [];
      for (let i = 0; i < 32; i++) {
        nodes.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
          r: Math.random() * 1.8 + 1.2,
          phase: Math.random() * Math.PI * 2,
          type: Math.random() < 0.12 ? "threat" : Math.random() < 0.28 ? "active" : "node",
        });
      }
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          if (dx * dx + dy * dy < 170 * 170) edges.push({ a: i, b: j });
        }
      }
      edges.forEach((e) => { if (Math.random() < 0.25) spawnPacket(e.a, e.b); });
      for (let i = 0; i < 4; i++) {
        rings.push({
          x: Math.random() * W, y: Math.random() * H,
          r: Math.random() * 60 + 30,
          phase: Math.random() * Math.PI * 2,
          speed: 0.006 + Math.random() * 0.004,
        });
      }
      for (let i = 0; i < 5; i++) {
        hexRings.push({
          x: Math.random() * W, y: Math.random() * H,
          size: Math.random() * 50 + 25,
          rot: Math.random() * Math.PI,
          rotSpeed: (Math.random() - 0.5) * 0.005,
          alpha: Math.random() * 0.055 + 0.025,
        });
      }
    }

    function spawnPacket(a, b) {
      packets.push({ a, b, t: Math.random(), dir: Math.random() < 0.5 ? 1 : -1, speed: 0.0025 + Math.random() * 0.004 });
    }

    function hexPath(cx, cy, sz, rot) {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = rot + (i * Math.PI) / 3;
        const x = cx + sz * Math.cos(a);
        const y = cy + sz * Math.sin(a);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.closePath();
    }

    function drawBinary() {
      ctx.font = "10px monospace";
      ctx.fillStyle = "rgba(0,210,255,0.04)";
      for (let i = 0; i < 12; i++) {
        ctx.fillText(Math.random() < 0.5 ? "0" : "1", Math.random() * W, Math.random() * H);
      }
    }

    function drawGrid() {
      const sz = 64;
      ctx.strokeStyle = "rgba(0,180,255,0.025)";
      ctx.lineWidth = 0.5;
      for (let x = 0; x < W; x += sz) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
      }
      for (let y = 0; y < H; y += sz) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
      }
    }

    function drawMouseRipple() {
      const { x: mx, y: my } = mouseRef.current;
      for (let i = 1; i <= 3; i++) {
        ctx.beginPath();
        ctx.arc(mx, my, 30 * i, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0,210,255,${0.06 / i})`;
        ctx.lineWidth = 0.6;
        ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(mx, my, 4, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0,210,255,0.5)"; ctx.fill();
      ctx.beginPath(); ctx.arc(mx, my, 1.5, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0,230,255,0.95)"; ctx.fill();
    }

    function drawMouseLines() {
      const { x: mx, y: my } = mouseRef.current;
      nodes.forEach((n) => {
        const dx = n.x - mx, dy = n.y - my, dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          const alpha = (1 - dist / 140) * 0.18;
          ctx.beginPath(); ctx.moveTo(mx, my); ctx.lineTo(n.x, n.y);
          ctx.strokeStyle = `rgba(0,210,255,${alpha})`; ctx.lineWidth = 0.5; ctx.stroke();
        }
      });
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      drawGrid();
      drawBinary();
      hexRings.forEach((h) => {
        h.rot += h.rotSpeed;
        hexPath(h.x, h.y, h.size, h.rot);
        ctx.strokeStyle = `rgba(0,180,255,${h.alpha})`; ctx.lineWidth = 0.7; ctx.stroke();
        hexPath(h.x, h.y, h.size * 0.6, h.rot + Math.PI / 6);
        ctx.strokeStyle = `rgba(120,80,255,${h.alpha * 0.7})`; ctx.stroke();
      });
      rings.forEach((rg) => {
        rg.phase += rg.speed;
        const pulse = 0.5 + 0.5 * Math.sin(rg.phase);
        ctx.beginPath(); ctx.arc(rg.x, rg.y, rg.r * (0.9 + 0.1 * pulse), 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0,210,255,${0.04 + 0.03 * pulse})`; ctx.lineWidth = 0.6; ctx.stroke();
        ctx.beginPath(); ctx.arc(rg.x, rg.y, rg.r * 0.4, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(120,80,255,${0.05 + 0.03 * pulse})`; ctx.stroke();
      });
      edges.forEach((e) => {
        const a = nodes[e.a], b = nodes[e.b];
        const dx = b.x - a.x, dy = b.y - a.y, dist = Math.sqrt(dx * dx + dy * dy);
        const alpha = (1 - dist / 170) * 0.1;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = `rgba(0,180,255,${alpha})`; ctx.lineWidth = 0.45; ctx.stroke();
      });
      packets.forEach((p) => {
        p.t += p.speed * p.dir;
        if (p.t > 1) { p.t = 1; p.dir = -1; }
        if (p.t < 0) { p.t = 0; p.dir = 1; }
        const a = nodes[p.a], b = nodes[p.b];
        const x = a.x + (b.x - a.x) * p.t, y = a.y + (b.y - a.y) * p.t;
        ctx.beginPath(); ctx.arc(x, y, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0,210,255,0.9)"; ctx.fill();
        ctx.beginPath(); ctx.arc(x, y, 5.5, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0,210,255,0.12)"; ctx.fill();
      });
      nodes.forEach((n) => {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
        n.phase += 0.035;
        const p = 0.5 + 0.5 * Math.sin(n.phase);
        const col =
          n.type === "threat"
            ? `rgba(255,55,55,${0.5 + 0.4 * p})`
            : n.type === "active"
              ? `rgba(0,210,255,${0.55 + 0.35 * p})`
              : `rgba(100,160,255,${0.35 + 0.25 * p})`;
        const glow =
          n.type === "threat"
            ? "rgba(255,55,55,0.15)"
            : n.type === "active"
              ? "rgba(0,210,255,0.12)"
              : "rgba(80,130,255,0.08)";
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r * 3, 0, Math.PI * 2);
        ctx.fillStyle = glow; ctx.fill();
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = col; ctx.fill();
      });
      if (Math.random() < 0.006 && packets.length < 50) {
        const ei = Math.floor(Math.random() * edges.length);
        if (ei < edges.length) spawnPacket(edges[ei].a, edges[ei].b);
      }
      drawMouseLines();
      drawMouseRipple();
      animId = requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener("resize", resize);
    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const rx = e.clientX - rect.left;
    const ry = e.clientY - rect.top;
    mouseRef.current = { x: rx, y: ry };
    if (spotlightRef.current) {
      spotlightRef.current.style.left = rx + "px";
      spotlightRef.current.style.top = ry + "px";
    }
    if (cardRef.current) {
      const el = e.currentTarget;
      const cw = el.offsetWidth;
      const ch = el.offsetHeight;
      const dx = ((rx - cw / 2) / (cw / 2)) * 6;
      const dy = ((ry - ch / 2) / (ch / 2)) * 4;
      cardRef.current.style.transform = `perspective(900px) rotateY(${dx}deg) rotateX(${-dy}deg) translateZ(4px)`;
      cardRef.current.style.transition = "transform .12s ease";
    }
  };

  const handleMouseLeave = () => {
    if (cardRef.current) {
      cardRef.current.style.transform =
        "perspective(900px) rotateY(0deg) rotateX(0deg) translateZ(0px)";
      cardRef.current.style.transition = "transform .5s ease";
    }
  };

  return (
    <main
      className="relative min-h-screen w-full flex items-start sm:items-center justify-center px-3 sm:px-4 md:px-6 py-4 sm:py-6 lg:py-8 overflow-hidden"
      style={{
        background: "#030812",
        "--bg": "#000000",
        "--bg-rgb": "2, 6, 23",
        "--surface": "#16161d70",
        "--surface-rgb": "15, 23, 42",
        "--surface-50": "#0f172a80",
        "--border": "rgba(255, 255, 255, 0.1)",
        "--text": "#ffffff",
        "--muted": "#94a3b8",
        "--color-primary": "#06b6d4",
        "--color-primary-rgb": "6, 182, 212",
        "--color-secondary-rgb": "139, 92, 246",
        "--glass-dark-bg": "rgba(2, 6, 23, 0.85)",
      }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
    >
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full"
        style={{ display: "block" }}
      />

      {/* ── Floating Illustration Layer ── */}
      <div className="pointer-events-none absolute inset-0 z-[1] overflow-hidden hidden lg:block">
        {/* Shield — top-left */}
        <div className="absolute -top-12 -left-12 opacity-[0.045]" style={{ animation: "lp-float-slow 13s ease-in-out infinite" }}>
          <svg width="310" height="310" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M50 6 L88 21 L88 50 C88 71 71 87 50 95 C29 87 12 71 12 50 L12 21 Z" stroke="rgba(0,180,255,1)" strokeWidth="1.4" fill="none" />
            <path d="M50 19 L76 30 L76 50 C76 65 65 77 50 83 C35 77 24 65 24 50 L24 30 Z" stroke="rgba(0,180,255,0.55)" strokeWidth="0.8" fill="none" />
            <circle cx="50" cy="53" r="10" stroke="rgba(0,180,255,0.45)" strokeWidth="0.8" fill="none" />
            <line x1="50" y1="38" x2="50" y2="43" stroke="rgba(0,180,255,0.45)" strokeWidth="0.9" />
            <path d="M42 53 L47 58 L60 47" stroke="rgba(0,210,255,0.6)" strokeWidth="1.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>

        {/* Fingerprint — top-right */}
        <div className="absolute -top-8 -right-8 opacity-[0.038]" style={{ animation: "lp-float 10s ease-in-out infinite", animationDelay: "2s" }}>
          <svg width="270" height="270" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M30 70 C20 60 18 40 30 28 C42 16 58 16 70 28 C82 40 80 60 70 70 C60 80 40 82 30 70" stroke="rgba(100,140,255,1)" strokeWidth="1" fill="none" />
            <path d="M36 65 C28 55 27 43 36 34 C45 25 55 25 64 34 C73 43 72 55 64 65" stroke="rgba(100,140,255,1)" strokeWidth="1" fill="none" />
            <path d="M42 60 C36 52 36 46 42 40 C48 34 54 35 58 40 C64 46 62 55 56 60" stroke="rgba(100,140,255,1)" strokeWidth="1" fill="none" />
            <path d="M47 56 C44 51 44 49 47 46 C50 43 53 44 55 47" stroke="rgba(100,140,255,1)" strokeWidth="1" fill="none" />
            <circle cx="50" cy="50" r="2.5" stroke="rgba(100,140,255,0.8)" strokeWidth="0.8" fill="none" />
          </svg>
        </div>

        {/* Lock — bottom-right */}
        <div className="absolute -bottom-10 right-16 opacity-[0.042]" style={{ animation: "lp-float-slow 15s ease-in-out infinite", animationDelay: "4s" }}>
          <svg width="200" height="220" viewBox="0 0 100 110" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="18" y="46" width="64" height="50" rx="7" stroke="rgba(0,200,255,1)" strokeWidth="1.5" fill="none" />
            <path d="M34 46 L34 31 C34 18 66 18 66 31 L66 46" stroke="rgba(0,200,255,1)" strokeWidth="1.5" fill="none" />
            <circle cx="50" cy="68" r="8" stroke="rgba(0,200,255,0.7)" strokeWidth="1.1" fill="none" />
            <line x1="50" y1="76" x2="50" y2="84" stroke="rgba(0,200,255,0.7)" strokeWidth="1.1" />
            <rect x="22" y="50" width="56" height="42" rx="5" stroke="rgba(0,200,255,0.22)" strokeWidth="0.5" fill="none" />
          </svg>
        </div>

        {/* Circuit nodes — bottom-left */}
        <div className="absolute bottom-8 -left-8 opacity-[0.04]" style={{ animation: "lp-float 12s ease-in-out infinite", animationDelay: "1s" }}>
          <svg width="240" height="240" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="20" cy="20" r="5" stroke="rgba(0,180,255,1)" strokeWidth="1.1" />
            <circle cx="80" cy="20" r="5" stroke="rgba(0,180,255,1)" strokeWidth="1.1" />
            <circle cx="50" cy="50" r="8" stroke="rgba(0,180,255,1)" strokeWidth="1.3" />
            <circle cx="20" cy="80" r="5" stroke="rgba(0,180,255,1)" strokeWidth="1.1" />
            <circle cx="80" cy="80" r="5" stroke="rgba(0,180,255,1)" strokeWidth="1.1" />
            <line x1="20" y1="25" x2="20" y2="42" stroke="rgba(0,180,255,0.55)" strokeWidth="0.7" />
            <line x1="24" y1="23" x2="42" y2="43" stroke="rgba(0,180,255,0.55)" strokeWidth="0.7" />
            <line x1="76" y1="23" x2="58" y2="43" stroke="rgba(0,180,255,0.55)" strokeWidth="0.7" />
            <line x1="80" y1="25" x2="80" y2="75" stroke="rgba(0,180,255,0.3)" strokeWidth="0.5" />
            <line x1="58" y1="57" x2="24" y2="76" stroke="rgba(0,180,255,0.55)" strokeWidth="0.7" />
            <line x1="58" y1="57" x2="76" y2="76" stroke="rgba(0,180,255,0.55)" strokeWidth="0.7" />
            <circle cx="20" cy="20" r="2" fill="rgba(0,180,255,0.3)" />
            <circle cx="80" cy="20" r="2" fill="rgba(0,180,255,0.3)" />
            <circle cx="50" cy="50" r="3" fill="rgba(0,180,255,0.25)" />
            <circle cx="20" cy="80" r="2" fill="rgba(0,180,255,0.3)" />
            <circle cx="80" cy="80" r="2" fill="rgba(0,180,255,0.3)" />
          </svg>
        </div>

        {/* Eye / scan — middle-right */}
        <div className="absolute top-[38%] -right-14 opacity-[0.035]" style={{ animation: "lp-float-slow 17s ease-in-out infinite", animationDelay: "3.5s" }}>
          <svg width="260" height="130" viewBox="0 0 200 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M8 50 C50 8 150 8 192 50 C150 92 50 92 8 50 Z" stroke="rgba(120,80,255,1)" strokeWidth="1.4" fill="none" />
            <circle cx="100" cy="50" r="24" stroke="rgba(120,80,255,0.75)" strokeWidth="1.1" fill="none" />
            <circle cx="100" cy="50" r="11" stroke="rgba(120,80,255,0.6)" strokeWidth="1" fill="none" />
            <circle cx="100" cy="50" r="3.5" fill="rgba(120,80,255,0.35)" />
            <line x1="8" y1="50" x2="192" y2="50" stroke="rgba(120,80,255,0.18)" strokeWidth="0.5" />
          </svg>
        </div>

        {/* Key — center-left */}
        <div className="absolute top-[28%] left-10 opacity-[0.04]" style={{ animation: "lp-float 11s ease-in-out infinite", animationDelay: "5s" }}>
          <svg width="160" height="160" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="34" cy="38" r="21" stroke="rgba(0,210,255,1)" strokeWidth="1.4" fill="none" />
            <circle cx="34" cy="38" r="12" stroke="rgba(0,210,255,0.55)" strokeWidth="0.9" fill="none" />
            <line x1="53" y1="52" x2="88" y2="76" stroke="rgba(0,210,255,1)" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="72" y1="64" x2="72" y2="78" stroke="rgba(0,210,255,0.8)" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="80" y1="70" x2="80" y2="82" stroke="rgba(0,210,255,0.8)" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </div>

        {/* Hexagon stamp — bottom-center */}
        <div className="absolute -bottom-16 left-[42%] opacity-[0.03]" style={{ animation: "lp-float-slow 18s ease-in-out infinite", animationDelay: "7s" }}>
          <svg width="220" height="220" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5" stroke="rgba(0,180,255,1)" strokeWidth="1.2" fill="none" />
            <polygon points="50,17 80,33 80,67 50,83 20,67 20,33" stroke="rgba(0,180,255,0.6)" strokeWidth="0.8" fill="none" />
            <polygon points="50,29 70,39.5 70,60.5 50,71 30,60.5 30,39.5" stroke="rgba(120,80,255,0.5)" strokeWidth="0.7" fill="none" />
            <circle cx="50" cy="50" r="6" stroke="rgba(0,180,255,0.5)" strokeWidth="0.8" fill="none" />
          </svg>
        </div>
      </div>

      <div
        ref={spotlightRef}
        className="pointer-events-none absolute z-[1] hidden lg:block"
        style={{
          width: "500px",
          height: "500px",
          borderRadius: "50%",
          transform: "translate(-50%, -50%)",
          background: "radial-gradient(circle, rgba(0,200,255,0.07) 0%, transparent 70%)",
          left: "50%",
          top: "50%",
        }}
      />
      <div
        ref={cardRef}
        className="relative z-[3] w-full max-w-[420px] sm:max-w-[460px]"
        style={{ transition: "transform .5s ease" }}
      >
        <div className="relative rounded-[22px] sm:rounded-[28px] border border-[var(--border)] bg-[linear-gradient(160deg,rgba(var(--surface-rgb),0.16)_0%,rgba(var(--surface-rgb),0.08)_38%,rgba(var(--surface-rgb),0.04)_100%)] backdrop-blur-[26px] shadow-[0_24px_60px_rgba(var(--bg-rgb),0.5),inset_0_1px_0_rgba(255,255,255,0.2),inset_0_-1px_0_rgba(255,255,255,0.08)] px-4 py-4 sm:px-7 sm:py-7">
          <div className="pointer-events-none absolute inset-0 rounded-[28px] bg-[radial-gradient(circle_at_22%_0%,rgba(255,255,255,0.24),transparent_42%)]" />
          <div className="pointer-events-none absolute inset-[1px] rounded-[27px] bg-[linear-gradient(170deg,rgba(6,12,24,0.55)_0%,rgba(13,21,38,0.64)_100%)]" />
          <div className="pointer-events-none absolute top-0 left-1/2 -translate-x-1/2 h-[1px] w-[76%] bg-gradient-to-r from-transparent via-white/80 to-transparent" />
          <section className="relative z-10 flex w-full flex-col items-center text-center">
            <Image
              src={Logo}
              alt="Company Logo"
              className="mb-3 h-8 w-auto drop-shadow-lg sm:mb-4 sm:h-10"
              priority
            />

            <h1 className="text-[17px] leading-6 font-bold text-[var(--text)] sm:text-[20px] sm:leading-7" style={{ fontFamily: "Sora, var(--font-ui)" }}>
              Sign in to Continue
            </h1>
            <p className="mt-1 max-w-[320px] text-[12px] leading-5 text-[var(--muted)] sm:text-[14px] sm:leading-[23px]" style={{ fontFamily: "DM Sans, var(--font-ui)" }}>
              Access your workspace securely through your preferred account.
            </p>

            <div className="mt-4 sm:mt-5 h-px w-full bg-[linear-gradient(90deg,rgba(var(--color-primary-rgb),0)_0%,rgba(var(--color-primary-rgb),0.35)_50%,rgba(var(--color-primary-rgb),0)_100%)]" />

            {error && (
              <div className="w-full mt-5 px-4 py-3 rounded-xl border border-rose-300/35 bg-rose-500/20 text-rose-100 text-sm font-medium">
                {error}
              </div>
            )}

            <div className="mt-4 sm:mt-5 w-full pb-1 sm:pb-3">
              <LoginOptions
                onGitHubLogin={handleGitHubLogin}
                isLoading={isLoading}
                orgId={orgId}
                onLeaveOrg={handleLeaveOrg}
              />
            </div>

            <div className="w-full pt-1 sm:pt-2">
              <p className="mt-3 sm:mt-4 text-center text-[11px] sm:text-[12px] leading-5 text-[var(--muted)]" style={{ fontFamily: "DM Sans, var(--font-ui)" }}>
                By signing in, you agree to our{" "}
                <Link href="/terms" prefetch={false} className="text-[var(--color-primary)] hover:opacity-80 transition-opacity">
                  Terms &amp; Conditions
                </Link>
                ,{" "}
                <Link href="/privacy" prefetch={false} className="text-[var(--color-primary)] hover:opacity-80 transition-opacity">
                  Privacy Policy
                </Link>
                , and{" "}
                <Link href="/cookies" prefetch={false} className="text-[var(--color-primary)] hover:opacity-80 transition-opacity">
                  Cookie Policy
                </Link>
                .
              </p>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
