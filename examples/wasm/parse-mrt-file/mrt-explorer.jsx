import { useState, useEffect, useRef, useCallback } from "react";

// ── Example MRT files from RIPE RIS (gzipped updates) ─────────────────────
const PRESETS = [
  {
    label: "RIPE RIS rrc00 — 2025-01-01 00:00",
    url: "https://data.ris.ripe.net/rrc00/2025.01/updates.20250101.0000.gz",
  },
  {
    label: "RIPE RIS rrc06 — 2025-06-01 00:00",
    url: "https://data.ris.ripe.net/rrc06/2025.06/updates.20250601.0000.gz",
  },
  {
    label: "RIPE RIS rrc21 — 2025-01-01 00:00",
    url: "https://data.ris.ripe.net/rrc21/2025.01/updates.20250101.0000.gz",
  },
];

// ── Utility ────────────────────────────────────────────────────────────────
function fmtTs(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function truncate(str, n) {
  if (!str) return "—";
  return str.length > n ? str.slice(0, n) + "…" : str;
}

async function decompressGzip(bytes) {
  if (bytes[0] !== 0x1f || bytes[1] !== 0x8b) return bytes; // not gzip
  const stream = new Response(bytes).body.pipeThrough(
    new DecompressionStream("gzip")
  );
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

// ── Component ──────────────────────────────────────────────────────────────
export default function MrtExplorer() {
  const [wasmStatus, setWasmStatus] = useState("loading"); // loading | ready | error
  const [wasmError, setWasmError] = useState("");
  const parseFn = useRef(null);

  const [url, setUrl] = useState(PRESETS[0].url);
  const [isDragging, setIsDragging] = useState(false);

  const [stage, setStage] = useState(""); // fetch | decompress | parse | done
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [elems, setElems] = useState([]);
  const [stats, setStats] = useState(null);
  const [fileName, setFileName] = useState("");

  // Table state
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [sortCol, setSortCol] = useState("timestamp");
  const [sortDir, setSortDir] = useState("asc");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  // ── Load WASM ──────────────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        // Use new Function to bypass the artifact bundler's static import analysis.
        // The bundler would throw "Module not found" on a bare URL string literal
        // inside a normal import(), but can't analyze through new Function.
        const dynamicImport = new Function("url", "return import(url)");

        // esm.sh serves wasm-bindgen packages with the wasm binary colocated.
        // The web target exports a default init() that accepts an optional wasm URL.
        const CDN = "https://esm.sh/@bgpkit/parser@0.15.0";
        const mod = await dynamicImport(CDN);

        // web target: default export is init(); bundler target: no init needed.
        if (typeof mod.default === "function") {
          // Point init() at the wasm binary esm.sh serves alongside the JS
          try {
            await mod.default(`${CDN}/bgpkit_parser_bg.wasm`);
          } catch {
            // Some builds self-fetch the wasm; try without explicit URL
            await mod.default();
          }
        }

        const recFn = mod.parseMrtRecords ?? mod.parse_mrt_records;
        if (!recFn) throw new Error("parseMrtRecords not exported — check package version");
        // Wrap the generator into a batch function for the UI
        parseFn.current = (data) => {
          const allElems = [];
          for (const { elems } of recFn(data)) allElems.push(...elems);
          return allElems;
        };
        setWasmStatus("ready");
      } catch (e) {
        setWasmStatus("error");
        setWasmError(e.message);
      }
    })();
  }, []);

  // ── Parse ──────────────────────────────────────────────────────────────
  async function runParse(rawBytes, name) {
    setError("");
    setElems([]);
    setStats(null);
    setPage(0);
    setFileName(name);

    try {
      setStage("decompress");
      setProgress(20);
      const decompressed = await decompressGzip(rawBytes);

      setStage("parse");
      setProgress(50);
      const result = parseFn.current(decompressed);

      // result is BgpElem[] (array of JS objects from wasm-bindgen)
      const data = Array.isArray(result)
        ? result
        : typeof result === "string"
        ? JSON.parse(result)
        : [];

      setProgress(100);
      setElems(data);
      setStage("done");

      const announces = data.filter(
        (e) => (e.type || e.elem_type) === "ANNOUNCE" || e.elem_type === "A"
      ).length;
      const peerAsns = new Set(data.map((e) => e.peer_asn)).size;
      const prefixes = new Set(data.map((e) => e.prefix)).size;
      const originAsns = new Set(
        data.flatMap((e) => (e.origin_asns || []))
      ).size;
      setStats({
        total: data.length,
        announces,
        withdraws: data.length - announces,
        peerAsns,
        prefixes,
        originAsns,
      });
    } catch (e) {
      setError(e.message);
      setStage("");
    }
  }

  async function handleFetchUrl() {
    if (!parseFn.current) return;
    setStage("fetch");
    setProgress(0);
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);

      setStage("download");
      setProgress(10);
      const raw = new Uint8Array(await resp.arrayBuffer());
      const name = url.split("/").pop();
      await runParse(raw, name);
    } catch (e) {
      setError(e.message);
      setStage("");
    }
  }

  const handleDrop = useCallback(
    async (e) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (!file || !parseFn.current) return;
      setStage("read");
      setProgress(5);
      const raw = new Uint8Array(await file.arrayBuffer());
      await runParse(raw, file.name);
    },
    []
  );

  const handleFileInput = useCallback(async (e) => {
    const file = e.target.files[0];
    if (!file || !parseFn.current) return;
    setStage("read");
    setProgress(5);
    const raw = new Uint8Array(await file.arrayBuffer());
    await runParse(raw, file.name);
  }, []);

  // ── Filtering & sorting ────────────────────────────────────────────────
  const filtered = elems
    .filter((e) => {
      const t = e.type || (e.elem_type === "W" ? "WITHDRAW" : "ANNOUNCE");
      if (typeFilter !== "ALL" && t !== typeFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          (e.prefix || "").toLowerCase().includes(q) ||
          String(e.peer_asn || "").includes(q) ||
          (e.as_path || "").toLowerCase().includes(q) ||
          (e.peer_ip || "").toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      let av = a[sortCol] ?? "";
      let bv = b[sortCol] ?? "";
      if (sortCol === "peer_asn") { av = +av; bv = +bv; }
      if (typeof av === "number") return sortDir === "asc" ? av - bv : bv - av;
      return sortDir === "asc"
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageData = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  function toggleSort(col) {
    if (sortCol === col) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortCol(col); setSortDir("asc"); }
    setPage(0);
  }

  const isLoading = ["fetch", "download", "read", "decompress", "parse"].includes(stage);

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0e14",
      color: "#c5cdd9",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      fontSize: "13px",
    }}>
      {/* Google Font */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0a0e14; }
        ::-webkit-scrollbar-thumb { background: #2a3042; border-radius: 3px; }

        .btn {
          background: transparent;
          border: 1px solid #2a3042;
          color: #7aa2f7;
          padding: 6px 14px;
          cursor: pointer;
          font-family: inherit;
          font-size: 12px;
          letter-spacing: 0.05em;
          transition: all 0.15s;
          border-radius: 2px;
        }
        .btn:hover:not(:disabled) {
          border-color: #7aa2f7;
          background: rgba(122, 162, 247, 0.08);
        }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .btn-primary {
          background: #7aa2f7;
          color: #0a0e14;
          border-color: #7aa2f7;
          font-weight: 600;
        }
        .btn-primary:hover:not(:disabled) {
          background: #9ab5ff;
          border-color: #9ab5ff;
        }

        input, select {
          background: #0d1117;
          border: 1px solid #2a3042;
          color: #c5cdd9;
          padding: 6px 10px;
          font-family: inherit;
          font-size: 12px;
          border-radius: 2px;
          outline: none;
          transition: border-color 0.15s;
        }
        input:focus, select:focus { border-color: #7aa2f7; }
        select option { background: #0d1117; }

        .th-btn {
          background: none;
          border: none;
          color: #506073;
          cursor: pointer;
          font-family: inherit;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          padding: 0;
          white-space: nowrap;
          display: flex;
          align-items: center;
          gap: 4px;
        }
        .th-btn:hover { color: #c5cdd9; }
        .th-btn.active { color: #7aa2f7; }

        @keyframes shimmer {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn 0.3s ease forwards; }

        .tr-announce:hover { background: rgba(115, 218, 148, 0.04) !important; }
        .tr-withdraw:hover { background: rgba(247, 118, 142, 0.04) !important; }
      `}</style>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{
        borderBottom: "1px solid #1a2030",
        padding: "12px 20px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        position: "sticky",
        top: 0,
        zIndex: 100,
        background: "#0a0e14",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ color: "#7aa2f7", fontWeight: 700, fontSize: "15px", letterSpacing: "0.02em" }}>
            MRT Explorer
          </span>
          <span style={{ color: "#2a3042", fontSize: "11px" }}>powered by</span>
          <span style={{
            background: "rgba(122, 162, 247, 0.1)",
            border: "1px solid rgba(122, 162, 247, 0.2)",
            color: "#7aa2f7",
            padding: "2px 8px",
            borderRadius: "2px",
            fontSize: "11px",
            letterSpacing: "0.04em",
          }}>@bgpkit/parser@0.15.0</span>
        </div>

        {/* WASM Status */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
          <span style={{
            width: 7, height: 7, borderRadius: "50%",
            background: wasmStatus === "ready" ? "#73da94"
              : wasmStatus === "error" ? "#f7768e"
              : "#e0af68",
            display: "inline-block",
            animation: wasmStatus === "loading" ? "pulse 1.2s ease infinite" : "none",
          }} />
          <span style={{ color: "#506073" }}>
            WASM {wasmStatus === "ready" ? "ready" : wasmStatus === "error" ? "error" : "loading…"}
          </span>
          {wasmStatus === "error" && (
            <span style={{ color: "#f7768e", marginLeft: 4 }}>{truncate(wasmError, 60)}</span>
          )}
        </div>
      </div>

      <div style={{ maxWidth: 1400, margin: "0 auto", padding: "20px" }}>

        {/* ── Input Panel ───────────────────────────────────────────────── */}
        <div style={{
          border: "1px solid #1a2030",
          borderRadius: "4px",
          overflow: "hidden",
          marginBottom: 20,
        }}>
          {/* Drop Zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            style={{
              padding: "20px",
              borderBottom: "1px solid #1a2030",
              background: isDragging ? "rgba(122, 162, 247, 0.06)" : "transparent",
              borderTop: isDragging ? "2px solid #7aa2f7" : "2px solid transparent",
              transition: "all 0.15s",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 8,
              cursor: "default",
            }}
          >
            <span style={{ color: "#506073", fontSize: "12px" }}>
              {isDragging ? "DROP MRT FILE HERE" : "DRAG & DROP .mrt / .gz / .bz2"}
            </span>
            <span style={{ color: "#2a3042", fontSize: "11px" }}>or</span>
            <label style={{
              cursor: "pointer",
              color: "#7aa2f7",
              fontSize: "11px",
              letterSpacing: "0.05em",
              textDecoration: "underline",
              textUnderlineOffset: "3px",
            }}>
              browse files
              <input type="file" style={{ display: "none" }} onChange={handleFileInput} />
            </label>
          </div>

          {/* URL Input */}
          <div style={{ padding: "14px 20px", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <select
              value=""
              onChange={(e) => { if (e.target.value) setUrl(e.target.value); }}
              style={{ minWidth: 160 }}
            >
              <option value="">— Presets —</option>
              {PRESETS.map((p) => (
                <option key={p.url} value={p.url}>{p.label}</option>
              ))}
            </select>

            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://data.ris.ripe.net/…/updates.*.gz"
              style={{ flex: 1, minWidth: 300 }}
              onKeyDown={(e) => e.key === "Enter" && !isLoading && wasmStatus === "ready" && handleFetchUrl()}
            />

            <button
              className="btn btn-primary"
              disabled={isLoading || wasmStatus !== "ready" || !url}
              onClick={handleFetchUrl}
            >
              {isLoading ? "PARSING…" : "FETCH & PARSE"}
            </button>
          </div>

          {/* Progress */}
          {isLoading && (
            <div style={{ padding: "0 20px 14px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ color: "#506073", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  {stage === "fetch" || stage === "download" ? "↓ fetching"
                    : stage === "decompress" ? "⟳ decompressing"
                    : stage === "parse" ? "⚙ parsing wasm"
                    : stage === "read" ? "↑ reading file"
                    : "…"}
                </span>
                <span style={{ color: "#7aa2f7", fontSize: "11px" }}>{progress}%</span>
              </div>
              <div style={{ height: 2, background: "#1a2030", borderRadius: 1 }}>
                <div style={{
                  height: "100%",
                  width: `${progress}%`,
                  background: "linear-gradient(90deg, #7aa2f7, #bb9af7)",
                  borderRadius: 1,
                  transition: "width 0.4s ease",
                }} />
              </div>
            </div>
          )}

          {error && (
            <div style={{
              padding: "10px 20px",
              background: "rgba(247, 118, 142, 0.06)",
              borderTop: "1px solid rgba(247, 118, 142, 0.2)",
              color: "#f7768e",
              fontSize: "12px",
            }}>
              ✗ {error}
            </div>
          )}
        </div>

        {/* ── Stats ─────────────────────────────────────────────────────── */}
        {stats && (
          <div className="fade-in" style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
            gap: 10,
            marginBottom: 20,
          }}>
            {[
              { label: "Total Elems", value: stats.total.toLocaleString(), color: "#7aa2f7" },
              { label: "Announcements", value: stats.announces.toLocaleString(), color: "#73da94" },
              { label: "Withdrawals", value: stats.withdraws.toLocaleString(), color: "#f7768e" },
              { label: "Peer ASNs", value: stats.peerAsns.toLocaleString(), color: "#e0af68" },
              { label: "Unique Prefixes", value: stats.prefixes.toLocaleString(), color: "#bb9af7" },
            ].map((s) => (
              <div key={s.label} style={{
                border: "1px solid #1a2030",
                borderRadius: 4,
                padding: "12px 16px",
                background: "#0d1117",
              }}>
                <div style={{ color: "#506073", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>
                  {s.label}
                </div>
                <div style={{ color: s.color, fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em" }}>
                  {s.value}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Table ─────────────────────────────────────────────────────── */}
        {elems.length > 0 && (
          <div className="fade-in" style={{
            border: "1px solid #1a2030",
            borderRadius: 4,
            overflow: "hidden",
          }}>
            {/* Table Controls */}
            <div style={{
              display: "flex",
              gap: 8,
              padding: "10px 14px",
              borderBottom: "1px solid #1a2030",
              alignItems: "center",
              flexWrap: "wrap",
              background: "#0d1117",
            }}>
              <span style={{ color: "#506073", fontSize: "11px", marginRight: 4 }}>
                {fileName && <span style={{ color: "#7aa2f7" }}>{fileName}</span>}
                {" "}· {filtered.length.toLocaleString()} rows
              </span>

              <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
                {["ALL", "ANNOUNCE", "WITHDRAW"].map((t) => (
                  <button
                    key={t}
                    className="btn"
                    onClick={() => { setTypeFilter(t); setPage(0); }}
                    style={{
                      borderColor: typeFilter === t
                        ? t === "ANNOUNCE" ? "#73da94" : t === "WITHDRAW" ? "#f7768e" : "#7aa2f7"
                        : "#2a3042",
                      color: typeFilter === t
                        ? t === "ANNOUNCE" ? "#73da94" : t === "WITHDRAW" ? "#f7768e" : "#7aa2f7"
                        : "#506073",
                      padding: "4px 10px",
                      fontSize: "11px",
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>

              <input
                type="text"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0); }}
                placeholder="filter prefix / ASN / AS-path…"
                style={{ width: 240 }}
              />
            </div>

            {/* Table */}
            <div style={{ overflowX: "auto" }}>
              <table style={{
                width: "100%",
                borderCollapse: "collapse",
                tableLayout: "auto",
              }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1a2030" }}>
                    {[
                      { key: "timestamp", label: "Timestamp" },
                      { key: "type", label: "Type" },
                      { key: "prefix", label: "Prefix" },
                      { key: "peer_asn", label: "Peer ASN" },
                      { key: "peer_ip", label: "Peer IP" },
                      { key: "as_path", label: "AS Path" },
                      { key: "next_hop", label: "Next Hop" },
                      { key: "communities", label: "Communities" },
                    ].map((col) => (
                      <th key={col.key} style={{
                        padding: "8px 12px",
                        textAlign: "left",
                        background: "#0d1117",
                        whiteSpace: "nowrap",
                      }}>
                        <button
                          className={`th-btn ${sortCol === col.key ? "active" : ""}`}
                          onClick={() => toggleSort(col.key)}
                        >
                          {col.label}
                          {sortCol === col.key && (
                            <span>{sortDir === "asc" ? " ↑" : " ↓"}</span>
                          )}
                        </button>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {pageData.map((e, i) => {
                    const type = e.type || (e.elem_type === "W" ? "WITHDRAW" : "ANNOUNCE");
                    const isAnn = type === "ANNOUNCE";
                    const asPath = e.as_path
                      ? (Array.isArray(e.as_path) ? e.as_path.join(" ") : String(e.as_path))
                      : null;
                    const communities = e.communities
                      ? (Array.isArray(e.communities)
                          ? e.communities.join(" ")
                          : String(e.communities))
                      : null;

                    return (
                      <tr
                        key={i}
                        className={isAnn ? "tr-announce" : "tr-withdraw"}
                        style={{
                          borderBottom: "1px solid #0f1621",
                          background: i % 2 === 0 ? "#0a0e14" : "#0c111a",
                          transition: "background 0.1s",
                        }}
                      >
                        <td style={{ padding: "6px 12px", color: "#506073", whiteSpace: "nowrap", fontSize: "12px" }}>
                          {fmtTs(e.timestamp)}
                        </td>
                        <td style={{ padding: "6px 12px", whiteSpace: "nowrap" }}>
                          <span style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            letterSpacing: "0.06em",
                            padding: "2px 6px",
                            borderRadius: "2px",
                            background: isAnn ? "rgba(115, 218, 148, 0.12)" : "rgba(247, 118, 142, 0.12)",
                            color: isAnn ? "#73da94" : "#f7768e",
                            border: `1px solid ${isAnn ? "rgba(115,218,148,0.25)" : "rgba(247,118,142,0.25)"}`,
                          }}>
                            {isAnn ? "ANN" : "WDR"}
                          </span>
                        </td>
                        <td style={{ padding: "6px 12px", color: "#9ab5ff", whiteSpace: "nowrap", fontWeight: 500 }}>
                          {e.prefix || "—"}
                        </td>
                        <td style={{ padding: "6px 12px", color: "#e0af68", whiteSpace: "nowrap" }}>
                          {e.peer_asn ? `AS${e.peer_asn}` : "—"}
                        </td>
                        <td style={{ padding: "6px 12px", color: "#506073", whiteSpace: "nowrap", fontSize: "12px" }}>
                          {e.peer_ip || "—"}
                        </td>
                        <td style={{ padding: "6px 12px", color: "#c5cdd9", maxWidth: 280 }}>
                          <span title={asPath || ""} style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {asPath ? truncate(asPath, 50) : <span style={{ color: "#2a3042" }}>—</span>}
                          </span>
                        </td>
                        <td style={{ padding: "6px 12px", color: "#506073", whiteSpace: "nowrap", fontSize: "12px" }}>
                          {e.next_hop || <span style={{ color: "#2a3042" }}>—</span>}
                        </td>
                        <td style={{ padding: "6px 12px", color: "#bb9af7", maxWidth: 200, fontSize: "11px" }}>
                          <span title={communities || ""} style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {communities || <span style={{ color: "#2a3042" }}>—</span>}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "8px 14px",
                borderTop: "1px solid #1a2030",
                background: "#0d1117",
              }}>
                <span style={{ color: "#506073", fontSize: "11px" }}>
                  {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length.toLocaleString()}
                </span>
                <div style={{ display: "flex", gap: 4 }}>
                  <button className="btn" disabled={page === 0} onClick={() => setPage(0)} style={{ padding: "3px 8px", fontSize: "11px" }}>«</button>
                  <button className="btn" disabled={page === 0} onClick={() => setPage(p => p - 1)} style={{ padding: "3px 8px", fontSize: "11px" }}>‹</button>
                  <span style={{ color: "#7aa2f7", fontSize: "11px", padding: "3px 10px", border: "1px solid #2a3042", borderRadius: 2 }}>
                    {page + 1} / {totalPages}
                  </span>
                  <button className="btn" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} style={{ padding: "3px 8px", fontSize: "11px" }}>›</button>
                  <button className="btn" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)} style={{ padding: "3px 8px", fontSize: "11px" }}>»</button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Empty state ────────────────────────────────────────────────── */}
        {!isLoading && elems.length === 0 && !error && (
          <div style={{
            textAlign: "center",
            padding: "60px 20px",
            color: "#2a3042",
          }}>
            <div style={{ fontSize: "32px", marginBottom: 12 }}>⟁</div>
            <div style={{ fontSize: "13px", letterSpacing: "0.04em" }}>
              {wasmStatus === "ready"
                ? "select a preset or enter an MRT URL above"
                : wasmStatus === "loading"
                ? "loading wasm module…"
                : "wasm failed to load — check console"}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
