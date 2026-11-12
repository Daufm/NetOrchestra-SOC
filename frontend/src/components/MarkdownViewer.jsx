/**
 * Lightweight, zero-dependency Markdown renderer for React with SOC styling.
 * Supports headers (#, ##, ###), lists, tables, inline code, fenced code blocks,
 * blockquotes, horizontal rules, bold, italic, links, and badges.
 */
export function MarkdownViewer({ content }) {
  if (!content) return null;

  const lines = content.split("\n");
  const elements = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block ```
    if (line.trim().startsWith("```")) {
      const lang = line.trim().slice(3).trim();
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // Skip closing ```
      elements.push(
        <div key={`code-${i}`} className="my-4 overflow-hidden rounded-md border border-soc-border bg-black/60">
          {lang && (
            <div className="border-b border-soc-border bg-slate-900/80 px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-slate-400">
              {lang}
            </div>
          )}
          <pre className="overflow-x-auto p-4 font-mono text-xs text-slate-300">
            <code>{codeLines.join("\n")}</code>
          </pre>
        </div>
      );
      continue;
    }

    // Markdown Table: lines starting with |
    if (line.trim().startsWith("|") && line.trim().endsWith("|")) {
      const tableLines = [];
      while (i < lines.length && lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      if (tableLines.length >= 2) {
        const parseRow = (row) =>
          row
            .split("|")
            .slice(1, -1)
            .map((cell) => cell.trim());

        const headers = parseRow(tableLines[0]);
        // line 1 is separator |---|---|
        const rows = tableLines.slice(2).map(parseRow);

        elements.push(
          <div key={`table-${i}`} className="my-4 overflow-x-auto rounded border border-soc-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/90 text-slate-300">
                <tr>
                  {headers.map((h, hi) => (
                    <th key={hi} className="border-b border-soc-border px-3 py-2 font-mono font-semibold text-soc-neon">
                      {renderInline(h)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/60 font-mono text-slate-300">
                {rows.map((row, ri) => (
                  <tr key={ri} className="hover:bg-slate-900/40">
                    {row.map((cell, ci) => (
                      <td key={ci} className="px-3 py-2 align-top">
                        {renderInline(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
        continue;
      }
    }

    // Headings
    if (line.startsWith("# ")) {
      elements.push(
        <h1 key={`h1-${i}`} className="mb-4 mt-6 border-b border-soc-border pb-2 text-2xl font-bold tracking-tight text-white">
          {renderInline(line.slice(2))}
        </h1>
      );
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      elements.push(
        <h2 key={`h2-${i}`} className="mb-3 mt-6 border-b border-soc-border/60 pb-1.5 text-lg font-semibold text-soc-neon">
          {renderInline(line.slice(3))}
        </h2>
      );
      i++;
      continue;
    }
    if (line.startsWith("### ")) {
      elements.push(
        <h3 key={`h3-${i}`} className="mb-2 mt-4 text-sm font-semibold uppercase tracking-wider text-slate-200">
          {renderInline(line.slice(4))}
        </h3>
      );
      i++;
      continue;
    }

    // Blockquote >
    if (line.startsWith("> ")) {
      elements.push(
        <blockquote
          key={`quote-${i}`}
          className="my-3 border-l-2 border-soc-neon bg-soc-neon/5 px-4 py-2 text-xs italic text-slate-300"
        >
          {renderInline(line.slice(2))}
        </blockquote>
      );
      i++;
      continue;
    }

    // Horizontal Rule
    if (line.trim() === "---" || line.trim() === "***") {
      elements.push(<hr key={`hr-${i}`} className="my-6 border-soc-border" />);
      i++;
      continue;
    }

    // Unordered List (- or *)
    if (line.trim().startsWith("- ") || line.trim().startsWith("* ")) {
      const listItems = [];
      while (i < lines.length && (lines[i].trim().startsWith("- ") || lines[i].trim().startsWith("* "))) {
        listItems.push(lines[i].trim().slice(2));
        i++;
      }
      elements.push(
        <ul key={`ul-${i}`} className="my-2 list-disc space-y-1 pl-5 text-xs text-slate-300">
          {listItems.map((item, li) => (
            <li key={li}>{renderInline(item)}</li>
          ))}
        </ul>
      );
      continue;
    }

    // Numbered List
    if (/^\d+\.\s/.test(line.trim())) {
      const listItems = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i].trim())) {
        listItems.push(lines[i].trim().replace(/^\d+\.\s/, ""));
        i++;
      }
      elements.push(
        <ol key={`ol-${i}`} className="my-2 list-decimal space-y-1 pl-5 text-xs text-slate-300">
          {listItems.map((item, li) => (
            <li key={li}>{renderInline(item)}</li>
          ))}
        </ol>
      );
      continue;
    }

    // Blank line
    if (!line.trim()) {
      i++;
      continue;
    }

    // Paragraph
    elements.push(
      <p key={`p-${i}`} className="my-2 text-xs leading-relaxed text-slate-300">
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return <div className="markdown-body space-y-1">{elements}</div>;
}

/**
 * Format inline text: `code`, **bold**, *italic*, [link](url)
 */
function renderInline(text) {
  if (!text) return "";

  // Split on code tokens first `...`
  const codeParts = text.split(/(`[^`]+`)/g);

  return codeParts.map((part, idx) => {
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      return (
        <code key={idx} className="rounded bg-black/70 px-1.5 py-0.5 font-mono text-[11px] text-soc-neon border border-soc-border">
          {part.slice(1, -1)}
        </code>
      );
    }

    // Format links: [label](url)
    const linkRegex = /\[([^\]]+)\]\(([^)]+)\)/g;
    const segments = [];
    let lastIndex = 0;
    let match;

    while ((match = linkRegex.exec(part)) !== null) {
      if (match.index > lastIndex) {
        segments.push(formatStyles(part.slice(lastIndex, match.index), `${idx}-${lastIndex}`));
      }
      const label = match[1];
      const url = match[2];
      segments.push(
        <a
          key={`link-${idx}-${match.index}`}
          href={url}
          target={url.startsWith("http") ? "_blank" : undefined}
          rel={url.startsWith("http") ? "noopener noreferrer" : undefined}
          className="text-soc-neon hover:underline"
        >
          {label}
        </a>
      );
      lastIndex = match.index + match[0].length;
    }
    if (lastIndex < part.length) {
      segments.push(formatStyles(part.slice(lastIndex), `${idx}-${lastIndex}`));
    }

    return <span key={idx}>{segments}</span>;
  });
}

function formatStyles(str, baseKey) {
  // Bold **...**
  const boldParts = str.split(/(\*\*[^*]+\*\*)/g);
  return boldParts.map((bPart, bIdx) => {
    if (bPart.startsWith("**") && bPart.endsWith("**") && bPart.length >= 4) {
      return (
        <strong key={`${baseKey}-b-${bIdx}`} className="font-semibold text-white">
          {bPart.slice(2, -2)}
        </strong>
      );
    }
    // Italic *...*
    const italicParts = bPart.split(/(\*[^*]+\*)/g);
    return italicParts.map((iPart, iIdx) => {
      if (iPart.startsWith("*") && iPart.endsWith("*") && iPart.length >= 2) {
        return (
          <em key={`${baseKey}-i-${iIdx}`} className="italic text-slate-200">
            {iPart.slice(1, -1)}
          </em>
        );
      }
      return iPart;
    });
  });
}
