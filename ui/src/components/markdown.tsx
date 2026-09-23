import type { ReactNode } from "react";

// A deliberately small markdown renderer for scan reports. No dependency, no
// HTML passthrough: every node below is constructed from plain text, so a
// report can never inject markup into this page.

function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  const pattern = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = pattern.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    const key = `${keyBase}-${i++}`;
    if (tok.startsWith("`")) {
      out.push(<code key={key}>{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith("**")) {
      out.push(<strong key={key}>{tok.slice(2, -2)}</strong>);
    } else {
      const label = tok.slice(1, tok.indexOf("]"));
      const href = tok.slice(tok.indexOf("(") + 1, -1);
      out.push(
        <a key={key} href={href} target="_blank" rel="noreferrer">
          {label}
        </a>,
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let list: string[] = [];
  let code: string[] | null = null;
  let para: string[] = [];

  const flushList = () => {
    if (!list.length) return;
    const items = list;
    list = [];
    blocks.push(
      <ul key={`ul-${blocks.length}`}>
        {items.map((it, i) => (
          <li key={i}>{inline(it, `li-${blocks.length}-${i}`)}</li>
        ))}
      </ul>,
    );
  };
  const flushPara = () => {
    if (!para.length) return;
    const body = para.join(" ");
    para = [];
    blocks.push(<p key={`p-${blocks.length}`}>{inline(body, `p-${blocks.length}`)}</p>);
  };

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    if (code !== null) {
      if (line.trim().startsWith("```")) {
        blocks.push(
          <pre key={`pre-${blocks.length}`}>
            <code>{code.join("\n")}</code>
          </pre>,
        );
        code = null;
      } else {
        code.push(raw);
      }
      continue;
    }
    if (line.trim().startsWith("```")) {
      flushPara();
      flushList();
      code = [];
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      flushPara();
      flushList();
      const level = heading[1].length;
      const body = inline(heading[2], `h-${blocks.length}`);
      blocks.push(
        level <= 2 ? (
          <h2 key={`h-${blocks.length}`}>{body}</h2>
        ) : (
          <h3 key={`h-${blocks.length}`}>{body}</h3>
        ),
      );
      continue;
    }
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      flushPara();
      list.push(bullet[1]);
      continue;
    }
    if (!line.trim()) {
      flushPara();
      flushList();
      continue;
    }
    para.push(line.trim());
  }
  flushPara();
  flushList();
  if (code) {
    blocks.push(
      <pre key={`pre-${blocks.length}`}>
        <code>{code.join("\n")}</code>
      </pre>,
    );
  }

  return <div className="prose text-[0.92rem]">{blocks}</div>;
}
