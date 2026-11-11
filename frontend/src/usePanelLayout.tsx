import { useEffect, useRef, useState, type CSSProperties } from "react";

type Side = "left" | "right";
interface Layout { leftWidth: number; rightWidth: number; leftOpen: boolean; rightOpen: boolean }
const defaults = (): Layout => ({ leftWidth: 229, rightWidth: 443, leftOpen: innerWidth >= 900, rightOpen: innerWidth >= 1200 });
const minimum = { left: 180, right: 280 };
const maximum = { left: 640, right: 900 };
const keyFor = (id: string) => `codesentry.layout.v1.${id}`;

function read(id: string): Layout {
  try {
    const value = JSON.parse(localStorage.getItem(keyFor(id)) || "null");
    if (value && [value.leftWidth, value.rightWidth].every(Number.isFinite) &&
        typeof value.leftOpen === "boolean" && typeof value.rightOpen === "boolean")
      return { leftWidth: Math.max(180, Math.min(640, value.leftWidth)), rightWidth: Math.max(280, Math.min(900, value.rightWidth)), leftOpen: value.leftOpen, rightOpen: value.rightOpen };
  } catch { /* Private browsing still permits resizing. */ }
  return defaults();
}

export function usePanelLayout(workspaceId?: string | null, railWidth = 48) {
  const id = workspaceId || "welcome";
  const [stored, setStored] = useState(() => ({ id, layout: read(id) }));
  const [width, setWidth] = useState(innerWidth);
  const container = useRef<HTMLDivElement>(null);
  const previous = useRef<Pick<Layout, "leftOpen" | "rightOpen"> | null>(null);
  const layout = stored.id === id ? stored.layout : read(id);
  useEffect(() => { setStored({ id, layout: read(id) }); previous.current = null; }, [id]);
  useEffect(() => {
    if (stored.id !== id) return;
    try { localStorage.setItem(keyFor(id), JSON.stringify(stored.layout)); } catch { /* Optional persistence. */ }
  }, [id, stored]);
  useEffect(() => {
    const measure = () => setWidth(container.current?.clientWidth || innerWidth);
    const observer = typeof ResizeObserver !== "undefined" ? new ResizeObserver(measure) : null;
    if (container.current) observer?.observe(container.current);
    window.addEventListener("resize", measure); measure();
    return () => { observer?.disconnect(); window.removeEventListener("resize", measure); };
  }, []);
  function change(update: (value: Layout) => Layout) {
    setStored(value => ({ id, layout: update(value.id === id ? value.layout : read(id)) }));
  }
  function open(side: Side, value: boolean | ((open: boolean) => boolean)) {
    previous.current = null;
    change(current => ({ ...current, [`${side}Open`]: typeof value === "function" ? value(current[`${side}Open`]) : value }));
  }
  const gutter = 8;
  // Keep preferred widths intact when a smaller window temporarily fits them.
  const available = Math.max(0, width - railWidth - Math.min(400, width * .55) - gutter * (Number(layout.leftOpen) + Number(layout.rightOpen)));
  const used = (layout.leftOpen ? layout.leftWidth : 0) + (layout.rightOpen ? layout.rightWidth : 0);
  const ratio = used > available ? available / Math.max(1, used) : 1;
  const effective = { left: Math.round(layout.leftWidth * ratio), right: Math.round(layout.rightWidth * ratio) };
  function range(side: Side) {
    const other = side === "left" ? "right" : "left";
    return { min: Math.min(minimum[side], available), max: Math.max(Math.min(minimum[side], available), Math.min(maximum[side], width - railWidth - 400 - gutter - (layout[`${other}Open`] ? effective[other] + gutter : 0))) };
  }
  function resize(side: Side, value: number) {
    const limits = range(side);
    change(current => ({ ...current, [`${side}Width`]: Math.round(Math.max(limits.min, Math.min(limits.max, value))) }));
  }
  function focus() {
    if (!layout.leftOpen && !layout.rightOpen) {
      const visibility = previous.current || { leftOpen: true, rightOpen: true };
      change(current => ({ ...current, ...visibility }));
      previous.current = null;
    } else {
      previous.current = { leftOpen: layout.leftOpen, rightOpen: layout.rightOpen };
      change(current => ({ ...current, leftOpen: false, rightOpen: false }));
    }
  }
  const style = { "--left-width": `${effective.left}px`, "--right-width": `${effective.right}px` } as CSSProperties;
  return { container, style, showLeft: layout.leftOpen, showRight: layout.rightOpen,
    setShowLeft: (value: boolean | ((open: boolean) => boolean)) => open("left", value),
    setShowRight: (value: boolean | ((open: boolean) => boolean)) => open("right", value),
    focus, reset: () => { previous.current = null; change(() => ({ ...defaults(), leftOpen: true, rightOpen: true })); },
    separator: (side: Side) => <PanelSeparator key={side} side={side} value={effective[side]} range={range(side)} onResize={value => resize(side, value)} /> };
}

function PanelSeparator({ side, value, range, onResize }: { side: Side; value: number; range: { min: number; max: number }; onResize: (width: number) => void }) {
  const drag = useRef<{ x: number; width: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    if (dragging) document.body.classList.add("panels-resizing");
    return () => document.body.classList.remove("panels-resizing");
  }, [dragging]);
  const stop = () => { drag.current = null; setDragging(false); };
  return <div className={`panel-separator ${side} ${dragging ? "dragging" : ""}`} role="separator" tabIndex={0}
    aria-label={`调整${side === "left" ? "左" : "右"}侧栏宽度`} aria-orientation="vertical"
    aria-valuenow={value} aria-valuemin={Math.round(range.min)} aria-valuemax={Math.round(range.max)}
    title="拖动调整宽度；双击恢复默认宽度；方向键微调"
    onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId); drag.current = { x: event.clientX, width: value }; setDragging(true); }}
    onPointerMove={event => { if (drag.current) onResize(drag.current.width + (side === "left" ? 1 : -1) * (event.clientX - drag.current.x)); }}
    onPointerUp={stop} onPointerCancel={stop} onLostPointerCapture={stop}
    onDoubleClick={() => onResize(side === "left" ? 229 : 443)}
    onKeyDown={event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      onResize(event.key === "Home" ? range.min : event.key === "End" ? range.max : value + (side === "left" ? 1 : -1) * (event.key === "ArrowRight" ? 1 : -1) * (event.shiftKey ? 40 : 10));
    }} />;
}
