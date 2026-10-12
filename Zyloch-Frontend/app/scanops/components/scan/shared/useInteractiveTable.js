import { useEffect } from "react";

const RESIZE_HANDLE_CLASS = "zyloch-table-resize-handle";

function normalizeColumnId(value, index) {
    const raw = String(value || "").trim().toLowerCase();
    const compact = raw.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    return compact || `col-${index}`;
}

function getTableElement(containerRef) {
    const root = containerRef?.current;
    if (!root) return null;
    if (root.tagName === "TABLE") return root;
    return root.querySelector("table");
}

function getHeaderCells(tableEl) {
    return Array.from(tableEl?.tHead?.rows?.[0]?.cells || []);
}

function getRows(tableEl) {
    return Array.from(tableEl?.rows || []);
}

function ensureColumnIds(tableEl) {
    getHeaderCells(tableEl).forEach((th, index) => {
        if (!th.dataset.colId) {
            th.dataset.colId = normalizeColumnId(th.textContent, index);
        }
    });
}

function readStoredOrder(storageKey) {
    if (typeof window === "undefined") return null;
    try {
        const raw = window.localStorage.getItem(`${storageKey}:order`);
        const parsed = raw ? JSON.parse(raw) : null;
        return Array.isArray(parsed) ? parsed : null;
    } catch {
        return null;
    }
}

function readStoredWidths(storageKey) {
    if (typeof window === "undefined") return {};
    try {
        const raw = window.localStorage.getItem(`${storageKey}:widths`);
        const parsed = raw ? JSON.parse(raw) : {};
        return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
        return {};
    }
}

function saveStoredOrder(storageKey, order) {
    if (typeof window === "undefined") return;
    try {
        window.localStorage.setItem(`${storageKey}:order`, JSON.stringify(order));
    } catch {
        // ignore storage failures
    }
}

function saveStoredWidths(storageKey, widths) {
    if (typeof window === "undefined") return;
    try {
        window.localStorage.setItem(`${storageKey}:widths`, JSON.stringify(widths));
    } catch {
        // ignore storage failures
    }
}

function reorderColumn(tableEl, fromIndex, toIndex) {
    if (fromIndex === toIndex) return;

    const rows = getRows(tableEl);
    rows.forEach((row) => {
        const cells = Array.from(row.cells || []);
        if (fromIndex >= cells.length || toIndex >= cells.length) return;

        const movingCell = cells[fromIndex];
        const targetCell = cells[toIndex];
        if (!movingCell || !targetCell) return;

        if (fromIndex < toIndex) {
            targetCell.insertAdjacentElement("afterend", movingCell);
        } else {
            row.insertBefore(movingCell, targetCell);
        }
    });

    const colgroup = tableEl.querySelector("colgroup");
    if (colgroup) {
        const cols = Array.from(colgroup.children || []);
        if (fromIndex < cols.length && toIndex < cols.length) {
            const movingCol = cols[fromIndex];
            const targetCol = cols[toIndex];
            if (movingCol && targetCol) {
                if (fromIndex < toIndex) {
                    targetCol.insertAdjacentElement("afterend", movingCol);
                } else {
                    colgroup.insertBefore(movingCol, targetCol);
                }
            }
        }
    }
}

function applyOrder(tableEl, order) {
    if (!Array.isArray(order) || !order.length) return;

    const headerCells = getHeaderCells(tableEl);
    const idToIndex = new Map(headerCells.map((th, index) => [th.dataset.colId, index]));

    order.forEach((colId, targetIndex) => {
        const currentHeaderCells = getHeaderCells(tableEl);
        const currentIndex = currentHeaderCells.findIndex((th) => th.dataset.colId === colId);
        if (currentIndex === -1 || currentIndex === targetIndex) return;
        reorderColumn(tableEl, currentIndex, targetIndex);
    });
}

function setColumnWidth(tableEl, columnIndex, widthPx, minWidth) {
    const finalWidth = Math.max(minWidth, Math.round(widthPx));
    const colgroup = tableEl.querySelector("colgroup");
    if (colgroup && colgroup.children?.[columnIndex]) {
        colgroup.children[columnIndex].style.width = `${finalWidth}px`;
    }

    getRows(tableEl).forEach((row) => {
        const cell = row.cells?.[columnIndex];
        if (!cell) return;
        cell.style.width = `${finalWidth}px`;
        cell.style.minWidth = `${minWidth}px`;
    });
}

function applyWidths(tableEl, widthsById, minWidth) {
    const headerCells = getHeaderCells(tableEl);
    headerCells.forEach((th, index) => {
        const colId = th.dataset.colId;
        const width = Number(widthsById[colId]);
        if (Number.isFinite(width) && width > 0) {
            setColumnWidth(tableEl, index, width, minWidth);
        }
    });
}

export function useInteractiveTable({ containerRef, storageKey, minWidth = 96, enabled = true, deps = [] }) {
    useEffect(() => {
        if (!enabled || !storageKey) return;

        const tableEl = getTableElement(containerRef);
        if (!tableEl) return;

        ensureColumnIds(tableEl);

        const savedOrder = readStoredOrder(storageKey);
        if (savedOrder?.length) {
            applyOrder(tableEl, savedOrder);
        }

        const savedWidths = readStoredWidths(storageKey);
        applyWidths(tableEl, savedWidths, minWidth);

        const cleanupFns = [];
        let dragIndex = -1;

        const headerCells = getHeaderCells(tableEl);
        headerCells.forEach((th) => {
            th.style.position = th.style.position || "relative";
            th.style.userSelect = "none";
            th.style.cursor = "grab";
            th.draggable = true;

            const existingGuide = th.querySelector(".zyloch-table-resize-guide");
            if (existingGuide) existingGuide.remove();

            const guide = document.createElement("span");
            guide.className = "zyloch-table-resize-guide";
            guide.setAttribute("aria-hidden", "true");
            guide.style.position = "absolute";
            guide.style.top = "0";
            guide.style.right = "0";
            guide.style.width = "1px";
            guide.style.height = "100%";
            guide.style.background = "rgba(148, 163, 184, 0.42)";
            guide.style.pointerEvents = "none";
            guide.style.zIndex = "6";
            th.appendChild(guide);

            const onDragStart = (event) => {
                if (event.target?.classList?.contains(RESIZE_HANDLE_CLASS)) {
                    event.preventDefault();
                    return;
                }
                const cells = getHeaderCells(tableEl);
                dragIndex = cells.indexOf(th);
                if (dragIndex < 0) return;
                if (event.dataTransfer) {
                    event.dataTransfer.effectAllowed = "move";
                    event.dataTransfer.setData("text/plain", th.dataset.colId || "");
                }
                th.style.opacity = "0.65";
                th.style.cursor = "grabbing";
            };

            const onDragEnd = () => {
                th.style.opacity = "1";
                th.style.cursor = "grab";
            };

            const onDragOver = (event) => {
                event.preventDefault();
                if (event.dataTransfer) {
                    event.dataTransfer.dropEffect = "move";
                }
            };

            const onDrop = (event) => {
                event.preventDefault();
                const cells = getHeaderCells(tableEl);
                const dropIndex = cells.indexOf(th);
                if (dragIndex < 0 || dropIndex < 0 || dragIndex === dropIndex) return;

                reorderColumn(tableEl, dragIndex, dropIndex);
                const nextOrder = getHeaderCells(tableEl).map((cell) => cell.dataset.colId);
                saveStoredOrder(storageKey, nextOrder);
                dragIndex = -1;
            };

            th.addEventListener("dragstart", onDragStart);
            th.addEventListener("dragend", onDragEnd);
            th.addEventListener("dragover", onDragOver);
            th.addEventListener("drop", onDrop);

            cleanupFns.push(() => {
                th.removeEventListener("dragstart", onDragStart);
                th.removeEventListener("dragend", onDragEnd);
                th.removeEventListener("dragover", onDragOver);
                th.removeEventListener("drop", onDrop);
            });

            const existingHandle = th.querySelector(`.${RESIZE_HANDLE_CLASS}`);
            if (existingHandle) existingHandle.remove();

            const handle = document.createElement("span");
            handle.className = RESIZE_HANDLE_CLASS;
            handle.setAttribute("aria-hidden", "true");
            handle.style.position = "absolute";
            handle.style.top = "0";
            handle.style.right = "0";
            handle.style.height = "100%";
            handle.style.width = "14px";
            handle.style.cursor = "col-resize";
            handle.style.touchAction = "none";
            handle.style.userSelect = "none";
            handle.style.zIndex = "8";
            handle.style.display = "flex";
            handle.style.alignItems = "center";
            handle.style.justifyContent = "center";
            handle.style.opacity = "1";
            handle.style.background = "transparent";
            handle.style.transition = "opacity 120ms ease";
            handle.title = "Drag to resize";

            const onHandleEnter = () => {
                handle.style.opacity = "1";
                guide.style.background = "rgba(100, 116, 139, 0.75)";
                guide.style.boxShadow = "none";
            };

            const onHandleLeave = () => {
                handle.style.opacity = "1";
                guide.style.background = "rgba(148, 163, 184, 0.42)";
                guide.style.boxShadow = "none";
            };

            const onMouseDown = (event) => {
                event.preventDefault();
                event.stopPropagation();

                const cells = getHeaderCells(tableEl);
                const columnIndex = cells.indexOf(th);
                if (columnIndex < 0) return;

                const startX = event.clientX;
                const startWidth = th.getBoundingClientRect().width;

                const onMouseMove = (moveEvent) => {
                    const delta = moveEvent.clientX - startX;
                    const nextWidth = startWidth + delta;
                    setColumnWidth(tableEl, columnIndex, nextWidth, minWidth);
                };

                const onMouseUp = () => {
                    document.removeEventListener("mousemove", onMouseMove);
                    document.removeEventListener("mouseup", onMouseUp);

                    const headerAfter = getHeaderCells(tableEl)[columnIndex];
                    const colId = headerAfter?.dataset?.colId;
                    if (!colId) return;

                    const widthNow = headerAfter.getBoundingClientRect().width;
                    const existing = readStoredWidths(storageKey);
                    existing[colId] = Math.round(widthNow);
                    saveStoredWidths(storageKey, existing);
                };

                document.addEventListener("mousemove", onMouseMove);
                document.addEventListener("mouseup", onMouseUp);
            };

            handle.addEventListener("mousedown", onMouseDown);
            handle.addEventListener("mouseenter", onHandleEnter);
            handle.addEventListener("mouseleave", onHandleLeave);
            th.appendChild(handle);

            cleanupFns.push(() => {
                handle.removeEventListener("mousedown", onMouseDown);
                handle.removeEventListener("mouseenter", onHandleEnter);
                handle.removeEventListener("mouseleave", onHandleLeave);
                if (handle.parentElement === th) {
                    th.removeChild(handle);
                }
                if (guide.parentElement === th) {
                    th.removeChild(guide);
                }
            });
        });

        return () => {
            cleanupFns.forEach((fn) => fn());
        };
    }, [containerRef, storageKey, minWidth, enabled, ...deps]);
}
