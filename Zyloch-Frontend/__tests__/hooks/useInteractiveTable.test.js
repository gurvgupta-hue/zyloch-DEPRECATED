import React, { useRef } from "react";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { useInteractiveTable } from "@/app/scanops/components/scan/shared/useInteractiveTable";

function HookTable({ storageKey = "table-test", minWidth = 96, enabled = true, deps = [] }) {
  const containerRef = useRef(null);

  useInteractiveTable({
    containerRef,
    storageKey,
    minWidth,
    enabled,
    deps,
  });

  return (
    <div ref={containerRef}>
      <table data-testid="interactive-table">
        <colgroup>
          <col style={{ width: "120px" }} />
          <col style={{ width: "140px" }} />
          <col style={{ width: "160px" }} />
        </colgroup>
        <thead>
          <tr>
            <th>Package Name</th>
            <th>License</th>
            <th>Version</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>react</td>
            <td>MIT</td>
            <td>19.0.0</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

describe("useInteractiveTable", () => {
  let originalGetBoundingClientRect;

  beforeEach(() => {
    localStorage.clear();
    originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function getBoundingClientRectMock() {
      const parsedWidth = Number.parseFloat(this.style?.width || "");
      const width = Number.isFinite(parsedWidth) ? parsedWidth : 120;
      return {
        width,
        height: 32,
        top: 0,
        left: 0,
        right: width,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      };
    };
  });

  afterEach(() => {
    Element.prototype.getBoundingClientRect = originalGetBoundingClientRect;
    cleanup();
  });

  test("applies persisted column order from localStorage", () => {
    localStorage.setItem(
      "scanops-order:order",
      JSON.stringify(["license", "version", "package-name"])
    );

    render(<HookTable storageKey="scanops-order" />);

    const headers = screen
      .getAllByRole("columnheader")
      .map((node) => node.textContent?.trim());

    expect(headers).toEqual(["License", "Version", "Package Name"]);
  });

  test("applies persisted column widths from localStorage", () => {
    localStorage.setItem(
      "scanops-widths:widths",
      JSON.stringify({ "package-name": 280, license: 210 })
    );

    render(<HookTable storageKey="scanops-widths" />);

    const headers = screen.getAllByRole("columnheader");

    expect(headers[0].style.width).toBe("280px");
    expect(headers[1].style.width).toBe("210px");
  });

  test("renders resize handle and keeps the single guide line", () => {
    render(<HookTable storageKey="scanops-guides" />);

    const headers = screen.getAllByRole("columnheader");

    headers.forEach((header) => {
      const handles = header.querySelectorAll(".zyloch-table-resize-handle");
      const guides = header.querySelectorAll(".zyloch-table-resize-guide");
      expect(handles).toHaveLength(1);
      expect(guides).toHaveLength(1);
    });
  });

  test("stores updated width after resizing", () => {
    render(<HookTable storageKey="scanops-resize" minWidth={96} />);

    const firstHeader = screen.getAllByRole("columnheader")[0];
    const handle = firstHeader.querySelector(".zyloch-table-resize-handle");

    expect(handle).toBeTruthy();

    fireEvent.mouseDown(handle, { clientX: 100 });
    fireEvent.mouseMove(document, { clientX: 220 });
    fireEvent.mouseUp(document);

    const stored = JSON.parse(localStorage.getItem("scanops-resize:widths") || "{}");
    expect(stored["package-name"]).toBeGreaterThanOrEqual(96);
  });
});
