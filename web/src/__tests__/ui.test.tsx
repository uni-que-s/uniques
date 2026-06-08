import { describe, test, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  AssetStatusBadge,
  SeverityBadge,
  StatusBadge,
  StatCard,
  ASSET_STATUS_META,
} from "../components/ui";
import { ASSET_STATUSES } from "../lib/api";

describe("status metadata", () => {
  test("ASSET_STATUS_META has a label + color for every status", () => {
    for (const s of ASSET_STATUSES) {
      expect(ASSET_STATUS_META[s]).toBeTruthy();
      expect(ASSET_STATUS_META[s].label.length).toBeGreaterThan(0);
      expect(ASSET_STATUS_META[s].color).toMatch(/^#/);
    }
  });
});

describe("badges render human-readable text", () => {
  test("AssetStatusBadge maps snake_case status to a friendly label", () => {
    render(<AssetStatusBadge status="in_progress" />);
    expect(screen.getByText("In Progress")).toBeInTheDocument();
  });

  test("AssetStatusBadge renders the migrated label", () => {
    render(<AssetStatusBadge status="migrated" />);
    expect(screen.getByText("Migrated")).toBeInTheDocument();
  });

  test("SeverityBadge shows the severity level", () => {
    render(<SeverityBadge level="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  test("StatusBadge maps compliance status to a label", () => {
    render(<StatusBadge status="gap" />);
    expect(screen.getByText("Partial")).toBeInTheDocument();
  });
});

describe("StatCard", () => {
  test("renders label, value, and sub-text", () => {
    render(<StatCard label="Crypto Assets" value={42} sub="seeded" />);
    expect(screen.getByText("Crypto Assets")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("seeded")).toBeInTheDocument();
  });
});
