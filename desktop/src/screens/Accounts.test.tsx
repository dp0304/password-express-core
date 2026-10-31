// SPDX-License-Identifier: Apache-2.0
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type ItemDetail } from "../api";
import { AppCtx, makeT, type Ctx } from "../ui";
import { Accounts } from "./Accounts";

// get_item serializes Rust's #[serde(flatten)] ItemSummary at the top level.
// Deliberately no nested `summary`: this matches the real Tauri response.
const detail: ItemDetail = {
  entry_id: "ent_01jbz3k6w8a7m2q4t5v9x0y1z2",
  kind: "api_key",
  title: "Demo API key",
  username: "demo@example.com",
  primary_url: "https://api.example.com",
  project_id: "proj_01jbz3k6w8a7m2q4t5v9x0y1z2",
  lifecycle: "imported",
  has_conflict: false,
  pending_sync: false,
  tags: ["demo", "staging"],
  updated_at: "2026-10-31T12:00:00Z",
  urls: ["https://api.example.com"],
  notes: "Fictional README account",
  has_secret: true,
  secret_masked: "••••••••",
  has_totp: false,
  fields: [],
  version: 1,
  conflict_versions: [],
  created_at: "2026-10-30T12:00:00Z",
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("account details", () => {
  it("renders the flat Rust response and preserves its fields when editing", async () => {
    vi.spyOn(api, "listItems").mockResolvedValue([detail]);
    vi.spyOn(api, "projects").mockResolvedValue({ projects: [{ project_id: detail.project_id!, name: "Demo project" }] });
    vi.spyOn(api, "getItem").mockResolvedValue(detail);
    const save = vi.spyOn(api, "saveItem").mockResolvedValue(detail.entry_id);
    const reveal = vi.spyOn(api, "revealSecret");
    const ctx: Ctx = {
      lang: "en", t: makeT("en"), status: null,
      refresh: async () => undefined, toast: vi.fn(), errText: () => "Error",
      go: vi.fn(), setLang: vi.fn(),
    };
    render(<AppCtx.Provider value={ctx}><Accounts /></AppCtx.Provider>);

    fireEvent.click(await screen.findByRole("option", { name: /Demo API key/ }));
    expect((await screen.findByRole("heading", { name: detail.title })).textContent).toBe(detail.title);
    expect(screen.getByText(detail.secret_masked!).textContent).toBe("••••••••");
    expect(reveal).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const editor = within(screen.getByRole("dialog", { name: "Edit" }));
    expect((editor.getByLabelText("Title") as HTMLInputElement).value).toBe(detail.title);
    expect((editor.getByLabelText("Username") as HTMLInputElement).value).toBe(detail.username);
    expect((editor.getByLabelText("Type") as HTMLSelectElement).value).toBe(detail.kind);
    expect((editor.getByLabelText("Project") as HTMLSelectElement).value).toBe(detail.project_id);
    expect((editor.getByLabelText("Tags (comma-separated)") as HTMLInputElement).value).toBe("demo, staging");
    fireEvent.click(editor.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      entry_id: detail.entry_id, kind: detail.kind, title: detail.title,
      username: detail.username, project_id: detail.project_id, tags: detail.tags,
      secret: undefined,
    })));
  });
});
