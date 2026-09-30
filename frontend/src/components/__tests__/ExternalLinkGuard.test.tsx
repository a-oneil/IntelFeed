import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockPatch = vi.fn();
vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: (...args: unknown[]) => mockPatch(...args) },
}));

import { ExternalLinkGuard } from "@/components/ExternalLinkGuard";
import { SafeHTML } from "@/components/SafeHTML";
import { useAuthStore } from "@/stores/authStore";
import { useExternalLinkStore } from "@/stores/externalLinkStore";
import type { User } from "@/api/types";

function user(settings: Record<string, unknown> = {}): User {
  return {
    id: "u1",
    username: "analyst",
    role: "analyst",
    is_active: true,
    settings,
    theme_id: null,
    custom_css: null,
    last_login: null,
    created_at: "2026-01-01T00:00:00Z",
  };
}

function renderPage(html: string, outside = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SafeHTML html={html} />
      <div dangerouslySetInnerHTML={{ __html: outside }} />
      <ExternalLinkGuard />
    </QueryClientProvider>,
  );
}

const EVIL = '<a href="https://evil.example/landing?x=1" target="_blank">the report</a>';

beforeEach(() => {
  mockPatch.mockReset();
  useAuthStore.setState({ accessToken: null, refreshToken: null, user: null });
  useExternalLinkStore.setState({ pending: null, sessionTrustedHosts: [] });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ExternalLinkGuard", () => {
  it("holds a click on an external link inside article content", () => {
    renderPage(EVIL);
    const link = screen.getByText("the report");

    // fireEvent returns false when the event was default-prevented.
    expect(fireEvent.click(link)).toBe(false);

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByTestId("external-link-host")).toHaveTextContent("evil.example");
    expect(screen.getByTestId("external-link-url")).toHaveTextContent(
      "https://evil.example/landing?x=1",
    );
  });

  it("does not stop same-origin links", () => {
    renderPage('<a href="/settings">settings</a>');
    expect(fireEvent.click(screen.getByText("settings"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("ignores external links outside article content by default", () => {
    renderPage("<p>body</p>", '<a href="https://evil.example/">chrome</a>');
    expect(fireEvent.click(screen.getByText("chrome"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("intercepts those too when scope is 'all'", () => {
    useAuthStore.setState({ user: user({ external_link_mode: "all" }) });
    renderPage("<p>body</p>", '<a href="https://evil.example/">chrome</a>');
    expect(fireEvent.click(screen.getByText("chrome"))).toBe(false);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("does nothing when switched off", () => {
    useAuthStore.setState({ user: user({ external_link_mode: "off" }) });
    renderPage(EVIL);
    expect(fireEvent.click(screen.getByText("the report"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("holds middle-click and modifier-click, not just plain clicks", () => {
    renderPage(EVIL);
    const link = screen.getByText("the report");

    expect(fireEvent(link, new MouseEvent("auxclick", { bubbles: true, cancelable: true, button: 1 }))).toBe(false);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    act(() => useExternalLinkStore.getState().release());
    expect(screen.queryByRole("dialog")).toBeNull();

    expect(fireEvent.click(link, { metaKey: true })).toBe(false);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("does not react to a right-button auxclick", () => {
    renderPage(EVIL);
    const evt = new MouseEvent("auxclick", { bubbles: true, cancelable: true, button: 2 });
    expect(fireEvent(screen.getByText("the report"), evt)).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("skips built-in trusted domains", () => {
    renderPage('<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1">CVE</a>');
    expect(fireEvent.click(screen.getByText("CVE"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("skips hosts of the user's feeds, read from the query cache", () => {
    const client = new QueryClient();
    client.setQueryData(["feeds"], {
      items: [{ url: "https://blog.vendor.example/feed.xml", site_url: "https://blog.vendor.example/" }],
      total: 1,
      limit: 1000,
      offset: 0,
      has_more: false,
    });
    render(
      <QueryClientProvider client={client}>
        <SafeHTML html='<a href="https://blog.vendor.example/post">post</a>' />
        <ExternalLinkGuard />
      </QueryClientProvider>,
    );
    expect(fireEvent.click(screen.getByText("post"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shouts when the link text names a different host", () => {
    renderPage('<a href="https://evil.example/x">https://microsoft.com/security/advisory</a>');
    fireEvent.click(screen.getByText(/microsoft\.com/));
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("microsoft.com");
    expect(alert).toHaveTextContent("evil.example");
  });

  it("shows a lookup-style link as a note, not the red alarm", () => {
    renderPage('<a href="https://decryptads.com/publisher/armytimes.com">armytimes.com</a>');
    fireEvent.click(screen.getByText("armytimes.com"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("dialog")).toHaveTextContent("may be a lookup page");
    // Not an alarm, so trusting the host is still on offer.
    expect(screen.getByRole("checkbox")).toBeInTheDocument();
  });

  it("closes on Cancel and on Escape without navigating", () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    renderPage(EVIL);

    fireEvent.click(screen.getByText("the report"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.click(screen.getByText("the report"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();

    expect(open).not.toHaveBeenCalled();
  });

  it("starts focus on Cancel so a stray Enter doesn't open the link", () => {
    renderPage(EVIL);
    fireEvent.click(screen.getByText("the report"));
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
  });

  it("opens a new tab with noopener for target=_blank links", () => {
    // SafeHTML's sanitiser drops `target`, so use one of the app's own
    // hand-written target="_blank" links, which need scope "all".
    useAuthStore.setState({ user: user({ external_link_mode: "all" }) });
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    renderPage("<p>body</p>", EVIL);
    fireEvent.click(screen.getByText("the report"));
    fireEvent.click(screen.getByRole("button", { name: "Open link" }));

    expect(open).toHaveBeenCalledWith(
      "https://evil.example/landing?x=1",
      "_blank",
      "noopener,noreferrer",
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("copies the link and a defanged form", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });

    renderPage(EVIL);
    fireEvent.click(screen.getByText("the report"));

    fireEvent.click(screen.getByRole("button", { name: "Copy link" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("https://evil.example/landing?x=1"));

    fireEvent.click(screen.getByRole("button", { name: "Copy defanged" }));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("hxxps://evil[.]example/landing?x=1"),
    );
  });

  it("remembers a host for the session when there is no account to save to", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    renderPage(EVIL);

    fireEvent.click(screen.getByText("the report"));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Open link" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    expect(mockPatch).not.toHaveBeenCalled();
    expect(fireEvent.click(screen.getByText("the report"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("saves 'don't ask again' to the account with a shallow settings patch", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    useAuthStore.setState({ user: user({ default_view: "unread" }) });
    mockPatch.mockResolvedValue({
      data: user({ default_view: "unread", external_link_trusted_hosts: ["evil.example"] }),
    });

    renderPage(EVIL);
    fireEvent.click(screen.getByText("the report"));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Open link" }));

    await waitFor(() =>
      expect(mockPatch).toHaveBeenCalledWith("/auth/me/settings", {
        settings: { external_link_trusted_hosts: ["evil.example"] },
      }),
    );
    await waitFor(() =>
      expect(useAuthStore.getState().user?.settings.external_link_trusted_hosts).toEqual([
        "evil.example",
      ]),
    );

    // Trusted now, so the next click goes straight through.
    expect(fireEvent.click(screen.getByText("the report"))).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("doesn't offer to trust a host when the link text is lying about it", () => {
    renderPage('<a href="https://evil.example/x">https://microsoft.com/advisory</a>');
    fireEvent.click(screen.getByText(/microsoft\.com/));
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("keeps keystrokes from reaching the page's global shortcuts while open", () => {
    // EntryList/EntryReader bind Enter, j/k, Escape... on window/document and only
    // skip text inputs — a focused dialog button must not also drive the page.
    const seen: string[] = [];
    const onKey = (e: KeyboardEvent) => seen.push(e.key);
    window.addEventListener("keydown", onKey);
    try {
      renderPage(EVIL);
      fireEvent.click(screen.getByText("the report"));

      fireEvent.keyDown(screen.getByRole("button", { name: "Cancel" }), { key: "Enter" });
      fireEvent.keyDown(document.body, { key: "j" });
      expect(seen).toEqual([]);

      // Tab is left alone: the focus trap depends on it.
      fireEvent.keyDown(screen.getByRole("button", { name: "Cancel" }), { key: "Tab" });
      expect(seen).toEqual(["Tab"]);

      // Escape closes the dialog and goes no further, so it can't also close the reader.
      fireEvent.keyDown(document.body, { key: "Escape" });
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(seen).toEqual(["Tab"]);
    } finally {
      window.removeEventListener("keydown", onKey);
    }
  });

  it("navigates before saving 'don't ask again', so the open keeps its user gesture", async () => {
    const order: string[] = [];
    vi.spyOn(window, "open").mockImplementation(() => {
      order.push("open");
      return null;
    });
    useAuthStore.setState({ user: user() });
    mockPatch.mockImplementation(async () => {
      order.push("save");
      return { data: user({ external_link_trusted_hosts: ["evil.example"] }) };
    });

    renderPage("<p>body</p>", EVIL);
    useAuthStore.setState({ user: user({ external_link_mode: "all" }) });
    fireEvent.click(screen.getByText("the report"));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Open link" }));

    await waitFor(() => expect(order).toEqual(["open", "save"]));
  });
});
