import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import AdmZip from "adm-zip";
import { generateToken } from "../../auth";
import { createUser, deleteUser, getUserById, setUserPluginAccessScope } from "../../users";
import { handlePluginRoutes } from "./plugin-routes";

const PASSWORD = "Aa1!ServerPluginPermissionTest123";
let operatorId = 0;
let operatorToken = "";

beforeAll(async () => {
  const created = await createUser(
    `plugin_operator_${Date.now().toString(36)}`,
    PASSWORD,
    "operator",
    "test",
  );
  if (!created.success || !created.userId) throw new Error(created.error || "failed to create operator");
  operatorId = created.userId;
  if (!setUserPluginAccessScope(operatorId, "all").success) throw new Error("failed to grant plugin scope");
  operatorToken = await generateToken(getUserById(operatorId)!);
});

afterAll(() => {
  if (operatorId) deleteUser(operatorId);
});

function deps(overrides: Record<string, unknown> = {}) {
  return {
    pluginState: {
      enabled: {},
      lastError: {},
      autoLoad: {},
      autoStartEvents: {},
      approvedNeeds: {},
    },
    sanitizePluginId: (id: string) => id,
    pluginRuntime: {
      hasServerCode: () => false,
    },
    ...overrides,
  } as any;
}

describe("server plugin code authorization", () => {
  test("operators cannot upload a bundle containing server.js", async () => {
    const zip = new AdmZip();
    zip.addFile("config.json", Buffer.from('{"id":"host-code"}'));
    zip.addFile("nested/server.js", Buffer.from("Bun.spawn(['sh', '-c', 'id'])"));
    const form = new FormData();
    const zipBytes = Uint8Array.from(zip.toBuffer().values());
    form.set("file", new File([zipBytes], "host-code.zip", { type: "application/zip" }));
    const url = new URL("https://localhost/api/plugins/upload");

    const response = await handlePluginRoutes(new Request(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${operatorToken}` },
      body: form,
    }), url, deps());

    expect(response?.status).toBe(403);
    expect(await response?.text()).toContain("plugins:configure");
  });

  test("operators cannot enable an installed server-side plugin", async () => {
    let started = false;
    const url = new URL("https://localhost/api/plugins/host-code/enable");
    const response = await handlePluginRoutes(new Request(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ enabled: true, confirmed: true }),
    }), url, deps({
      pluginRuntime: {
        hasServerCode: () => true,
        startPlugin: async () => { started = true; },
      },
    }));

    expect(response?.status).toBe(403);
    expect(await response?.text()).toContain("plugins:configure");
    expect(started).toBe(false);
  });

  test("plugin proxy cannot reach server-local or metadata addresses", async () => {
    for (const target of ["http://127.0.0.1:3000/admin", "http://169.254.169.254/latest/meta-data/"]) {
      const url = new URL(`https://localhost/api/plugins/client-plugin/proxy?url=${encodeURIComponent(target)}`);
      const response = await handlePluginRoutes(new Request(url, {
        headers: { Authorization: `Bearer ${operatorToken}` },
      }), url, deps());

      expect(response?.status).toBe(502);
      expect((await response?.json() as any).error).toContain("private/internal");
    }
  });
});
