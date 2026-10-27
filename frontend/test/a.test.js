"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const scriptPath = path.join(__dirname, "..", "m-8c1f3e", "a.js");
const script = fs.readFileSync(scriptPath, "utf8");

const flushPromises = () => new Promise((resolve) => setImmediate(resolve));

function createElement() {
  const listeners = {};
  return {
    disabled: false,
    value: "",
    textContent: "",
    listeners,
    addEventListener(type, listener) {
      listeners[type] = listener;
    },
    focus() {
      this.focused = true;
    },
  };
}

function load(options = {}) {
  const form = createElement();
  const field = createElement();
  const button = createElement();
  const message = createElement();
  const elements = { f: form, k: field, b: button, m: message };
  const replacements = [];
  const storageWrites = [];
  let storageError = options.storageError;
  const requests = [];

  const context = {
    document: {
      getElementById(id) {
        return elements[id];
      },
    },
    window: {
      APP_API: options.api || "https://relaybrowse.onrender.com",
    },
    location: {
      hash: options.hash || "",
      search: options.search || "",
      pathname: "/m-8c1f3e/index.html",
      replace(value) {
        replacements.push(value);
      },
    },
    history: {
      replaceState(state, title, url) {
        this.replaced = url;
      },
    },
    URLSearchParams,
    localStorage: {
      setItem(key, value) {
        if (storageError) throw storageError;
        storageWrites.push([key, value]);
      },
    },
    fetch(url, init) {
      requests.push({ url, init });
      return options.fetch
        ? options.fetch(url, init)
        : Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ frameToken: "frame-token" }),
          });
    },
    Error,
    JSON,
    Promise,
  };

  vm.runInNewContext(script, context, { filename: scriptPath });
  return {
    form,
    field,
    button,
    message,
    replacements,
    storageWrites,
    requests,
    context,
  };
}

test("submitting a passcode posts JSON, stores the frame token, and returns with go", async () => {
  const page = load({
    api: "https://relaybrowse.onrender.com",
    search: "?go=https%3A%2F%2Fpear.test%2Fstart",
  });
  page.field.value = "  secret passcode  ";

  page.form.listeners.submit({ preventDefault() {} });
  await flushPromises();

  assert.deepEqual(
    page.requests.map(({ url }) => url),
    ["https://relaybrowse.onrender.com/api/auth"],
  );
  assert.equal(page.requests[0].init.method, "POST");
  assert.equal(page.requests[0].init.referrerPolicy, "no-referrer");
  assert.deepEqual(JSON.parse(page.requests[0].init.body), {
    token: "secret passcode",
  });
  assert.deepEqual(page.storageWrites, [["app.t", "frame-token"]]);
  assert.deepEqual(page.replacements, [
    "../index.html?go=https%3A%2F%2Fpear.test%2Fstart",
  ]);
});

test("empty submissions are ignored", () => {
  const page = load();
  page.field.value = "   ";

  page.form.listeners.submit({ preventDefault() {} });

  assert.equal(page.requests.length, 0);
  assert.equal(page.button.disabled, false);
});

test("authentication failures re-enable the form and display the server message", async () => {
  const page = load({
    fetch() {
      return Promise.resolve({
        ok: false,
        json: () => Promise.resolve({ error: "Invalid passcode" }),
      });
    },
  });
  page.field.value = "wrong";

  page.form.listeners.submit({ preventDefault() {} });
  await flushPromises();

  assert.equal(page.button.disabled, false);
  assert.equal(page.message.textContent, "Invalid passcode");
  assert.equal(page.field.focused, true);
});

test("blocked storage re-enables the form and explains that the token cannot be kept", async () => {
  const page = load({ storageError: new Error("blocked") });
  page.field.value = "secret";

  page.form.listeners.submit({ preventDefault() {} });
  await flushPromises();

  assert.equal(page.button.disabled, false);
  assert.match(page.message.textContent, /Storage is blocked/);
});

test("network failures receive a connection-specific status message", async () => {
  const page = load({
    fetch() {
      return Promise.reject(new Error("Failed to fetch"));
    },
  });
  page.field.value = "secret";

  page.form.listeners.submit({ preventDefault() {} });
  await flushPromises();

  assert.equal(page.button.disabled, false);
  assert.equal(
    page.message.textContent,
    "Couldn’t connect. Try again in a moment.",
  );
});

test("a passcode hash is scrubbed and submitted after URL decoding", async () => {
  const page = load({ hash: "#key=hello%20world" });
  await flushPromises();

  assert.equal(page.context.history.replaced, "/m-8c1f3e/index.html");
  assert.deepEqual(JSON.parse(page.requests[0].init.body), {
    token: "hello world",
  });
  assert.deepEqual(page.storageWrites, [["app.t", "frame-token"]]);
});

test("malformed URL encoding in the hash falls back to the raw passcode", async () => {
  const page = load({ hash: "#key=%E0%A4%A" });
  await flushPromises();

  assert.deepEqual(JSON.parse(page.requests[0].init.body), {
    token: "%E0%A4%A",
  });
});
