(function () {
  "use strict";

  function byId(id) {
    return document.getElementById(id);
  }

  var signInForm = byId("f");
  var passcodeInput = byId("k");
  var submitButton = byId("b");
  var statusMessage = byId("m");
  var apiBase = String(window.APP_API || "").replace(/\/+$/, "");
  var tokenStorageKey = "app.t"; // read by ../app.js

  function showStatus(message) {
    statusMessage.textContent = message || "";
  }

  function storeFrameToken(token) {
    try {
      localStorage.setItem(tokenStorageKey, token);
      return true;
    } catch (error) {
      return false;
    }
  }

  function signIn(passcode) {
    return fetch(apiBase + "/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: passcode }),
      referrerPolicy: "no-referrer",
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!response.ok || !data.frameToken) {
            throw new Error(data.error || "Sign-in failed.");
          }

          if (!storeFrameToken(data.frameToken)) {
            throw new Error(
              "Storage is blocked here, so the sign-in can’t be kept.",
            );
          }
        });
    });
  }

  // Back to the main page, carrying over an optional ?go= from the link used to get here.
  function returnToMainPage() {
    var destination = new URLSearchParams(location.search).get("go");
    var query = destination ? "?go=" + encodeURIComponent(destination) : "";
    location.replace("../index.html" + query);
  }

  function attemptSignIn(passcode) {
    submitButton.disabled = true;
    showStatus("Please wait…");

    return signIn(passcode)
      .then(returnToMainPage)
      .catch(function (error) {
        submitButton.disabled = false;
        showStatus(
          error && error.message === "Failed to fetch"
            ? "Couldn’t connect. Try again in a moment."
            : (error && error.message) || "Sign-in failed.",
        );
        passcodeInput.focus();
      });
  }

  signInForm.addEventListener("submit", function (event) {
    event.preventDefault();
    var passcode = passcodeInput.value.trim();
    if (passcode) {
      attemptSignIn(passcode);
    }
  });

  // A link ending in #key=... signs in once and scrubs the key from the address bar first.
  var keyInHash = /[#&]key=([^&]+)/.exec(location.hash);
  if (keyInHash) {
    history.replaceState(null, "", location.pathname + location.search);
    var passcodeFromLink = "";

    try {
      passcodeFromLink = decodeURIComponent(keyInHash[1]);
    } catch (error) {
      passcodeFromLink = keyInHash[1];
    }

    attemptSignIn(passcodeFromLink);
  } else {
    passcodeInput.focus();
  }
})();
