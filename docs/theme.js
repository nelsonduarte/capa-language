// theme.js -- tiny theme toggle.
//
// Applies the user's stored choice (or OS preference) as a
// data-theme="light"|"dark" attribute on <html>. The CSS uses
// that attribute for explicit overrides and keeps a
// prefers-color-scheme @media rule as the fallback for the
// no-JS / no-choice case.
//
// One IIFE, no globals, no dependencies. Loaded synchronously
// in <head> so the first paint already shows the right theme
// (avoids the FOUC where dark loads then flicks to light).

(function () {
    var KEY = "capa-theme";

    function apply(theme) {
        if (theme === "light" || theme === "dark") {
            document.documentElement.setAttribute("data-theme", theme);
        }
    }

    function current() {
        return document.documentElement.getAttribute("data-theme")
            || (window.matchMedia &&
                window.matchMedia("(prefers-color-scheme: light)").matches
                ? "light"
                : "dark");
    }

    // Apply stored choice ASAP (this runs in <head>, before <body>).
    try {
        var stored = localStorage.getItem(KEY);
        if (stored) apply(stored);
    } catch (_) { /* localStorage disabled; just follow @media */ }

    // Wire the toggle button once the DOM exists.
    document.addEventListener("DOMContentLoaded", function () {
        var btn = document.getElementById("theme-toggle");
        if (!btn) return;
        function refreshLabel() {
            var t = current();
            btn.setAttribute("aria-label",
                t === "light"
                    ? "Switch to dark theme"
                    : "Switch to light theme");
            btn.setAttribute("data-active", t);
        }
        refreshLabel();
        btn.addEventListener("click", function () {
            var next = current() === "light" ? "dark" : "light";
            apply(next);
            try { localStorage.setItem(KEY, next); } catch (_) { }
            refreshLabel();
        });
    });
})();
