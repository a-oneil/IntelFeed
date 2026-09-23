// Apply the cached theme before React loads to prevent a flash of the baked-in
// default palette (and the PWA title bar color) on hard refresh.
try {
  var root = document.documentElement;
  var vars = localStorage.getItem("intelfeed-theme-vars");
  if (vars) {
    var parsed = JSON.parse(vars);
    for (var key in parsed) {
      if (Object.prototype.hasOwnProperty.call(parsed, key)) {
        root.style.setProperty("--" + key, parsed[key]);
      }
    }
  }
  var bg = localStorage.getItem("intelfeed-theme-bg");
  if (bg) {
    document.querySelector('meta[name="theme-color"]').setAttribute("content", bg);
  }
} catch (e) {}
