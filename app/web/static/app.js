(function () {
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm");
      if (message && !window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.getElementById(button.getAttribute("data-copy"));
      if (!target) return;
      var text = "value" in target ? target.value : target.textContent;
      var done = function () {
        var previous = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(function () {
          button.textContent = previous;
        }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {
          target.focus();
          target.select();
          document.execCommand("copy");
          done();
        });
      } else {
        target.focus();
        target.select();
        document.execCommand("copy");
        done();
      }
    });
  });

  var filter = document.getElementById("mapping-filter");
  if (filter) {
    var rows = Array.prototype.slice.call(document.querySelectorAll("[data-mapping-row]"));
    filter.addEventListener("input", function () {
      var query = filter.value.trim().toLowerCase();
      rows.forEach(function (row) {
        var hay = (row.getAttribute("data-search") || "").toLowerCase();
        row.hidden = Boolean(query) && hay.indexOf(query) === -1;
      });
    });
  }

  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector("[type=submit]");
      if (!button) return;
      button.disabled = true;
      button.textContent = button.getAttribute("data-busy-label") || "Working…";
    });
  });
})();
