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
  var groups = Array.prototype.slice.call(document.querySelectorAll("[data-mapping-group]"));
  if (filter) {
    var rows = Array.prototype.slice.call(document.querySelectorAll("[data-mapping-row]"));
    var savedOpen = null;
    filter.addEventListener("input", function () {
      var query = filter.value.trim().toLowerCase();
      if (!query) {
        rows.forEach(function (row) { row.hidden = false; });
        groups.forEach(function (group) {
          group.hidden = false;
          if (savedOpen) group.open = savedOpen.get(group);
        });
        savedOpen = null;
        return;
      }
      if (!savedOpen) {
        savedOpen = new Map();
        groups.forEach(function (group) { savedOpen.set(group, group.open); });
      }
      rows.forEach(function (row) {
        var hay = (row.getAttribute("data-search") || "").toLowerCase();
        row.hidden = hay.indexOf(query) === -1;
      });
      groups.forEach(function (group) {
        var visible = group.querySelector("[data-mapping-row]:not([hidden])");
        group.hidden = !visible;
        if (visible) group.open = true;
      });
    });
  }
  document.querySelectorAll("[data-mapping-toggle]").forEach(function (button) {
    button.addEventListener("click", function () {
      var open = button.getAttribute("data-mapping-toggle") === "open";
      groups.forEach(function (group) {
        if (!group.hidden) group.open = open;
      });
    });
  });

  document.querySelectorAll("[data-dropzone]").forEach(function (zone) {
    var input = zone.querySelector("input[type=file]");
    var list = zone.querySelector("[data-file-list]");
    var title = zone.querySelector("[data-drop-title]");
    if (!input || !list || !title) return;
    var depth = 0;

    function render() {
      var files = input.files ? Array.prototype.slice.call(input.files) : [];
      list.innerHTML = "";
      if (!files.length) {
        list.hidden = true;
        title.textContent = "Drop configuration files here, or click to choose";
        return;
      }
      title.textContent = files.length === 1 ? "1 file ready" : files.length + " files ready";
      list.hidden = false;
      files.forEach(function (file) {
        var item = document.createElement("li");
        item.textContent = file.name;
        list.appendChild(item);
      });
    }

    input.addEventListener("change", render);
    zone.addEventListener("dragenter", function (event) {
      event.preventDefault();
      depth += 1;
      zone.classList.add("is-dragover");
    });
    zone.addEventListener("dragover", function (event) {
      event.preventDefault();
    });
    zone.addEventListener("dragleave", function () {
      depth -= 1;
      if (depth <= 0) {
        depth = 0;
        zone.classList.remove("is-dragover");
      }
    });
    zone.addEventListener("drop", function (event) {
      event.preventDefault();
      depth = 0;
      zone.classList.remove("is-dragover");
      var dropped = event.dataTransfer && event.dataTransfer.files;
      if (!dropped || !dropped.length || typeof DataTransfer === "undefined") return;
      var transfer = new DataTransfer();
      Array.prototype.forEach.call(dropped, function (file) {
        transfer.items.add(file);
      });
      input.files = transfer.files;
      render();
    });
  });

  document.querySelectorAll("[data-subnet-form]").forEach(function (form) {
    var list = form.querySelector("[data-subnet-list]");
    if (!list) return;

    function bind(row) {
      var add = row.querySelector("[data-subnet-add]");
      var remove = row.querySelector("[data-subnet-remove]");
      if (add) {
        add.addEventListener("click", function () {
          var fresh = row.cloneNode(true);
          fresh.querySelectorAll("input").forEach(function (input) { input.value = ""; });
          list.appendChild(fresh);
          bind(fresh);
          var first = fresh.querySelector("input");
          if (first) first.focus();
        });
      }
      if (remove) {
        remove.addEventListener("click", function () {
          var rows = list.querySelectorAll("[data-subnet-row]");
          if (rows.length <= 1) {
            row.querySelectorAll("input").forEach(function (input) { input.value = ""; });
            return;
          }
          row.remove();
        });
      }
    }

    list.querySelectorAll("[data-subnet-row]").forEach(bind);
  });

  document.querySelectorAll("form[data-sanitize]").forEach(function (form) {
    form.addEventListener("submit", function () {
      form.querySelectorAll("[data-copied-subnet]").forEach(function (node) {
        node.remove();
      });
      var source = document.querySelector("[data-subnet-form]");
      if (!source) return;
      function hidden(name, value) {
        var input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        input.setAttribute("data-copied-subnet", "");
        form.appendChild(input);
      }
      hidden("subnet_settings", "1");
      var box = source.querySelector("input[name='keep_ips']");
      if (box && box.checked) hidden("keep_ips", "1");
      source.querySelectorAll("[data-subnet-row]").forEach(function (row) {
        var real = row.querySelector("input[name='real_subnet']");
        var stand = row.querySelector("input[name='stand_in']");
        hidden("real_subnet", real ? real.value : "");
        hidden("stand_in", stand ? stand.value : "");
      });
    });
  });

  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector("[type=submit]");
      if (!button) return;
      button.disabled = true;
      button.textContent = button.getAttribute("data-busy-label") || "Working…";
    });
  });
})();
