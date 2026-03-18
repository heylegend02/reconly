function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function labelize(value) {
  return String(value)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function renderLeaf(value) {
  if (value === null || value === undefined || value === "") {
    return '<p class="result-empty">No data returned.</p>';
  }

  if (typeof value === "boolean") {
    return `<p class="result-leaf">${value ? "Yes" : "No"}</p>`;
  }

  return `<pre>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value, null, 2))}</pre>`;
}

function renderArray(items) {
  if (items.length === 0) {
    return '<p class="result-empty">No items returned.</p>';
  }

  const primitiveOnly = items.every(
    (item) =>
      item === null ||
      ["string", "number", "boolean"].includes(typeof item)
  );

  if (primitiveOnly) {
    return `<ul class="result-list">${items
      .map((item) => `<li>${escapeHtml(item === null ? "null" : item)}</li>`)
      .join("")}</ul>`;
  }

  return `<div class="result-array">${items
    .map(
      (item, index) => `
        <div class="result-item">
          <h5>Item ${index + 1}</h5>
          ${renderValue(item)}
        </div>
      `
    )
    .join("")}</div>`;
}

function renderObject(value) {
  const entries = Object.entries(value);
  if (entries.length === 0) {
    return '<p class="result-empty">No structured fields returned.</p>';
  }

  return `<div class="result-object">${entries
    .map(
      ([key, entryValue]) => `
        <section class="result-section">
          <h4>${escapeHtml(labelize(key))}</h4>
          ${renderValue(entryValue)}
        </section>
      `
    )
    .join("")}</div>`;
}

function renderValue(value) {
  if (Array.isArray(value)) {
    return renderArray(value);
  }

  if (value && typeof value === "object") {
    return renderObject(value);
  }

  return renderLeaf(value);
}

function formatResultHtml(result) {
  return `<div class="result-structured">${renderValue(result)}</div>`;
}

module.exports = {
  formatResultHtml,
};
