const $ = (id) => document.getElementById(id);

function badge(text, cls) { return `<span class="badge ${cls}">${text}</span>`; }

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const status = $("status");
  const knockBtn = $("knock");

  if (!tab || !tab.id) { status.textContent = "No active tab."; return; }

  const res = await chrome.runtime.sendMessage({ type: "status", tabId: tab.id }).catch(() => null);
  if (!res || !res.origin) {
    status.innerHTML = badge("n/a", "n") + " Not an http(s) page.";
    return;
  }
  const host = new URL(res.origin).host;
  if (!res.enrolled) {
    status.innerHTML = badge("Not protected", "n") + "<br><span class='muted'>" + host + "</span>";
    return;
  }
  if (res.granted) {
    status.innerHTML = badge("Unlocked", "g") + "<br><span class='muted'>" + host + "</span>";
  } else {
    status.innerHTML = badge("Locked", "r") + "<br><span class='muted'>" + host + "</span>";
  }
  knockBtn.style.display = "block";
  knockBtn.textContent = res.granted ? "Re-knock" : "Knock now";
  knockBtn.onclick = async () => {
    knockBtn.disabled = true;
    knockBtn.textContent = "Knocking…";
    await chrome.runtime.sendMessage({ type: "knock", tabId: tab.id }).catch(() => {});
    window.close();
  };
}

$("opts").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
main();
