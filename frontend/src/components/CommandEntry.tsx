import { useState, type RefObject } from "react";

const titles: Record<string, string> = {
  run: "Run", step: "Step", "step over": "Step over", pause: "Pause", skip: "Skip",
  stop: "Stop", reload: "Reload", recover: "Recover", abort: "Abort execution",
};

/** Keyboard equivalent of existing buttons, never a Python/SPELL evaluation shell. */
export function CommandEntry({ toolbar, disabled }: { toolbar: RefObject<HTMLDivElement | null>; disabled: boolean }) {
  const [value, setValue] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  return <form className="manual-command-entry" onSubmit={(event) => {
    event.preventDefault();
    const title = titles[value.trim().toLowerCase().replace(/\s+/g, " ")];
    const button = title ? toolbar.current?.querySelector<HTMLButtonElement>(`button[title="${title}"]`) : null;
    if (!button) { setMessage("Use run, step, step over, pause, skip, stop, reload, recover or abort."); return; }
    if (disabled || button.disabled) { setMessage("That command is unavailable in the current procedure state."); return; }
    button.click(); setValue(""); setMessage(null);
  }}>
    <label htmlFor="procedure-command">Enter command</label>
    <input id="procedure-command" autoComplete="off" spellCheck={false} maxLength={48} value={value}
      disabled={disabled} onChange={(event) => { setValue(event.target.value); setMessage(null); }} />
    <button type="submit" disabled={disabled || !value.trim()}>Confirm</button>
    <button type="button" disabled={!value && !message} onClick={() => { setValue(""); setMessage(null); }}>Reset</button>
    {message && <p role="alert">{message}</p>}
  </form>;
}
