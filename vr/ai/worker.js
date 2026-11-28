// GhostCorp local inference worker. No server-side or paid API fallback.
import { CreateMLCEngine } from "https://esm.run/@mlc-ai/web-llm@0.2.86";

const MODEL_ID = "SmolLM2-360M-Instruct-q4f32_1-MLC";
let engine = null;
let busy = false;

self.onmessage = async (event) => {
  const data = event.data || {};
  if (data.type === "load") {
    if (busy || engine) return;
    busy = true;
    try {
      engine = await CreateMLCEngine(MODEL_ID, {
        initProgressCallback: (report) => self.postMessage({
          type: "progress",
          text: String(report?.text || "Preparing local model"),
          progress: Number.isFinite(report?.progress) ? report.progress : 0
        })
      });
      self.postMessage({ type: "ready", model: MODEL_ID, localOnly: true });
    } catch (error) {
      engine = null;
      self.postMessage({ type: "error", message: String(error?.message || error).slice(0, 500) });
    } finally {
      busy = false;
    }
    return;
  }
  if (data.type === "generate") {
    if (!engine || busy) {
      self.postMessage({ type: "error", message: "Local model is not ready or is busy." });
      return;
    }
    busy = true;
    try {
      const messages = Array.isArray(data.messages) ? data.messages.slice(-12) : [];
      const result = await engine.chat.completions.create({
        messages,
        temperature: 0.65,
        max_tokens: 384
      });
      const content = result?.choices?.[0]?.message?.content;
      if (typeof content !== "string") throw new Error("Model returned an invalid response.");
      self.postMessage({ type: "complete", content: content.slice(0, 12000) });
    } catch (error) {
      self.postMessage({ type: "error", message: String(error?.message || error).slice(0, 500) });
    } finally {
      busy = false;
    }
  }
};
