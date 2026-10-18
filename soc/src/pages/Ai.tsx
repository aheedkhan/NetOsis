import { BrainCircuit, CircleCheck, CircleX } from "lucide-react";
import { useAi } from "../lib/api";
import { clock } from "../lib/format";
import { Card, CardHead, Counter, Empty, ErrorState, PageHead, Skeleton } from "../components/ui";

export default function Ai() {
  const { data, isLoading, error } = useAi();
  if (error) return <ErrorState error={error} />;
  const share = data && data.commands ? Math.round((data.llm_answered / data.commands) * 100) : 0;
  return (
    <>
      <PageHead
        title="AI intelligence"
        sub="The local LLM only answers commands the deterministic engine can't. Everything below is measured from shipped events and a live probe of Ollama."
      />
      {isLoading || !data ? (
        <Skeleton className="h-[360px]" />
      ) : (
        <div className="grid gap-4">
          <div className="grid grid-cols-3 gap-4 max-lg:grid-cols-1">
            <Card className="p-5">
              <div className="flex items-center gap-2 text-[12.5px] font-medium text-ink-2">
                {data.ollama.reachable ? <CircleCheck className="size-4 text-green" /> : <CircleX className="size-4 text-red" />}
                Ollama {data.ollama.reachable ? "reachable" : "not reachable from the controller"}
              </div>
              <div className="mono mt-2 break-all text-[12px] text-ink-3">{data.ollama.url}</div>
              <div className="mt-3 text-[12.5px]">
                Live model: <span className="mono font-medium">{data.model}</span>
              </div>
              {data.ollama.reachable ? (
                <div className="mt-1 text-[12px] text-ink-3">Installed: {data.ollama.models.join(", ") || "none"}</div>
              ) : (
                <div className="mt-1 break-all text-[12px] text-ink-3">{data.ollama.error}</div>
              )}
            </Card>
            <Card className="p-5">
              <div className="text-[12.5px] font-medium text-ink-2">Commands answered by the LLM</div>
              <div className="mt-2 flex items-end gap-2">
                <Counter value={data.llm_answered} className="text-[30px] font-semibold leading-none" />
                <span className="pb-1 text-[12.5px] text-ink-3">of {data.commands.toLocaleString()} ({share}%)</span>
              </div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-line-2">
                <div className="h-2 rounded-full bg-blue" style={{ width: `${share}%` }} />
              </div>
              <p className="mt-2 text-[11.5px] text-ink-3">
                The rest ({data.deterministic.toLocaleString()}) came from the deterministic engine: the fake filesystem, network theater and system facts.
              </p>
            </Card>
            <Card className="p-5">
              <div className="text-[12.5px] font-medium text-ink-2">How an answer is chosen</div>
              <ol className="mt-2 grid gap-1.5 text-[12px] text-ink-2">
                <li>1 · Deterministic engine (files, users, ps, nmap, uname…)</li>
                <li>2 · Not a real binary → instant “command not found”</li>
                <li>3 · Cached answer for this host and user</li>
                <li>4 · RAG evidence (host facts + this attacker's profile) → local Qwen</li>
                <li>5 · Leak filter strips anything that would reveal the honeypot</li>
              </ol>
            </Card>
          </div>
          <Card>
            <CardHead title="Recent LLM-answered commands" sub="Commands no deterministic handler covered — candidates to emulate next" />
            {data.recent_llm.length === 0 ? (
              <Empty title="The LLM hasn't been needed in this window" icon={<BrainCircuit className="size-6" />} />
            ) : (
              <div className="overflow-x-auto">
              <table className="table mt-2">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Honeypot</th>
                    <th>Command</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_llm.map((r, i) => (
                    <tr key={i}>
                      <td className="num whitespace-nowrap text-ink-3">{clock(r.ts)}</td>
                      <td className="whitespace-nowrap">{r.sensor}</td>
                      <td className="mono">{r.command}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
