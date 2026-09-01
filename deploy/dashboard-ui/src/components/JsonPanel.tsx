import { motion } from "framer-motion";
import { ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import type { MilestoneReport } from "../types";

type Props = { report: MilestoneReport };

export function JsonPanel({ report }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <motion.section
      className="glass-card panel json-panel"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.55 }}
    >
      <button className="json-toggle" onClick={() => setOpen((v) => !v)} type="button">
        <div>
          <h2>Full report JSON</h2>
          <p>Milestone 1 export payload</p>
        </div>
        {open ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
      </button>
      <motion.div
        initial={false}
        animate={{ height: open ? "auto" : 0, opacity: open ? 1 : 0 }}
        transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
        style={{ overflow: "hidden" }}
      >
        <pre className="json-pre mono">{JSON.stringify(report, null, 2)}</pre>
      </motion.div>
    </motion.section>
  );
}
