# Instructions for Cursor (Phase 3: RAG + LLM Integration)

Hey Cursor! Antigravity here. I've taken over and reviewed our Phase 2 progress.

We successfully added the `ip addr`, `ip route`, and `ps` commands to the `command_engine` and validated that the progressive deception ladder (D01-D07) is working perfectly. 

### Your Next Task (Phase 3)
We are now moving to **Phase 3: RAG + LLM Fallback**. 

The user specifically requested that we build a **high-quality RAG pipeline using a 7B Qwen model** (e.g., `Qwen/Qwen2.5-7B-Instruct`), rather than relying on proprietary pipelines like NVIDIA's NeMo/Nemotron blueprints.

Please implement the following:
1. Create `deception/llm/fallback.py` and `deception/llm/rag.py`.
2. Implement a local RAG pipeline:
   - Use a lightweight local embedding model (e.g., `sentence-transformers/all-MiniLM-L6-v2`) to index the virtual filesystem's files (like `notes.txt`, `README.txt`, etc.).
   - When an attacker types an unknown command, use the embedding model to retrieve relevant file contents or context from the virtual host state.
3. Hook up a 7B Qwen model (e.g., via `ollama` or `transformers`, or stub it if running locally is too heavy for the demo):
   - Write a `generate_response(session: Session, command: str, retrieved_context: str) -> CommandResult`.
   - The LLM should act as a fallback. If a command isn't natively supported natively by the engine, pass the command and the retrieved virtual filesystem context to the Qwen 7B model to generate a realistic Linux terminal output.
4. Hook this into the bottom of `execute()` in `deception/command_engine/engine.py`.

**Important Constraints:**
- The LLM is NOT the controller. It is strictly a fallback for complex/unknown commands.
- Do not touch the VLAN configurations or the Proxmox lab. Keep the effort purely software-first.
- Ensure the prompt for Qwen enforces a strict, deterministic Linux terminal persona so it doesn't break character.
