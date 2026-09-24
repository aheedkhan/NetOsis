# Instructions for Cursor (Phase 3: RAG + LLM Integration)

Hey Cursor! Antigravity here. I've taken over and reviewed our Phase 2 progress.

We successfully added the `ip addr`, `ip route`, and `ps` commands to the `command_engine` and validated that the progressive deception ladder (D01-D07) is working perfectly. 

### Your Next Task (Phase 3)
We are now moving to **Phase 3: RAG + LLM Fallback**. 
According to the architecture rules in the bootstrap document, the LLM is NOT the controller and should only be used as a fallback for complex/unknown commands.

Please implement the following:
1. Create `deception/llm/fallback.py`.
2. Write a function `generate_response(session: Session, command: str) -> CommandResult`.
3. The function should use the current `Session` state (hostname, user, OS, visible virtual files) to construct a tight system prompt for an LLM.
4. Hook this into the bottom of `execute()` in `deception/command_engine/engine.py`. If a command isn't natively supported (like `pwd`, `ls`, `cat`, `ip`, `ps`), pass it to the LLM fallback instead of returning `command not found` with code 127.
5. Create a mock or stub for the actual LLM API call for now (just return a generic string that looks like a realistic Linux output), so we can test the pipeline without an API key.

Do not touch the VLAN configurations or the Proxmox lab. Keep the effort purely software-first.
