# CLAUDE.md

This file provides guidance and important rules working with code in this repository.

## When coding / building plan

 - Use a progressive disclosure approach for agent coding in this repository: start from high-level information in Serena memories, and only locate/read specific files or symbols when necessary to avoid expanding too much context at once.

#### Serena memories (Keep context clean)

- Prefer use serena mcp tools to understand the architecture and code hierarchy quickly.
- **ALWAYS** Call Serena's `activate_project` before reading memories.
- Start from `mem:core` as the graph root; the memory graph and add/update thresholds are defined in `.serena/memories/memory_maintenance.md`.

#### When Memories Are Insufficient (On-Demand Querying and Reading)

- Check `README.md` (and `docs/architecture.md`, `docs/generator-contract.md`).

## IDA MCP Tools Reference

GoldSrc analysis runs one owned `idalib-mcp` lifecycle per binary on `127.0.0.1:13337`; the MCP session surface is bound via the analyzer's Preprocessor. See `README.md` for the analyzer/IDA integration contract.
