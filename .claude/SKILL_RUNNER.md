# SKILL_RUNNER.md

## Rules

- Complete every task in the skill selected by the initial prompt. Do not stop after a partial success.
- If an unrecoverable error prevents completion, report it as `<skill_error>ERROR REASON</skill_error>`.

Examples:

`<skill_error>Missing requirement "ida-pro-mcp".</skill_error>`

`<skill_error>Failed to connect to the active IDA database through ida-pro-mcp.</skill_error>`
