## Description

<!-- What does this PR do? Keep it brief — one or two sentences. -->

## Changes

<!-- List the files changed and why. -->

- 

## How to Test

<!-- How can a reviewer verify this works? For skill changes, include the command to invoke it. -->

```bash
# Claude Code: copy the skill, then say the trigger phrase
cp -r .claude/skills/ai-ready ~/.claude/skills/ai-ready
# Then start Claude Code and say: "make this repo ai-ready"

# Copilot CLI: install the plugin and test
copilot plugin install johnpapa/ai-ready
# Then start copilot and say: "make this repo ai-ready"
```

## Checklist

- [ ] SKILL.md frontmatter includes `name` and `description`
- [ ] All YAML files are valid syntax
- [ ] Tested the skill on at least one repo (specify which below)
- [ ] Updated `CHANGELOG.md` with what changed and why
- [ ] Updated `AGENTS.md` if repo structure changed
- [ ] Updated `README.md` if user-facing behavior changed
- [ ] Updated `docs/how-it-works.md` if the 3-mechanism or 12-asset model changed

## Tested On

<!-- Which repo(s) did you run the skill against? What was the result? -->

| Repo | Type | Result |
|------|------|--------|
|  |  |  |
