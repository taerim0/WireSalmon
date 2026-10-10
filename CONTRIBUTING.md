# Contributing

## Workflow

- Work lands directly on `main`. No pull requests for now.
- Keep each commit to one logical change, and make sure `npm test` and `npx tsc` pass before pushing.
- Never commit capture files (`.pcap`, `.pcapng`). They can contain passwords, cookies and internal addresses. Samples are generated in code (`src/core/sample.ts`).

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), written in English:

```
<type>(<scope>): <summary>

<optional body: what changed and why>
```

- **Summary**: imperative mood, lower case, no trailing period, 72 characters or fewer.
- **Body**: only when the reason isn't obvious from the summary.

### Types

| Type | Use for |
|---|---|
| `feat` | A new capability the user can see |
| `fix` | A bug fix |
| `docs` | README, guides, comments only |
| `style` | Formatting or CSS-only visual tweaks with no behavior change |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or fixing tests |
| `chore` | Tooling, dependencies, repository settings |

### Scopes

| Scope | Area |
|---|---|
| `core` | Capture reader, dissectors, conversation grouping (`src/core`) |
| `ui` | React screens and styles (`src/ui`) |
| `server` | Live capture helper (`server`) |
| `i18n` | Explanatory text and translations |

Scope is optional for changes that span the whole repository.

### Examples

```
feat(core): dissect NTP packets
fix(core): stop flagging TCP keep-alives as retransmissions
feat(ui): add step-by-step scenario mode
docs: explain live capture requirements on Linux
chore: bump vite to 7.4
```
