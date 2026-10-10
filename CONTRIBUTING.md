# Contributing

## Workflow

- Work lands directly on `main`. No pull requests for now.
- Keep each commit to one logical change, and make sure `npm test` and `npx tsc` pass before pushing.
- Never commit capture files (`.pcap`, `.pcapng`). They can contain passwords, cookies and internal addresses. Samples are generated in code (`src/core/sample.ts`).

## Text and translations

Every sentence the app shows lives in `src/i18n`, one file per language. Code in `src/core` and `src/ui` never contains display text; it reads from the dictionary it is given.

- `ko.ts` defines the shape (`Messages`). Every other language file must match it, and `npx tsc` fails if a key is missing.
- Write each language naturally. Do not translate sentence by sentence: the friendly tone of the explanations is the point of the tool.
- Protocol terms stay as they are in every language (`SYN`, `Client Hello`, `EtherType`).

To add a language:

1. Copy `src/i18n/en.ts` to `src/i18n/<code>.ts` and rewrite the text.
2. Register it in `LOCALES` and `LOCALE_NAMES` in `src/i18n/index.ts`. It then appears in the language menu.

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
| `i18n` | Explanatory text and translations (`src/i18n`) |

Scope is optional for changes that span the whole repository.

### Examples

```
feat(core): dissect NTP packets
fix(core): stop flagging TCP keep-alives as retransmissions
feat(ui): add step-by-step scenario mode
docs: explain live capture requirements on Linux
chore: bump vite to 7.4
```
