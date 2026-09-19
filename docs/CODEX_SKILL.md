# UI UX Pro Max with Codex

The requested [UI UX Pro Max skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill)
was installed from `.claude/skills/ui-ux-pro-max` at upstream commit
`de5f12b400775997d213524ef02a7c7d2746806f`. Its scripts, design data and references are included.
Only that requested skill was installed; there is no runtime dependency on it in Discovr.

Local installation: `%USERPROFILE%\.codex\skills\ui-ux-pro-max`.
A directory junction at `%USERPROFILE%\.agents\skills\ui-ux-pro-max` points to it for Codex's
current user-skill discovery path. No copy was put in the product or release archives.

It will be available on your next turn. Invoke it explicitly in a Codex prompt:

```text
$ui-ux-pro-max Review Discovr's native desktop workflow for accessibility,
simplicity and responsiveness. Keep it offline, with no webview or extra downloads.
```

Or ask for a concrete change:

```text
$ui-ux-pro-max Improve the discovery form in this repository. Keep the native
Qt controls, make errors easy to fix, and verify keyboard navigation and dark mode.
```

Codex may also select a skill when its description matches your task. If it does not appear
after the next turn, restart Codex. See [official Codex skill guidance](https://learn.chatgpt.com/docs/build-skills).

The skill's search helpers use Python in the development environment. That does not change
the app's no-install requirement. Its web frameworks and remote-font suggestions do not
apply to this native product. For this upgrade, native guidance on visible labels, keyboard
focus, plain-text errors, background work, cached/virtualised tables, progress and progressive
disclosure was applied. Off-topic website-pattern search results were not persisted as a design system.
