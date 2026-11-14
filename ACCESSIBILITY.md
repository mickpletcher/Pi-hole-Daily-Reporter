# Accessibility

## Scope and current status

Pi-hole Daily Reporter is a Python command-line application with Markdown reports
and CSV exports, not a hosted web application. Accessibility applies to its CLI,
documentation, generated reports, and review workflow.

The project aims to make these surfaces usable with keyboard navigation,
screen readers, magnification, and other assistive technology. This statement is
a contribution standard, not certification of WCAG conformance. A comprehensive
assistive-technology audit has not been completed. Spreadsheet applications,
terminal emulators, email clients, and GitHub may present the same output
differently; their accessibility is outside this application's direct control.

## Guidelines for changes

- Use descriptive headings in a logical order and meaningful link labels.
- Explain commands, abbreviations, column meanings, and actionable errors in text.
- Do not convey status, warnings, recommendations, or decisions by color alone.
- Preserve text-based output and copyable commands. Avoid decorative characters
  or layout that obscures meaning when read linearly.
- Keep CSV headers stable and descriptive. Document column order, units, UTC
  timestamps, and the distinction between recommendations and manual decisions.
  Do not merge cells or require a visual layout to interpret a decision.
- Provide meaningful alternative text for informative images in documentation;
  do not use screenshots as the only explanation of a workflow.
- For any future HTML view, use semantic headings, tables and form labels,
  visible keyboard focus, sufficient contrast, and keyboard-operable controls.
  Treat WCAG 2.2 Level AA as a design target, not an achieved status.

## Review checklist

For changed output or documentation, check heading order and link clarity, read
the content in linear order, and confirm status remains understandable without
color. For interactive changes, test keyboard-only operation and relevant
assistive technology. For CSV changes, inspect headers and a synthetic sample in
a spreadsheet application where available. Record the platforms/tools actually
tested and any untested combinations or barriers in the pull request.

## Reporting a barrier

Use the [accessibility issue template](https://github.com/mickpletcher/Pi-hole-Daily-Reporter/issues/new?template=accessibility.md).
Describe the affected command/document/report, expected and actual behavior,
and the relevant operating system, application, and assistive technology if you
wish. Include synthetic examples only. You do not need to disclose a disability
or medical information to request an improvement.

Accessibility reports are reviewed alongside other project issues. No fixed
response or resolution timeline is promised. For private concerns, request a
private contact route without posting personal details in a public issue.
