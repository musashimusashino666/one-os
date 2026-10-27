# User Experience and Owner Control

## Purpose

The user environment must make the system controllable and understandable without requiring users to become kernel engineers. User agency is an architectural requirement, not a decorative layer added after the security model.

## Intended behavior

- Permission prompts state the resource, operation, scope, duration, and relevant consequence.
- Grants are narrow by default and can be inspected, modified, and revoked.
- Network activity, background work, device use, and privileged automation are discoverable.
- An AI or automation client receives only explicitly delegated capabilities. It cannot turn a natural-language request into authority that the user or kernel has not granted.
- Destructive or externally consequential actions require a proportionate confirmation policy and clear feedback.
- System errors explain the state and available recovery choices without exposing secrets.
- Core tasks have keyboard-accessible, assistive-technology-friendly, and low-connectivity paths where applicable.

## Permission model at the interface boundary

The UI may present a request and help the user understand it. It is not the source of truth for authority. The kernel MUST validate kernel-owned authority at the point where every protected operation executes. A policy or broker service may propose a decision or relay a request, but its own “allow” response cannot grant rights or override a kernel denial. A hidden background task cannot inherit broader rights merely because a foreground application once received permission. A compromised service is limited to its own explicitly delegated capabilities; this does not guarantee safe behavior within that service's own scope.

Revocation semantics must define whether existing handles are invalidated, in-flight operations finish or cancel, and resources are reclaimed. If these effects cannot be guaranteed, the UI must not promise instantaneous revocation.

## Measuring usability

Before claiming usability or accessibility, define representative tasks and measure task completion, error rate, recovery success, time-to-understand permission decisions, and accessibility conformance. Publish the method and limits. These measurements have not yet been established for ONE OS.

## Current status

The project is still at kernel bootstrap. A shell, compositor, permissions UI, accessibility implementation, and AI/automation control interface are not yet available.
