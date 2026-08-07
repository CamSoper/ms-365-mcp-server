/**
 * Outbound recipient allowlist ("send policy").
 *
 * Why: an MCP server with both mail-read and mail-send tools is a data
 * exfiltration hazard under prompt injection — a hostile email can steer the
 * model into forwarding mailbox contents to an attacker address. Tool-level
 * filtering (ENABLED_TOOLS / --read-only) can only remove send entirely. This
 * policy keeps send usable while bounding WHERE mail can go, enforced
 * server-side, below the model:
 *
 *  - Sends whose recipients are all on the allowlist proceed unchanged.
 *  - Sends with any recipient off the allowlist are REDIRECTED TO A DRAFT
 *    (Graph has native draft twins for every send action: sendMail →
 *    create message, reply/replyAll/forward → createReply/createReplyAll/
 *    createForward). Nothing leaves the mailbox; the user finds the message
 *    in Drafts and can send it themselves after review.
 *  - Actions with no draft equivalent (sending an existing draft, calendar
 *    invites — Graph sends invite mail to attendees on event create/update,
 *    and event forward) are DENIED with a structured error naming the
 *    blocked recipients. No silent stripping: surprising mutations are
 *    their own bug class.
 *  - graph-batch sub-requests that match any policed action are denied
 *    wholesale — the batch passthrough must not be a policy bypass.
 *
 * Opt-in per deployment via MS365_MCP_SEND_ALLOWLIST: a comma- or
 * whitespace-separated list of addresses and/or `*@domain` patterns
 * (case-insensitive). Unset or empty → the policy is off and nothing here
 * runs. Include the mailbox owner's own address: replyAll recipient sets
 * usually contain it.
 *
 * Known gaps (documented, excludable via ENABLED_TOOLS): Teams/chat/channel
 * sends and activity notifications are not policed in v1.
 */

export type RecipientPolicyDecision =
  | { action: 'proceed' }
  | { action: 'rewrite'; path: string; body: unknown; note: RecipientPolicyNote }
  | { action: 'deny'; reason: string; blockedRecipients: string[] };

export interface RecipientPolicyNote {
  policy: 'send_allowlist';
  action: 'redirected_to_draft';
  blockedRecipients: string[];
  message: string;
}

/** Read at call time (not module load) so tests and long-lived processes see env changes. */
export function getSendAllowlist(): string[] {
  const raw = process.env.MS365_MCP_SEND_ALLOWLIST || '';
  return raw
    .split(/[\s,]+/)
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length > 0);
}

export function isRecipientPolicyEnabled(): boolean {
  return getSendAllowlist().length > 0;
}

export function isRecipientAllowed(address: string, allowlist: string[]): boolean {
  const addr = address.trim().toLowerCase();
  if (addr.length === 0) return false;
  for (const entry of allowlist) {
    if (entry.startsWith('*@')) {
      if (addr.endsWith(entry.slice(1)) && addr.includes('@')) return true;
    } else if (addr === entry) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

type PolicedClass =
  | 'send' // sendMail: recipients in body, draft twin = create message
  | 'reply' // implicit recipient = original sender (lookup required)
  | 'replyAll' // implicit recipients = sender + to + cc (lookup required)
  | 'forward' // explicit toRecipients in body, draft twin = createForward
  | 'sendDraft' // recipients live on the stored draft (lookup required), no twin
  | 'eventWrite' // create/update event: attendees receive invite mail, no twin
  | 'eventForward' // explicit toRecipients, no twin
  | 'batch';

/** Collapse `{param}` / `:param` segments so generated and endpoints.json path styles match. */
function normalizePattern(p: string): string {
  return p
    .toLowerCase()
    .split('?')[0]
    .split('/')
    .map((seg) => (seg.startsWith('{') || seg.startsWith(':') ? '*' : seg))
    .join('/');
}

const CLASS_BY_PATTERN: Record<string, { method: string; cls: PolicedClass }[]> = {
  '/$batch': [{ method: 'post', cls: 'batch' }],
  '/me/sendmail': [{ method: 'post', cls: 'send' }],
  '/users/*/sendmail': [{ method: 'post', cls: 'send' }],
  '/me/messages/*/reply': [{ method: 'post', cls: 'reply' }],
  '/users/*/messages/*/reply': [{ method: 'post', cls: 'reply' }],
  '/me/messages/*/replyall': [{ method: 'post', cls: 'replyAll' }],
  '/users/*/messages/*/replyall': [{ method: 'post', cls: 'replyAll' }],
  '/me/messages/*/forward': [{ method: 'post', cls: 'forward' }],
  '/users/*/messages/*/forward': [{ method: 'post', cls: 'forward' }],
  '/me/messages/*/send': [{ method: 'post', cls: 'sendDraft' }],
  '/me/events': [{ method: 'post', cls: 'eventWrite' }],
  '/me/calendars/*/events': [{ method: 'post', cls: 'eventWrite' }],
  '/me/events/*': [{ method: 'patch', cls: 'eventWrite' }],
  '/me/calendars/*/events/*': [{ method: 'patch', cls: 'eventWrite' }],
  '/me/events/*/forward': [{ method: 'post', cls: 'eventForward' }],
};

function classify(pathPattern: string, method: string): PolicedClass | undefined {
  const entries = CLASS_BY_PATTERN[normalizePattern(pathPattern)];
  if (!entries) return undefined;
  const m = method.toLowerCase();
  return entries.find((e) => e.method === m)?.cls;
}

// ---------------------------------------------------------------------------
// Recipient extraction
// ---------------------------------------------------------------------------

const UNPARSEABLE = '<unparseable-recipient>';

/**
 * Extract addresses from a Graph Recipient[] value. Entries that exist but
 * carry no parseable address string are reported as UNPARSEABLE — the policy
 * fails closed on shapes it cannot evaluate rather than letting them through.
 */
function extractAddresses(recipients: unknown): string[] {
  if (recipients == null) return [];
  if (!Array.isArray(recipients)) return [UNPARSEABLE];
  const out: string[] = [];
  for (const r of recipients) {
    const addr = (r as { emailAddress?: { address?: unknown } } | null)?.emailAddress?.address;
    out.push(typeof addr === 'string' && addr.trim().length > 0 ? addr.trim() : UNPARSEABLE);
  }
  return out;
}

function blockedOf(addresses: string[], allowlist: string[]): string[] {
  return [...new Set(addresses.filter((a) => !isRecipientAllowed(a, allowlist)))];
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

/** to/cc/bcc of a message-shaped object ({to,cc,bcc}Recipients). */
function messageRecipientAddresses(message: Record<string, unknown> | undefined): string[] {
  if (!message) return [];
  return [
    ...extractAddresses(message.toRecipients),
    ...extractAddresses(message.ccRecipients),
    ...extractAddresses(message.bccRecipients),
  ];
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

export interface RecipientPolicyInput {
  /** Template path (endpoints.json pathPattern, or the generated tool path). */
  pathPattern: string;
  /** Concrete path the request will hit (query string tolerated). */
  resolvedPath: string;
  method: string;
  body: unknown;
  /** Authenticated GET returning parsed JSON; used to resolve implicit recipients. */
  fetchJson: (path: string) => Promise<Record<string, unknown>>;
}

function draftNote(blocked: string[]): RecipientPolicyNote {
  return {
    policy: 'send_allowlist',
    action: 'redirected_to_draft',
    blockedRecipients: blocked,
    message:
      'One or more recipients are not on the server send allowlist, so nothing was sent. ' +
      'The message was saved to the Drafts folder instead; the user can review and send it themselves. ' +
      'Tell the user this happened and name the blocked recipients.',
  };
}

const BATCH_MESSAGE_ACTION = /\/messages\/[^/]+\/(reply|replyall|forward|send)$/;
const BATCH_EVENT_FORWARD = /\/events\/[^/]+\/forward$/;
const BATCH_EVENT_WRITE = /\/events(\/[^/]+)?$/;

/** Offending sub-request descriptions, empty when the batch is clean. */
function batchViolations(body: unknown): string[] {
  const requests = asRecord(body)?.requests;
  if (!Array.isArray(requests)) return []; // Graph rejects malformed batches itself
  const offenders: string[] = [];
  for (const entry of requests) {
    const req = asRecord(entry);
    const url = typeof req?.url === 'string' ? req.url : undefined;
    const method = typeof req?.method === 'string' ? req.method.toLowerCase() : undefined;
    if (!req || !url || !method) {
      offenders.push('<malformed sub-request>'); // fail closed on shapes we cannot evaluate
      continue;
    }
    if (method === 'get') continue;
    const p = url.split('?')[0].toLowerCase();
    const attendees = asRecord(req.body)?.attendees;
    const hasAttendees = Array.isArray(attendees) ? attendees.length > 0 : attendees != null;
    if (
      p.endsWith('/sendmail') ||
      BATCH_MESSAGE_ACTION.test(p) ||
      BATCH_EVENT_FORWARD.test(p) ||
      (BATCH_EVENT_WRITE.test(p) && hasAttendees)
    ) {
      offenders.push(`${method.toUpperCase()} ${url}`);
    }
  }
  return offenders;
}

export async function applyRecipientPolicy(
  input: RecipientPolicyInput
): Promise<RecipientPolicyDecision> {
  const cls = classify(input.pathPattern, input.method);
  if (!cls) return { action: 'proceed' };

  const allowlist = getSendAllowlist();
  const cleanPath = input.resolvedPath.split('?')[0];
  const body = asRecord(input.body);

  switch (cls) {
    case 'send': {
      const message = asRecord(body?.message);
      if (!message) {
        // Cannot evaluate recipients on an unrecognized shape; Graph would
        // reject it anyway, but the safe error direction is closed.
        return {
          action: 'deny',
          reason: 'sendMail body has no message object; recipients cannot be evaluated.',
          blockedRecipients: [],
        };
      }
      const blocked = blockedOf(messageRecipientAddresses(message), allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      // Draft twin: POST /me/messages (or /users/{id}/messages).
      return {
        action: 'rewrite',
        path: cleanPath.replace(/\/sendMail$/i, '/messages'),
        body: message,
        note: draftNote(blocked),
      };
    }

    case 'reply':
    case 'replyAll': {
      const basePath = cleanPath.replace(/\/(reply|replyAll)$/i, '');
      let original: Record<string, unknown>;
      try {
        original = await input.fetchJson(
          `${basePath}?$select=from,replyTo,toRecipients,ccRecipients`
        );
      } catch {
        return {
          action: 'deny',
          reason:
            'Could not look up the original message to evaluate reply recipients against the send allowlist.',
          blockedRecipients: [],
        };
      }
      const replyTo = extractAddresses(original.replyTo);
      const implicit =
        replyTo.length > 0 ? replyTo : extractAddresses(original.from ? [original.from] : []);
      const addresses = [...implicit];
      if (cls === 'replyAll') {
        addresses.push(
          ...extractAddresses(original.toRecipients),
          ...extractAddresses(original.ccRecipients)
        );
      }
      // The reply action also accepts explicit additions under body.message.
      addresses.push(...messageRecipientAddresses(asRecord(body?.message)));
      const blocked = blockedOf(addresses, allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      // Draft twins: createReply / createReplyAll take the same body shape.
      const twin = cls === 'reply' ? '/createReply' : '/createReplyAll';
      return {
        action: 'rewrite',
        path: `${basePath}${twin}`,
        body: input.body ?? {},
        note: draftNote(blocked),
      };
    }

    case 'forward': {
      const addresses = [
        ...extractAddresses(body?.toRecipients),
        ...messageRecipientAddresses(asRecord(body?.message)),
      ];
      const blocked = blockedOf(addresses, allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      return {
        action: 'rewrite',
        path: cleanPath.replace(/\/forward$/i, '/createForward'),
        body: input.body ?? {},
        note: draftNote(blocked),
      };
    }

    case 'sendDraft': {
      const basePath = cleanPath.replace(/\/send$/i, '');
      let draft: Record<string, unknown>;
      try {
        draft = await input.fetchJson(
          `${basePath}?$select=toRecipients,ccRecipients,bccRecipients`
        );
      } catch {
        return {
          action: 'deny',
          reason:
            'Could not look up the draft to evaluate its recipients against the send allowlist.',
          blockedRecipients: [],
        };
      }
      const blocked = blockedOf(messageRecipientAddresses(draft), allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      return {
        action: 'deny',
        reason:
          'The draft addresses recipients that are not on the server send allowlist. It was NOT sent and remains in Drafts. ' +
          'Tell the user, naming the blocked recipients; they can send it themselves from Outlook.',
        blockedRecipients: blocked,
      };
    }

    case 'eventWrite': {
      // Graph mails invites to attendees on create/update; there is no draft
      // state for events, so violations are refused outright (no silent
      // attendee stripping).
      if (body?.attendees == null) return { action: 'proceed' };
      const blocked = blockedOf(extractAddresses(body.attendees), allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      return {
        action: 'deny',
        reason:
          'Calendar invites are sent by email to every attendee, and one or more attendees are not on the server send allowlist. ' +
          'The event was NOT created/updated. Retry without the blocked attendees, or tell the user why it was refused.',
        blockedRecipients: blocked,
      };
    }

    case 'eventForward': {
      const blocked = blockedOf(extractAddresses(body?.toRecipients), allowlist);
      if (blocked.length === 0) return { action: 'proceed' };
      return {
        action: 'deny',
        reason:
          'Forwarding a calendar event mails it to the recipients, and one or more are not on the server send allowlist. Nothing was forwarded.',
        blockedRecipients: blocked,
      };
    }

    case 'batch': {
      const offenders = batchViolations(input.body);
      if (offenders.length === 0) return { action: 'proceed' };
      return {
        action: 'deny',
        reason:
          'The batch contains sub-requests that send mail or calendar invites, which the batch passthrough cannot evaluate against the send allowlist. ' +
          `Offending sub-requests: ${offenders.join('; ')}. Use the dedicated tools (send-mail, reply-mail-message, create-calendar-event, ...) so the policy can evaluate recipients.`,
        blockedRecipients: [],
      };
    }
  }
}
