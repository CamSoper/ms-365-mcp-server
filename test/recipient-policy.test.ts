import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  applyRecipientPolicy,
  getSendAllowlist,
  isRecipientAllowed,
  isRecipientPolicyEnabled,
} from '../src/lib/recipient-policy.js';
import { registerGraphTools } from '../src/graph-tools.js';
import type { GraphClient } from '../src/graph-client.js';

vi.mock('../src/logger.js', () => ({
  default: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  },
}));

vi.mock('../src/generated/client-beta.js', () => ({ api: { endpoints: [] } }));
vi.mock('../src/generated/client.js', async () => {
  const { z } = await import('zod');
  return {
    api: {
      endpoints: [
        {
          alias: 'send-mail',
          method: 'post',
          path: '/me/sendMail',
          description: 'Send mail.',
          parameters: [
            {
              name: 'body',
              type: 'Body',
              schema: z.object({
                message: z.record(z.string(), z.unknown()).optional(),
                saveToSentItems: z.boolean().optional(),
              }),
            },
          ],
        },
        {
          alias: 'create-calendar-event',
          method: 'post',
          path: '/me/events',
          description: 'Create event.',
          parameters: [
            {
              name: 'body',
              type: 'Body',
              schema: z.object({
                subject: z.string().optional(),
                attendees: z.array(z.record(z.string(), z.unknown())).optional(),
              }),
            },
          ],
        },
      ],
    },
  };
});

const ALLOW = 'cam@family.example, *@soper.ninja';

function recipient(address: string) {
  return { emailAddress: { address } };
}

const noLookup = async (): Promise<Record<string, unknown>> => {
  throw new Error('no lookup expected');
};

beforeEach(() => {
  process.env.MS365_MCP_SEND_ALLOWLIST = ALLOW;
});

afterEach(() => {
  delete process.env.MS365_MCP_SEND_ALLOWLIST;
  vi.clearAllMocks();
});

describe('allowlist parsing and matching', () => {
  it('parses comma/whitespace separated entries case-insensitively', () => {
    process.env.MS365_MCP_SEND_ALLOWLIST = ' A@B.example ,, *@Soper.Ninja\n c@d.example ';
    expect(getSendAllowlist()).toEqual(['a@b.example', '*@soper.ninja', 'c@d.example']);
  });

  it('is disabled when unset or empty', () => {
    delete process.env.MS365_MCP_SEND_ALLOWLIST;
    expect(isRecipientPolicyEnabled()).toBe(false);
    process.env.MS365_MCP_SEND_ALLOWLIST = '  ';
    expect(isRecipientPolicyEnabled()).toBe(false);
  });

  it('matches exact addresses and domain wildcards', () => {
    const list = getSendAllowlist();
    expect(isRecipientAllowed('cam@family.example', list)).toBe(true);
    expect(isRecipientAllowed('CAM@Family.Example', list)).toBe(true);
    expect(isRecipientAllowed('anyone@soper.ninja', list)).toBe(true);
    expect(isRecipientAllowed('attacker@evil.example', list)).toBe(false);
    // must not match a bare domain string or a suffix without @
    expect(isRecipientAllowed('soper.ninja', list)).toBe(false);
  });
});

describe('sendMail', () => {
  const input = (
    message: unknown,
    pathPattern = '/me/sendMail',
    resolvedPath = '/me/sendMail'
  ) => ({
    pathPattern,
    resolvedPath,
    method: 'post',
    body: { message, saveToSentItems: true },
    fetchJson: noLookup,
  });

  it('proceeds when every recipient is allowlisted', async () => {
    const d = await applyRecipientPolicy(
      input({
        toRecipients: [recipient('cam@family.example')],
        ccRecipients: [recipient('kid@soper.ninja')],
      })
    );
    expect(d).toEqual({ action: 'proceed' });
  });

  it('redirects to a draft when any recipient is blocked', async () => {
    const message = {
      subject: 's',
      toRecipients: [recipient('cam@family.example'), recipient('attacker@evil.example')],
    };
    const d = await applyRecipientPolicy(input(message));
    expect(d.action).toBe('rewrite');
    if (d.action !== 'rewrite') return;
    expect(d.path).toBe('/me/messages');
    expect(d.body).toEqual(message);
    expect(d.note.blockedRecipients).toEqual(['attacker@evil.example']);
  });

  it('checks bcc and rewrites the shared-mailbox variant to the right drafts path', async () => {
    const d = await applyRecipientPolicy(
      input(
        { bccRecipients: [recipient('attacker@evil.example')] },
        '/users/{user-id}/sendMail',
        '/users/u1/sendMail'
      )
    );
    expect(d.action).toBe('rewrite');
    if (d.action !== 'rewrite') return;
    expect(d.path).toBe('/users/u1/messages');
  });

  it('fails closed on a body without a message object', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/sendMail',
      resolvedPath: '/me/sendMail',
      method: 'post',
      body: { toRecipients: [recipient('cam@family.example')] },
      fetchJson: noLookup,
    });
    expect(d.action).toBe('deny');
  });

  it('fails closed on recipient entries with no parseable address', async () => {
    const d = await applyRecipientPolicy(input({ toRecipients: [{ emailAddress: {} }] }));
    expect(d.action).toBe('rewrite');
  });
});

describe('reply / replyAll / forward', () => {
  const replyInput = (
    fetchJson: (path: string) => Promise<Record<string, unknown>>,
    action = 'reply',
    body: unknown = { comment: 'hi' }
  ) => ({
    pathPattern: `/me/messages/{message-id}/${action}`,
    resolvedPath: `/me/messages/m1/${action}`,
    method: 'post',
    body,
    fetchJson,
  });

  it('reply proceeds when the original sender is allowlisted', async () => {
    const d = await applyRecipientPolicy(
      replyInput(async () => ({ from: recipient('cam@family.example') }))
    );
    expect(d).toEqual({ action: 'proceed' });
  });

  it('reply honors replyTo over from and redirects to createReply when blocked', async () => {
    const lookups: string[] = [];
    const d = await applyRecipientPolicy(
      replyInput(async (p) => {
        lookups.push(p);
        return {
          from: recipient('cam@family.example'),
          replyTo: [recipient('attacker@evil.example')],
        };
      })
    );
    expect(lookups[0]).toBe('/me/messages/m1?$select=from,replyTo,toRecipients,ccRecipients');
    expect(d.action).toBe('rewrite');
    if (d.action !== 'rewrite') return;
    expect(d.path).toBe('/me/messages/m1/createReply');
    expect(d.body).toEqual({ comment: 'hi' });
  });

  it('replyAll also evaluates the original to/cc lists', async () => {
    const d = await applyRecipientPolicy(
      replyInput(
        async () => ({
          from: recipient('cam@family.example'),
          toRecipients: [recipient('cam@family.example')],
          ccRecipients: [recipient('outsider@evil.example')],
        }),
        'replyAll'
      )
    );
    expect(d.action).toBe('rewrite');
    if (d.action !== 'rewrite') return;
    expect(d.path).toBe('/me/messages/m1/createReplyAll');
  });

  it('reply evaluates explicit body.message recipient additions too', async () => {
    const d = await applyRecipientPolicy(
      replyInput(async () => ({ from: recipient('cam@family.example') }), 'reply', {
        comment: 'hi',
        message: { toRecipients: [recipient('attacker@evil.example')] },
      })
    );
    expect(d.action).toBe('rewrite');
  });

  it('reply denies when the original message lookup fails', async () => {
    const d = await applyRecipientPolicy(replyInput(noLookup));
    expect(d.action).toBe('deny');
  });

  it('forward checks explicit toRecipients and redirects to createForward', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/messages/{message-id}/forward',
      resolvedPath: '/me/messages/m1/forward',
      method: 'post',
      body: { toRecipients: [recipient('attacker@evil.example')], comment: 'fyi' },
      fetchJson: noLookup,
    });
    expect(d.action).toBe('rewrite');
    if (d.action !== 'rewrite') return;
    expect(d.path).toBe('/me/messages/m1/createForward');
  });
});

describe('send-draft-message', () => {
  const input = (fetchJson: (path: string) => Promise<Record<string, unknown>>) => ({
    pathPattern: '/me/messages/{message-id}/send',
    resolvedPath: '/me/messages/m1/send',
    method: 'post',
    body: null,
    fetchJson,
  });

  it('proceeds when the stored draft recipients are all allowlisted', async () => {
    const d = await applyRecipientPolicy(
      input(async () => ({ toRecipients: [recipient('kid@soper.ninja')] }))
    );
    expect(d).toEqual({ action: 'proceed' });
  });

  it('denies (leaving the draft intact) when a stored recipient is blocked', async () => {
    const d = await applyRecipientPolicy(
      input(async () => ({
        toRecipients: [recipient('kid@soper.ninja')],
        bccRecipients: [recipient('attacker@evil.example')],
      }))
    );
    expect(d.action).toBe('deny');
    if (d.action !== 'deny') return;
    expect(d.blockedRecipients).toEqual(['attacker@evil.example']);
  });

  it('denies when the draft lookup fails', async () => {
    const d = await applyRecipientPolicy(input(noLookup));
    expect(d.action).toBe('deny');
  });
});

describe('calendar events', () => {
  it('event create with no attendees proceeds', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/events',
      resolvedPath: '/me/events',
      method: 'post',
      body: { subject: 'dentist' },
      fetchJson: noLookup,
    });
    expect(d).toEqual({ action: 'proceed' });
  });

  it('event create with allowlisted attendees proceeds', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/calendars/{calendar-id}/events',
      resolvedPath: '/me/calendars/c1/events',
      method: 'post',
      body: { attendees: [recipient('cam@family.example')] },
      fetchJson: noLookup,
    });
    expect(d).toEqual({ action: 'proceed' });
  });

  it('event create with a blocked attendee is denied (invites are email)', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/events',
      resolvedPath: '/me/events',
      method: 'post',
      body: { attendees: [recipient('attacker@evil.example')] },
      fetchJson: noLookup,
    });
    expect(d.action).toBe('deny');
    if (d.action !== 'deny') return;
    expect(d.blockedRecipients).toEqual(['attacker@evil.example']);
  });

  it('event PATCH adding a blocked attendee is denied; PATCH without attendees proceeds', async () => {
    const base = {
      pathPattern: '/me/events/{event-id}',
      resolvedPath: '/me/events/e1',
      method: 'patch',
      fetchJson: noLookup,
    };
    const denied = await applyRecipientPolicy({
      ...base,
      body: { attendees: [recipient('attacker@evil.example')] },
    });
    expect(denied.action).toBe('deny');
    const ok = await applyRecipientPolicy({ ...base, body: { subject: 'rename only' } });
    expect(ok).toEqual({ action: 'proceed' });
  });

  it('event DELETE is not policed', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/events/{event-id}',
      resolvedPath: '/me/events/e1',
      method: 'delete',
      body: null,
      fetchJson: noLookup,
    });
    expect(d).toEqual({ action: 'proceed' });
  });

  it('event forward to a blocked recipient is denied', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/events/{event-id}/forward',
      resolvedPath: '/me/events/e1/forward',
      method: 'post',
      body: { toRecipients: [recipient('attacker@evil.example')] },
      fetchJson: noLookup,
    });
    expect(d.action).toBe('deny');
  });
});

describe('graph-batch passthrough', () => {
  const input = (requests: unknown) => ({
    pathPattern: '/$batch',
    resolvedPath: '/$batch',
    method: 'post',
    body: { requests },
    fetchJson: noLookup,
  });

  it('a read-only batch proceeds', async () => {
    const d = await applyRecipientPolicy(
      input([
        { id: '1', method: 'GET', url: '/me/messages?$top=5' },
        { id: '2', method: 'GET', url: '/me/events' },
      ])
    );
    expect(d).toEqual({ action: 'proceed' });
  });

  it('a batch smuggling sendMail is denied', async () => {
    const d = await applyRecipientPolicy(
      input([
        { id: '1', method: 'GET', url: '/me/messages' },
        { id: '2', method: 'POST', url: '/me/sendMail', body: { message: {} } },
      ])
    );
    expect(d.action).toBe('deny');
    if (d.action !== 'deny') return;
    expect(d.reason).toContain('POST /me/sendMail');
  });

  it('a batch message action (reply/forward/send) is denied', async () => {
    const d = await applyRecipientPolicy(
      input([{ id: '1', method: 'POST', url: '/me/messages/m1/forward', body: {} }])
    );
    expect(d.action).toBe('deny');
  });

  it('a batch event write with attendees is denied; without attendees proceeds', async () => {
    const denied = await applyRecipientPolicy(
      input([
        {
          id: '1',
          method: 'POST',
          url: '/me/events',
          body: { attendees: [recipient('x@y.example')] },
        },
      ])
    );
    expect(denied.action).toBe('deny');
    const ok = await applyRecipientPolicy(
      input([{ id: '1', method: 'POST', url: '/me/events', body: { subject: 'no attendees' } }])
    );
    expect(ok).toEqual({ action: 'proceed' });
  });

  it('a malformed sub-request fails closed', async () => {
    const d = await applyRecipientPolicy(input([{ id: '1', method: 'POST' }]));
    expect(d.action).toBe('deny');
  });
});

describe('non-policed operations', () => {
  it('draft creation is never policed - drafts are the safe sink', async () => {
    const d = await applyRecipientPolicy({
      pathPattern: '/me/messages',
      resolvedPath: '/me/messages',
      method: 'post',
      body: { toRecipients: [recipient('attacker@evil.example')] },
      fetchJson: noLookup,
    });
    expect(d).toEqual({ action: 'proceed' });
  });
});

describe('integration through executeGraphTool', () => {
  let mockServer: { tool: ReturnType<typeof vi.fn>; registerTool: ReturnType<typeof vi.fn> };
  let mockGraphClient: GraphClient;
  let graphRequest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockServer = { tool: vi.fn(), registerTool: vi.fn() };
    graphRequest = vi.fn().mockResolvedValue({
      content: [{ type: 'text', text: JSON.stringify({ id: 'result-1' }) }],
    });
    mockGraphClient = { graphRequest } as unknown as GraphClient;
  });

  function getToolHandler(toolName: string) {
    registerGraphTools(mockServer, mockGraphClient, false);
    const call = mockServer.registerTool.mock.calls.find((c: unknown[]) => c[0] === toolName);
    expect(call).toBeDefined();
    return call![call!.length - 1] as (
      params: Record<string, unknown>
    ) => Promise<{ content: { text: string }[]; isError?: boolean }>;
  }

  it('send-mail to an allowlisted recipient goes straight through', async () => {
    const handler = getToolHandler('send-mail');
    await handler({
      body: { message: { subject: 's', toRecipients: [recipient('kid@soper.ninja')] } },
    });
    expect(graphRequest).toHaveBeenCalledTimes(1);
    expect(graphRequest.mock.calls[0][0]).toBe('/me/sendMail');
  });

  it('send-mail to a blocked recipient is rewritten to a draft with a policy note', async () => {
    const handler = getToolHandler('send-mail');
    const result = await handler({
      body: { message: { subject: 's', toRecipients: [recipient('attacker@evil.example')] } },
    });
    expect(graphRequest).toHaveBeenCalledTimes(1);
    expect(graphRequest.mock.calls[0][0]).toBe('/me/messages');
    expect(graphRequest.mock.calls[0][1].method).toBe('POST');
    const payload = JSON.parse(result.content[0].text);
    expect(payload.policy.action).toBe('redirected_to_draft');
    expect(payload.policy.blockedRecipients).toEqual(['attacker@evil.example']);
    expect(payload.result).toEqual({ id: 'result-1' });
    expect(result.isError).toBeUndefined();
  });

  it('create-calendar-event with a blocked attendee returns a structured denial', async () => {
    const handler = getToolHandler('create-calendar-event');
    const result = await handler({
      body: { subject: 's', attendees: [recipient('attacker@evil.example')] },
    });
    expect(graphRequest).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toBe('recipient_policy_violation');
    expect(payload.blockedRecipients).toEqual(['attacker@evil.example']);
  });

  it('policy disabled: blocked recipients pass through untouched', async () => {
    delete process.env.MS365_MCP_SEND_ALLOWLIST;
    const handler = getToolHandler('send-mail');
    await handler({
      body: { message: { toRecipients: [recipient('attacker@evil.example')] } },
    });
    expect(graphRequest).toHaveBeenCalledTimes(1);
    expect(graphRequest.mock.calls[0][0]).toBe('/me/sendMail');
  });
});
