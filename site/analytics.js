(function exposeAnalytics(root, factory) {
  const analytics = factory();
  if (typeof module === 'object' && module.exports) module.exports = analytics;
  if (root) root.ReMediaLHQAnalytics = analytics;
})(typeof window === 'object' ? window : null, function buildAnalytics() {
  'use strict';

  const eventNames = Object.freeze([
    'newsletter_signup',
    'youtube_click',
    'affiliate_click',
    'sponsor_inquiry',
    'article_complete',
    'return_visitor',
    'guide_download'
  ]);
  const allowedEvents = new Set(eventNames);
  const sensitiveKey = /(address|cookie|email|ip|name|phone|token|user)/i;
  let enabled = false;
  let consent = 'denied';
  let sink = null;

  function snapshot() {
    return Object.freeze({
      enabled,
      consent,
      sinkConfigured: typeof sink === 'function',
      eventNames
    });
  }

  function configure(options) {
    const next = options && typeof options === 'object' ? options : {};
    enabled = next.enabled === true;
    consent = next.consent === 'granted' ? 'granted' : 'denied';
    sink = typeof next.sink === 'function' ? next.sink : null;
    return snapshot();
  }

  function disable() {
    enabled = false;
    consent = 'denied';
    sink = null;
    return snapshot();
  }

  function cleanParameters(parameters) {
    if (parameters === undefined) return Object.freeze({});
    if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
      throw new TypeError('analytics parameters must be an object');
    }
    const entries = Object.entries(parameters);
    if (entries.length > 8) throw new RangeError('analytics parameters exceed 8 keys');
    const cleaned = {};
    for (const [key, value] of entries) {
      if (!/^[a-z][a-z0-9_]{0,39}$/.test(key) || sensitiveKey.test(key)) {
        throw new TypeError(`analytics parameter is not allowed: ${key}`);
      }
      if (typeof value === 'string') {
        if (!value || value.length > 120) {
          throw new RangeError(`analytics parameter is out of bounds: ${key}`);
        }
        cleaned[key] = value;
      } else if (typeof value === 'boolean') {
        cleaned[key] = value;
      } else if (typeof value === 'number' && Number.isFinite(value)) {
        cleaned[key] = value;
      } else {
        throw new TypeError(`analytics parameter has an invalid value: ${key}`);
      }
    }
    return Object.freeze(cleaned);
  }

  function record(eventName, parameters) {
    if (!allowedEvents.has(eventName)) throw new TypeError(`unsupported analytics event: ${eventName}`);
    const params = cleanParameters(parameters);
    if (!enabled) return Object.freeze({ accepted: false, reason: 'disabled' });
    if (consent !== 'granted') {
      return Object.freeze({ accepted: false, reason: 'consent_required' });
    }
    if (typeof sink !== 'function') {
      return Object.freeze({ accepted: false, reason: 'sink_unconfigured' });
    }
    const event = Object.freeze({
      contractVersion: 1,
      name: eventName,
      params
    });
    try {
      sink(event);
    } catch {
      return Object.freeze({ accepted: false, reason: 'sink_failed' });
    }
    return Object.freeze({ accepted: true, reason: 'dispatched' });
  }

  function recordConfirmedNewsletterSignup(confirmation) {
    const valid = confirmation
      && typeof confirmation === 'object'
      && confirmation.status === 'confirmed'
      && typeof confirmation.providerEventId === 'string'
      && confirmation.providerEventId.length >= 8
      && confirmation.providerEventId.length <= 128;
    if (!valid) {
      return Object.freeze({ accepted: false, reason: 'provider_confirmation_required' });
    }
    return record('newsletter_signup', { source: 'provider_confirmation' });
  }

  return Object.freeze({
    EVENT_NAMES: eventNames,
    configure,
    disable,
    record,
    recordConfirmedNewsletterSignup,
    status: snapshot
  });
});
