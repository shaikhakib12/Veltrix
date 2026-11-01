// Cloudflare Worker: veltrix-edge-worker.js
// Non-blocking edge telemetry forwarder for VELTRIX

export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    const response = await fetch(request);
    const duration = Date.now() - startTime;

    // Asynchronously dispatch security event to VELTRIX without delaying client response
    ctx.waitUntil((async () => {
      const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
      const cfRay = request.headers.get('cf-ray');
      const threatScore = request.cf?.threatScore || 0;

      const eventPayload = {
        timestamp: new Date().toISOString(),
        eventType: threatScore > 10 ? 'web.attack.bot' : 'web.request.normal',
        severity: threatScore > 50 ? 'HIGH' : threatScore > 10 ? 'MEDIUM' : 'LOW',
        category: 'NETWORK',
        sourceIp: clientIp,
        sourceSystem: 'edge:cloudflare',
        metadata: {
          siteId: env.VELTRIX_SITE_ID,
          domain: new URL(request.url).hostname,
          httpMethod: request.method,
          requestUri: request.url,
          httpStatus: response.status,
          responseTimeMs: duration,
          userAgent: request.headers.get('user-agent'),
          cfRay: cfRay,
          asn: request.cf?.asn,
          country: request.cf?.country,
          wafAction: threatScore > 50 ? 'BLOCK' : 'ALLOW'
        }
      };

      try {
        await fetch(`${env.VELTRIX_ENDPOINT}/api/v1/events`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-organization-id': env.VELTRIX_ORG_ID,
            'x-api-key': env.VELTRIX_API_KEY
          },
          body: JSON.stringify(eventPayload)
        });
      } catch (err) {
        // Fail-open: Edge forwarder errors do not affect origin response
      }
    })());

    return response;
  }
};
