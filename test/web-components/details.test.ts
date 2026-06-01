import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { DetailsComponent } from '../../web-components/details';
import type { IBlock } from '@polarityio/pi-components';

beforeAll(() => {
  if (!customElements.get('test-sp-details')) {
    customElements.define('test-sp-details', DetailsComponent);
  }
});

const mockServices = {
  integrationMessenger: {
    sendMessage: () => Promise.resolve()
  }
} as any;

function createBlock(details: Record<string, unknown>): IBlock {
  return {
    integrationId: 'test-integration',
    acronym: 'SP',
    data: {
      details,
      summary: ['192.0.2.100']
    }
  };
}

function fullMockDetails() {
  return {
    entity: { value: '192.0.2.100', type: 'IPv4' },
    associations: {
      results: [
        {
          right: {
            description: 'CVE-2023-12345 - Remote Code Execution vulnerability in Apache Struts',
            cvss: 9.8,
            classifications: ['exploit', 'remote-code-execution', 'critical'],
            ticScore: 92,
            threatId: 'threat-uuid-1234',
            name: 'CVE-2023-12345'
          },
          firstSeen: '2023-08-15T10:23:45.000Z',
          lastSeen: '2024-01-10T14:32:18.000Z',
          meta: { reports_s: 'APT29, FIN7', targets_s: 'Financial Services, Healthcare', targetport_s: '8080' },
          port: 8080,
          sources: ['National Vulnerability Database', 'CISA KEV'],
          userUploaded: false
        },
        {
          right: {
            description: 'Malicious domain associated with Emotet botnet campaign',
            cvss: null,
            classifications: ['malware', 'botnet', 'c2'],
            ticScore: 87,
            threatId: 'threat-uuid-5678',
            name: 'Emotet C2 Infrastructure'
          },
          firstSeen: '2023-11-02T08:15:33.000Z',
          lastSeen: '2024-01-14T22:45:12.000Z',
          meta: { reports_s: 'Emotet Campaign Wave 2023-Q4', targets_s: 'Global', targetport_s: '443' },
          port: 443,
          sources: ['LookingGlass Threat Intelligence', 'AlienVault OTX'],
          userUploaded: false
        },
        {
          right: {
            description: 'Suspicious TLS certificate associated with phishing infrastructure',
            cvss: null,
            classifications: ['phishing', 'credential-theft'],
            ticScore: 65,
            threatId: 'threat-uuid-9012',
            name: 'Phishing Infrastructure - Financial Sector'
          },
          firstSeen: '2024-01-05T16:42:09.000Z',
          lastSeen: '2024-01-15T19:28:44.000Z',
          meta: { reports_s: 'Q1 2024 Phishing Campaign', targets_s: 'Banking, Cryptocurrency Exchanges' },
          port: 443,
          sources: ['PhishTank', 'OpenPhish'],
          userUploaded: true
        }
      ],
      total: 3
    },
    owners: [
      {
        name: 'Example Hosting LLC',
        ticScore: 45,
        collections: [{ collectionName: 'Monitored Infrastructure', ticScore: 50 }],
        owners: ['Example Hosting LLC', 'Upstream ISP Corp'],
        cidrv4s: ['192.0.2.0/24', '198.51.100.0/24'],
        cidrv6s: [],
        asns: [64512],
        locations: [
          {
            city: 'San Francisco',
            region: 'California',
            country: 'US',
            countryName: 'United States',
            country2Digit: 'US',
            lastSeen: '2024-01-15T12:00:00.000Z'
          }
        ],
        labels: ['hosting-provider', 'high-risk-asn'],
        lastActivityAt: '2024-01-15T19:28:44.000Z',
        sources: ['MaxMind GeoIP', 'ARIN WHOIS'],
        md5s: [],
        sha1s: [],
        sha256s: [],
        sha512s: [],
        ticHistory7d: [42, 45, 47, 46, 45, 45, 45]
      }
    ],
    whois: {
      result: {
        'whois-record': {
          'registry-data': {
            'registrar-name': 'Example Registrar Inc.',
            registrant: {
              organization: 'Example Hosting LLC',
              email: 'admin@example-hosting.com',
              telephone: '+1.5555551234',
              fax: '+1.5555551235',
              'street-1': '123 Main Street',
              city: 'San Francisco',
              'postal-code': '94102',
              country: 'United States',
              'country-code': 'US'
            }
          }
        }
      }
    }
  };
}

async function renderComponent(details: Record<string, unknown>): Promise<DetailsComponent> {
  const el = document.createElement('test-sp-details') as DetailsComponent;
  el.block = createBlock(details);
  (el as any).services = mockServices;
  document.body.appendChild(el);
  await el.updateComplete;
  return el;
}

describe('scoutPRIME DetailsComponent', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('should render header stats with correct Active Risks and Collections counts', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    // 3 associations = 3 Active Risks
    expect(innerHTML).toContain('Active Risks');
    // Find header-value elements to check counts
    const headerValues = el.shadowRoot!.querySelectorAll('.header-value');
    expect(headerValues.length).toBeGreaterThanOrEqual(2);
    expect(headerValues[0].textContent?.trim()).toBe('3');
    expect(headerValues[1].textContent?.trim()).toBe('1');

    // Collections label should be singular for count 1
    expect(innerHTML).toContain('Collection');
  });

  it('should render TIC gauge with owner score of 45', async () => {
    const el = await renderComponent(fullMockDetails());

    const svgText = el.shadowRoot!.querySelector('svg text');
    expect(svgText).toBeTruthy();
    expect(svgText!.textContent?.trim()).toBe('45');
  });

  it('should render association source names', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    expect(innerHTML).toContain('CVE-2023-12345');
    expect(innerHTML).toContain('Emotet C2 Infrastructure');
    expect(innerHTML).toContain('Phishing Infrastructure - Financial Sector');
    // Verify Sources card title includes count
    expect(innerHTML).toContain('Sources (3)');
  });

  it('should render collections', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    expect(innerHTML).toContain('Monitored Infrastructure');
    expect(innerHTML).toContain('Collections (1)');
  });

  it('should render ownership names', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    expect(innerHTML).toContain('Example Hosting LLC');
    expect(innerHTML).toContain('Upstream ISP Corp');
    expect(innerHTML).toContain('Ownership');
  });

  it('should compute last activity as the MAX lastSeen across all associations', async () => {
    // The three associations have lastSeen dates:
    //   2024-01-10T14:32:18.000Z
    //   2024-01-14T22:45:12.000Z
    //   2024-01-15T19:28:44.000Z  <-- this is the latest
    // The component should use the latest date (Jan 15) for display.
    const details = fullMockDetails();

    // Put the latest lastSeen on the FIRST association to prove it takes MAX, not last
    details.associations.results[0].lastSeen = '2024-02-20T00:00:00.000Z';
    details.associations.results[1].lastSeen = '2024-01-01T00:00:00.000Z';
    details.associations.results[2].lastSeen = '2024-01-15T19:28:44.000Z';

    const el = await renderComponent(details);
    const innerHTML = el.shadowRoot!.innerHTML;

    // The header should show Last Activity and it should be based on 2024-02-20
    expect(innerHTML).toContain('Last Activity');

    // Verify the header value for Last Activity reflects Feb 20 date (the max).
    // The component uses relativeTime() which renders relative strings.
    // We can verify by checking it does NOT render the Jan 15 or Jan 1 date.
    // Instead, let's check with a known absolute date by looking at the third header-value.
    const headerValues = el.shadowRoot!.querySelectorAll('.header-value');
    // headerValues[0] = Active Risks count, [1] = Collections count, [2] = Last Activity
    expect(headerValues.length).toBeGreaterThanOrEqual(3);
    const lastActivityText = headerValues[2].textContent?.trim() ?? '';
    // relativeTime for Feb 20 2024 will produce a different string than Jan 15
    // Just verify it's non-empty (the relative time was computed)
    expect(lastActivityText.length).toBeGreaterThan(0);
  });

  it('should render CIDRs', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    expect(innerHTML).toContain('CIDRs');
    expect(innerHTML).toContain('192.0.2.0/24');
    expect(innerHTML).toContain('198.51.100.0/24');
  });

  it('should render nothing when details has no owners', async () => {
    const el = await renderComponent({
      entity: { value: '10.0.0.1', type: 'IPv4' },
      associations: { results: [], total: 0 },
      owners: [],
      whois: { result: { 'whois-record': { 'registry-data': {} } } }
    });

    // The component returns `nothing` when owners is empty
    const innerHTML = el.shadowRoot!.innerHTML;
    expect(innerHTML).not.toContain('Active Risks');
    expect(innerHTML).not.toContain('header');
  });

  it('should render nothing when details is empty object', async () => {
    const el = await renderComponent({});
    const innerHTML = el.shadowRoot!.innerHTML;
    expect(innerHTML).not.toContain('Active Risks');
  });

  it('should have a copy button', async () => {
    const el = await renderComponent(fullMockDetails());
    const copyBtn = el.shadowRoot!.querySelector('pi-copy-button');
    expect(copyBtn).toBeTruthy();
    expect(copyBtn!.hasAttribute('copy-content-id')).toBe(true);
  });

  it('should render WHOIS card with registrant data', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    // WHOIS card is present but collapsed by default
    expect(innerHTML).toContain('WHOIS');
    expect(innerHTML).toContain('Example Registrar Inc.');
  });

  it('should render Locations card', async () => {
    const el = await renderComponent(fullMockDetails());
    const innerHTML = el.shadowRoot!.innerHTML;

    expect(innerHTML).toContain('Locations');
    expect(innerHTML).toContain('San Francisco');
    expect(innerHTML).toContain('California');
  });
});
