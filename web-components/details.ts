import { css, html, nothing, svg, unsafeCSS } from 'lit';
import { property, state } from 'lit/decorators.js';
import { IntegrationComponentBase, IBlock, typographyCSS } from '@polarityio/pi-components';

// ── Interfaces ──────────────────────────────────────────────────────────────

interface AssociationResult {
  right: {
    description: string;
    cvss: number;
    classifications: string[];
    ticScore: number;
    threatId: string;
    name: string;
  };
  firstSeen: string;
  lastSeen: string;
  meta: {
    reports_s?: string;
    targets_s?: string;
    targetport_s?: string;
  };
  port: number;
  sources: string[];
  userUploaded: boolean;
}

interface OwnerLocation {
  city: string;
  region: string;
  country: string;
  countryName: string;
  country2Digit: string;
  lastSeen: string;
}

interface OwnerCollection {
  collectionName: string;
  ticScore: number;
}

interface Owner {
  name: string;
  ticScore: number;
  collections: OwnerCollection[];
  owners: string[];
  cidrv4s: string[];
  cidrv6s: string[];
  asns: number[];
  locations: OwnerLocation[];
  labels: string[];
  lastActivityAt: string;
  sources: string[];
  md5s: string[];
  sha1s: string[];
  sha256s: string[];
  sha512s: string[];
  ticHistory7d: number[];
}

interface WhoisRegistrant {
  organization: string;
  email: string;
  telephone: string;
  fax: string;
  'street-1': string;
  city: string;
  'postal-code': string;
  country: string;
  'country-code': string;
}

interface WhoisRegistryData {
  'registrar-name': string;
  registrant: WhoisRegistrant;
}

interface ScoutPrimeDetails {
  entity: { value: string; type: string };
  associations: { results: AssociationResult[]; total: number };
  owners: Owner[];
  whois: {
    result: {
      'whois-record': {
        'registry-data': WhoisRegistryData;
      };
    };
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const RED = '#fa5843';
const YELLOW = '#ffc15d';
const GREEN = '#7dd21b';

function getThreatColor(ticScore: number): string {
  if (ticScore >= 75) return RED;
  if (ticScore >= 50) return YELLOW;
  return GREEN;
}

function formatDate(iso: string): string {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

function relativeTime(iso: string): string {
  if (!iso) return '';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diffMs = now - then;
  const diffSec = Math.round(diffMs / 1000);
  const diffMin = Math.round(diffSec / 60);
  const diffHr = Math.round(diffMin / 60);
  const diffDay = Math.round(diffHr / 24);
  const diffMonth = Math.round(diffDay / 30);
  const diffYear = Math.round(diffDay / 365);

  try {
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    if (Math.abs(diffSec) < 60) return rtf.format(-diffSec, 'second');
    if (Math.abs(diffMin) < 60) return rtf.format(-diffMin, 'minute');
    if (Math.abs(diffHr) < 24) return rtf.format(-diffHr, 'hour');
    if (Math.abs(diffDay) < 30) return rtf.format(-diffDay, 'day');
    if (Math.abs(diffMonth) < 12) return rtf.format(-diffMonth, 'month');
    return rtf.format(-diffYear, 'year');
  } catch {
    return formatDate(iso);
  }
}

// ── Component ───────────────────────────────────────────────────────────────

export class DetailsComponent extends IntegrationComponentBase {
  @property({ type: Object }) block: IBlock = {
    integrationId: '',
    acronym: '',
    data: { details: {} as any, summary: [] }
  };

  @state() private _showLocations = false;
  @state() private _showWhois = false;

  static styles = [
    unsafeCSS(typographyCSS),
    css`
      :host {
        display: block;
        font-size: var(--pi-size-font-sm, 0.875rem);
        color: var(--pi-color-font-primary, #333);
      }

      /* ── Copy button ── */
      .copy-btn-container {
        position: absolute;
        right: 10px;
        top: 7px;
      }

      /* ── Header stats row ── */
      .header {
        display: flex;
        align-items: center;
        padding: 0 var(--pi-size-spacing-xs, 4px);
      }

      .header-stats {
        display: flex;
        flex: 1;
        gap: var(--pi-size-spacing-md, 1rem);
      }

      .header-item {
        text-align: left;
      }

      .header-value {
        font-weight: bold;
        font-size: 14px;
      }

      .header-key {
        margin-top: var(--pi-size-spacing-xs, 4px);
        color: var(--pi-color-font-secondary, #888);
      }

      /* ── TIC Gauge ── */
      .tic-gauge-container {
        width: 60px;
        height: 60px;
        flex-shrink: 0;
      }

      /* ── Cards layout ── */
      .cards {
        display: flex;
        flex-direction: column;
        gap: var(--pi-size-spacing-xs, 4px);
        margin-top: var(--pi-size-spacing-sm, 0.5rem);
      }

      /* ── Association items ── */
      .association-info {
        margin-top: var(--pi-size-spacing-sm, 0.5rem);
        padding-bottom: var(--pi-size-spacing-sm, 0.5rem);
        border-bottom: 1px solid var(--pi-color-border-element, #efefef);
      }

      .association-info:last-child {
        border-bottom: none;
      }

      .association-name {
        font-weight: 500;
        margin-bottom: var(--pi-size-spacing-xxs, 0.125rem);
      }

      /* ── Collection / Ownership items ── */
      .ownership-item {
        margin-bottom: var(--pi-size-spacing-xs, 4px);
        border: 1px solid var(--pi-color-border-element, #efefef);
        padding: var(--pi-size-spacing-xxs, 0.125rem) var(--pi-size-spacing-xs, 4px);
        border-radius: var(--pi-size-radius-base, 4px);
      }

      .emphasize-text {
        font-weight: 500;
      }

      /* ── Location card ── */
      .location-card {
        padding: var(--pi-size-spacing-sm, 0.5rem) 0;
        border-bottom: 1px solid var(--pi-color-border-element, #efefef);
      }

      .location-card:last-child {
        border-bottom: none;
      }
    `
  ];

  private _copyContentId = `copy-content-${Array.from(
    crypto.getRandomValues(new Uint8Array(16)),
    (b) => b.toString(16).padStart(2, '0')
  ).join('')}`;

  private _originalExpandedState = new Map<string, boolean>();

  private _beforeCopy = async () => {
    this.shadowRoot?.querySelectorAll('pi-card').forEach((card: any) => {
      this._originalExpandedState.set(card.getAttribute('card-title') ?? '', card.expanded);
      card.expanded = true;
    });
    await this.updateComplete;
  };

  private _afterCopy = async () => {
    this.shadowRoot?.querySelectorAll('pi-card').forEach((card: any) => {
      const title = card.getAttribute('card-title') ?? '';
      const prev = this._originalExpandedState.get(title);
      if (prev !== undefined) card.expanded = prev;
    });
    this._originalExpandedState.clear();
  };

  // ── Computed helpers ────────────────────────────────────────────────────

  private get _details(): ScoutPrimeDetails {
    return this.block.data.details as ScoutPrimeDetails;
  }

  private get _owners(): Owner[] {
    return this._details?.owners ?? [];
  }

  private get _associations(): AssociationResult[] {
    return this._details?.associations?.results ?? [];
  }

  private get _ticScore(): number {
    return this._owners.reduce((sum, o) => sum + o.ticScore, 0);
  }

  private get _collections(): OwnerCollection[] {
    return this._owners.reduce<OwnerCollection[]>((acc, o) => acc.concat(o.collections ?? []), []);
  }

  private get _lastActivityAt(): string {
    const results = this._associations;
    if (results.length === 0) return '';
    return results[results.length - 1].lastSeen;
  }

  private get _hasLocationData(): boolean {
    return this._owners.some((o) => o.locations && o.locations.length > 0);
  }

  private get _whoisRecord(): WhoisRegistryData | null {
    try {
      return this._details.whois.result['whois-record']['registry-data'];
    } catch {
      return null;
    }
  }

  private get _whoisRegistrant(): WhoisRegistrant | null {
    return this._whoisRecord?.registrant ?? null;
  }

  // ── SVG TIC Gauge ─────────────────────────────────────────────────────

  private _renderGauge() {
    const radius = 20;
    const strokeWidth = 4;
    const circumference = 2 * Math.PI * radius;
    const score = this._ticScore;
    const offset = circumference * (1 - score / 100);
    const color = getThreatColor(score);

    return html`
      <div class="tic-gauge-container">
        <svg x="0" y="0" width="100%" height="100%" viewBox="0 0 55 50">
          <g transform="translate(28,25)">
            ${svg`
              <circle
                r="${radius}"
                stroke="#eee"
                transform="rotate(-90)"
                fill="#fff"
                stroke-width="${strokeWidth}"
                cx="0"
                cy="0"
              ></circle>
              <circle
                stroke-dasharray="${circumference}"
                r="${radius}"
                stroke="${color}"
                transform="rotate(-90)"
                fill="none"
                stroke-dashoffset="${offset}"
                stroke-width="${strokeWidth}"
                cx="0"
                cy="0"
              ></circle>
              <text
                text-anchor="middle"
                x="0"
                y="5"
                fill="${color}"
                font-size="13"
              >${score}</text>
            `}
          </g>
        </svg>
      </div>
    `;
  }

  // ── Section renderers ─────────────────────────────────────────────────

  private _renderAssociations() {
    const associations = this._associations;
    if (associations.length === 0) return nothing;

    return html`
      <pi-card card-title="Sources (${associations.length})" collapsible expanded>
        ${associations.map(
          (a) => html`
            <div class="association-info">
              <div class="association-name">${a.right.name}</div>
              ${a.sources.map(
                (src) => html`<pi-key-value key="Source" value=${src}></pi-key-value>`
              )}
              <pi-key-value key="TIC Score" value=${String(a.right.ticScore)}></pi-key-value>
              <pi-key-value key="First Seen" value=${formatDate(a.firstSeen)}></pi-key-value>
              <pi-key-value key="Last Seen" value=${formatDate(a.lastSeen)}></pi-key-value>
              <pi-key-value
                key="Classification"
                value=${(a.right.classifications ?? []).join(', ')}
              ></pi-key-value>
              ${a.meta.reports_s
                ? html`<pi-key-value key="Reports" value=${a.meta.reports_s}></pi-key-value>`
                : nothing}
              ${a.meta.targets_s
                ? html`<pi-key-value key="Targets" value=${a.meta.targets_s}></pi-key-value>`
                : nothing}
              ${a.meta.targetport_s
                ? html`<pi-key-value key="Targetport" value=${a.meta.targetport_s}></pi-key-value>`
                : nothing}
            </div>
          `
        )}
      </pi-card>
    `;
  }

  private _renderCollections() {
    const collections = this._collections;
    if (collections.length === 0) return nothing;

    return html`
      <pi-card card-title="Collections (${collections.length})" collapsible expanded>
        ${collections.map(
          (c) => html`
            <div class="ownership-item">
              <div class="emphasize-text">${c.collectionName}</div>
              <div>TIC Score: ${c.ticScore}</div>
            </div>
          `
        )}
      </pi-card>
    `;
  }

  private _renderOwnership() {
    const allOwnerNames = this._owners.reduce<string[]>((acc, o) => acc.concat(o.owners ?? []), []);
    if (allOwnerNames.length === 0) return nothing;

    return html`
      <pi-card card-title="Ownership" collapsible expanded>
        ${allOwnerNames.map(
          (name) => html`
            <div class="ownership-item">
              <span>${name}</span>
            </div>
          `
        )}
      </pi-card>
    `;
  }

  private _renderCidrs() {
    const allCidrs = this._owners.reduce<string[]>((acc, o) => acc.concat(o.cidrv4s ?? []), []);
    if (allCidrs.length === 0) return nothing;

    return html`
      <pi-card card-title="CIDRs" collapsible expanded>
        ${allCidrs.map(
          (cidr) => html`
            <div class="ownership-item">
              <span>${cidr}</span>
            </div>
          `
        )}
      </pi-card>
    `;
  }

  private _renderLocations() {
    if (!this._hasLocationData) return nothing;

    return html`
      <pi-card
        card-title="Locations"
        collapsible
        ?expanded=${this._showLocations}
        @pi-card-toggle=${(e: CustomEvent) => {
          this._showLocations = e.detail.expanded;
        }}
      >
        ${this._owners.map((owner) =>
          (owner.locations ?? []).map(
            (loc) => html`
              <div class="location-card">
                <pi-key-value key="City" value=${loc.city}></pi-key-value>
                <pi-key-value key="Country" value=${loc.country}></pi-key-value>
                <pi-key-value key="Region" value=${loc.region}></pi-key-value>
                <pi-key-value key="Country Name" value=${loc.countryName}></pi-key-value>
                <pi-key-value key="Country Digit" value=${loc.country2Digit}></pi-key-value>
                <pi-key-value key="Last Seen" value=${formatDate(loc.lastSeen)}></pi-key-value>
              </div>
            `
          )
        )}
      </pi-card>
    `;
  }

  private _renderWhois() {
    const record = this._whoisRecord;
    const registrant = this._whoisRegistrant;
    if (!record && !registrant) return nothing;

    return html`
      <pi-card
        card-title="WHOIS"
        collapsible
        ?expanded=${this._showWhois}
        @pi-card-toggle=${(e: CustomEvent) => {
          this._showWhois = e.detail.expanded;
        }}
      >
        ${record?.['registrar-name']
          ? html`<pi-key-value
              key="Registrar Name"
              value=${record['registrar-name']}
            ></pi-key-value>`
          : nothing}
        ${registrant?.organization
          ? html`<pi-key-value key="Organization" value=${registrant.organization}></pi-key-value>`
          : nothing}
        ${registrant?.city
          ? html`<pi-key-value key="City" value=${registrant.city}></pi-key-value>`
          : nothing}
        ${registrant?.['country-code']
          ? html`<pi-key-value
              key="Country Code"
              value=${registrant['country-code']}
            ></pi-key-value>`
          : nothing}
        ${registrant?.['postal-code']
          ? html`<pi-key-value key="Postal Code" value=${registrant['postal-code']}></pi-key-value>`
          : nothing}
        ${registrant?.['street-1']
          ? html`<pi-key-value key="Street" value=${registrant['street-1']}></pi-key-value>`
          : nothing}
        ${registrant?.country
          ? html`<pi-key-value key="Country" value=${registrant.country}></pi-key-value>`
          : nothing}
        ${registrant?.fax
          ? html`<pi-key-value key="Fax" value=${registrant.fax}></pi-key-value>`
          : nothing}
        ${registrant?.email
          ? html`<pi-key-value key="Email" value=${registrant.email}></pi-key-value>`
          : nothing}
        ${registrant?.telephone
          ? html`<pi-key-value key="Telephone" value=${registrant.telephone}></pi-key-value>`
          : nothing}
      </pi-card>
    `;
  }

  // ── Main render ───────────────────────────────────────────────────────

  render() {
    const d = this._details;
    if (!d || !d.owners || d.owners.length === 0) return nothing;

    const associations = this._associations;
    const collections = this._collections;

    return html`
      <div style="position: relative;">
        <div class="copy-btn-container">
          <pi-copy-button
            copy-content-id=${this._copyContentId}
            condensed
            button-type="tertiary"
            button-text=""
            .beforeCopy=${this._beforeCopy}
            .afterCopy=${this._afterCopy}
          ></pi-copy-button>
        </div>

        <div id=${this._copyContentId}>
          <!-- Header stats + TIC Gauge -->
          <div class="header">
            <div class="header-stats">
              <div class="header-item">
                <div class="header-value">${associations.length}</div>
                <div class="header-key">Active Risks</div>
              </div>
              <div class="header-item">
                <div class="header-value">${collections.length}</div>
                <div class="header-key">
                  ${collections.length === 1 ? 'Collection' : 'Collections'}
                </div>
              </div>
              ${associations.length > 0
                ? html`
                    <div class="header-item">
                      <div class="header-value">${relativeTime(this._lastActivityAt)}</div>
                      <div class="header-key">Last Activity</div>
                    </div>
                  `
                : nothing}
            </div>
            ${this._renderGauge()}
          </div>

          <!-- Detail cards -->
          <div class="cards">
            ${this._renderAssociations()} ${this._renderCollections()} ${this._renderOwnership()}
            ${this._renderCidrs()} ${this._renderLocations()} ${this._renderWhois()}
          </div>
        </div>
      </div>
    `;
  }
}
