import { describe, expect, it, vi } from 'vitest';

vi.mock('@/src/lib/api-auth', () => ({
  requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))),
  requireApiAdmin: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
  apiErrorResponse: vi.fn(),
}));

import { GET } from '@/app/api/v1/openapi.json/route';

describe('OpenAPI: certificate overview', () => {
  it('documents the endpoint and every reference resolves', async () => {
    const doc = await (await GET({ headers: { get: () => null } } as never)).json();
    const path = doc.paths['/api/v1/certificates/overview'];
    expect(Object.keys(path)).toEqual(['get']);
    expect(path.get.tags).toEqual(['Certificates']);
    expect(path.get.description).toMatch(/certificates:read/);
    expect(path.get.parameters).toBeUndefined();

    const row = doc.components.schemas.CertificateOverviewRow;
    expect(row.properties.renewal.properties.state.enum).toEqual(
      expect.arrayContaining(['scheduled', 'due', 'overdue', 'expired', 'manual', 'replace_soon', 'pending', 'missing', 'unknown', 'inactive'])
    );
    expect(row.properties.issuanceError.properties).toHaveProperty('message');
    expect(row.required).toEqual(expect.arrayContaining(['checkedAt', 'issuanceError']));
    expect(Object.keys(row.properties)).not.toContain('certificatePem');

    const documented = JSON.stringify([path, doc.components.schemas.CertificateOverview, row]);
    const refs = documented.match(/"\$ref":"#\/components\/[^"]+"/g) ?? [];
    expect(refs.length).toBeGreaterThan(2);
    for (const ref of new Set(refs)) {
      const parts = JSON.parse(`{${ref}}`).$ref.slice('#/'.length).split('/');
      expect(parts.reduce((node: Record<string, unknown> | undefined, key: string) => node?.[key] as Record<string, unknown> | undefined, doc), ref).toBeDefined();
    }
  });
});
