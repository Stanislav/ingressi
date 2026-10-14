/**
 * Server-side render of the path field of a WAF exclusion: the input with its
 * "Starts with" / "Exactly" choice, the paths to pick from, the hint for a
 * path that holds an ID, and a problem with the path.
 */
import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { WafExclusionPathField } from '@/app/(dashboard)/waf/WafExclusionPathField';

const ITEM_PATH = '/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo';

function render(props: Partial<Parameters<typeof WafExclusionPathField>[0]> = {}): string {
  return renderToStaticMarkup(
    createElement(WafExclusionPathField, {
      id: 'p',
      path: ITEM_PATH,
      pathMatch: 'exact',
      onChange: () => {},
      requestPath: ITEM_PATH,
      ...props,
    })
  );
}

describe('WafExclusionPathField', () => {
  it('is an input named Path with the choice of how it matches', () => {
    const html = render();
    expect(html).toContain('for="p"');
    expect(html).toContain('(optional)');
    expect(html).toContain(`value="${ITEM_PATH}"`);
    expect(html).toContain('Starts with');
    expect(html).toContain('Exactly');
  });

  it('offers every path, each directory and the path itself, marking the one in use', () => {
    const html = render();
    expect(html).toContain('aria-label="Paths to choose from"');
    expect(html).toContain('>Any path</button>');
    expect(html).toContain('>/Items/</button>');
    expect(html).toContain(`>${ITEM_PATH}</button>`);
    // Only the exact path chip is pressed.
    expect(html.match(/aria-pressed="true"/g)).toHaveLength(1);
    expect(html).toMatch(new RegExp(`aria-pressed="true"[^>]*>${ITEM_PATH}</button>`));
  });

  it('marks every path when the path is empty', () => {
    const html = render({ path: '' });
    expect(html).toMatch(/aria-pressed="true"[^>]*>Any path<\/button>/);
  });

  it('says a path with an ID in it matches only that one, and offers the directory above', () => {
    const html = render();
    expect(html).toContain('The path has an ID in it, so it matches only that one.');
    expect(html).toContain('Use <span class="num">/Items/</span>');
    expect(render({ path: '/Items/', pathMatch: 'prefix' })).not.toContain('has an ID in it');
    expect(render({ path: '/api/public/otel/v1/traces', requestPath: '/api/public/otel/v1/traces' })).not.toContain('has an ID in it');
  });

  it('has no paths to pick from without a request path, and says what is wrong with the path', () => {
    const html = render({ path: 'Items', requestPath: null, error: 'The path must start with /' });
    expect(html).not.toContain('Paths to choose from');
    expect(html).toContain('role="alert"');
    expect(html).toContain('The path must start with /');
    expect(html).toContain('aria-invalid="true"');
    expect(html).toContain('aria-describedby="p-error"');
  });

  it('turns the match choice off while there is no path', () => {
    const html = render({ path: '' });
    expect(html.match(/role="radio"[^>]*disabled/g)).toHaveLength(2);
  });
});
