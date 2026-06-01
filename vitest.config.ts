import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

export default defineConfig({
  test: {
    projects: [
      {
        resolve: {
          alias: {
            'polarity-integration-utils': new URL(
              'node_modules/polarity-integration-utils/dist/lib/index.js',
              import.meta.url
            ).pathname
          }
        },
        test: {
          name: 'server',
          environment: 'node',
          include: ['test/**/*.test.ts'],
          exclude: ['test/web-components/**']
        }
      },
      {
        test: {
          name: 'browser',
          include: ['test/web-components/**/*.test.ts'],
          browser: {
            enabled: true,
            provider: playwright(),
            instances: [{ browser: 'chromium' }]
          }
        }
      }
    ]
  }
});
