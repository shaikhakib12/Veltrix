import { Command } from 'commander';
import { PLATFORM_INFO } from '@veltrix/shared';

export function createCli(): Command {
  const program = new Command();

  program
    .name('veltrix')
    .description(`${PLATFORM_INFO.name} — ${PLATFORM_INFO.tagline}\nHigh-performance SOC terminal operator interface.`)
    .version(PLATFORM_INFO.version);

  // Status Command
  program
    .command('status')
    .description('Check platform operational status and backend connectivity')
    .option('--json', 'Output raw JSON')
    .action(async (options) => {
      const statusData = {
        platform: PLATFORM_INFO.name,
        version: PLATFORM_INFO.version,
        tagline: PLATFORM_INFO.tagline,
        status: 'READY',
        mode: process.env.STORAGE_MODE || 'memory',
        backendUrl: process.env.API_BASE_URL || 'http://localhost:4000/api/v1',
      };

      if (options.json) {
        console.log(JSON.stringify(statusData, null, 2));
      } else {
        console.log(`\n========================================`);
        console.log(`  ${statusData.platform} — ${statusData.tagline}`);
        console.log(`  Version: ${statusData.version} | Mode: ${statusData.mode}`);
        console.log(`  Status: ${statusData.status}`);
        console.log(`========================================\n`);
      }
    });

  // Auth Subcommand Stub
  program
    .command('auth [action]')
    .description('Authenticate and manage analyst session credentials (login, status, logout)')
    .action((action) => {
      console.log(`[VELTRIX CLI] Auth command '${action || 'status'}' initialized (ready for Phase 3).`);
    });

  // Events Subcommand Stub
  program
    .command('events [action]')
    .description('Ingest, search, and tail normalized security telemetry')
    .action((action) => {
      console.log(`[VELTRIX CLI] Events command '${action || 'list'}' initialized (ready for Phase 4).`);
    });

  // Detect Subcommand Stub
  program
    .command('detect [action]')
    .description('Manage and dry-run 10 Sigma-inspired detection rules')
    .action((action) => {
      console.log(`[VELTRIX CLI] Detect command '${action || 'list'}' initialized (ready for Phase 5).`);
    });

  // Incidents Subcommand Stub
  program
    .command('incidents [action]')
    .description('List, inspect, and triage correlated security incidents')
    .action((action) => {
      console.log(`[VELTRIX CLI] Incidents command '${action || 'list'}' initialized (ready for Phase 5).`);
    });

  // Threat Intel Subcommand Stub
  program
    .command('intel [action]')
    .description('Query offline IOC database and inspect IP reputation')
    .action((action) => {
      console.log(`[VELTRIX CLI] Threat Intel command '${action || 'inspect'}' initialized (ready for Phase 5).`);
    });

  // Response Subcommand Stub
  program
    .command('response [action]')
    .description('Execute, approve, or rollback defensive SOAR containment workflows')
    .action((action) => {
      console.log(`[VELTRIX CLI] Defensive Response command '${action || 'list'}' initialized (ready for Phase 5).`);
    });

  // Simulate Subcommand Stub
  program
    .command('simulate [action]')
    .description('Trigger controlled cyberattack scenarios in Simulation Lab')
    .action((action) => {
      console.log(`[VELTRIX CLI] Attack Simulation command '${action || 'list'}' initialized (ready for Phase 6).`);
    });

  return program;
}

// Direct execution guard
if (process.argv[1]?.endsWith('index.js') || process.argv[1]?.endsWith('index.ts') || process.argv[1]?.endsWith('veltrix.js')) {
  const cli = createCli();
  cli.parse(process.argv);
}
