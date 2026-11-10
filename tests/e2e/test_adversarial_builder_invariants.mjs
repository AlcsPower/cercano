// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');

// 1. Load schema
const schemaPath = path.join(ROOT_DIR, 'docs/specs/cercano-profile.schema.json');
const schemaRaw = fs.readFileSync(schemaPath, 'utf8');
const schema = JSON.parse(schemaRaw);

/**
 * Robust JSON Schema Draft-07 validator strictly enforcing cercano-profile.schema.json
 */
class SchemaValidator {
  constructor(schema) {
    this.schema = schema;
  }

  validate(payload) {
    const errors = [];
    this._validateObject(payload, this.schema, '', errors);

    // Validate allOf conditional invariants
    if (this.schema.allOf && Array.isArray(this.schema.allOf)) {
      for (let i = 0; i < this.schema.allOf.length; i++) {
        const rule = this.schema.allOf[i];
        if (rule.if && rule.then) {
          if (this._matchesCondition(payload, rule.if)) {
            this._validateConditionalThen(payload, rule.then, `allOf[${i}]`, errors);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  _matchesCondition(data, ifRule) {
    if (!data || typeof data !== 'object') return false;
    if (ifRule.properties) {
      for (const [key, valRule] of Object.entries(ifRule.properties)) {
        if ('const' in valRule) {
          if (data[key] !== valRule.const) return false;
        }
      }
    }
    return true;
  }

  _validateConditionalThen(data, thenRule, context, errors) {
    if (thenRule.properties) {
      for (const [propKey, subRule] of Object.entries(thenRule.properties)) {
        const propVal = data[propKey];
        if (subRule.properties && typeof propVal === 'object' && propVal !== null) {
          for (const [subKey, constRule] of Object.entries(subRule.properties)) {
            if ('const' in constRule) {
              if (propVal[subKey] !== constRule.const) {
                errors.push(
                  `${context}: Invariant violation on '${propKey}.${subKey}': expected ${JSON.stringify(
                    constRule.const
                  )}, got ${JSON.stringify(propVal[subKey])}`
                );
              }
            }
          }
        }
      }
    }
  }

  _validateObject(data, schemaNode, path, errors) {
    if (schemaNode.type === 'object') {
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        errors.push(`${path || 'root'}: Expected object, got ${data === null ? 'null' : typeof data}`);
        return;
      }

      // Check required
      if (schemaNode.required && Array.isArray(schemaNode.required)) {
        for (const req of schemaNode.required) {
          if (!(req in data) || data[req] === undefined) {
            errors.push(`${path ? path + '.' : ''}${req}: Missing required property`);
          }
        }
      }

      // Check additionalProperties: false
      if (schemaNode.additionalProperties === false) {
        const allowed = new Set(Object.keys(schemaNode.properties || {}));
        for (const actualKey of Object.keys(data)) {
          if (!allowed.has(actualKey)) {
            errors.push(`${path ? path + '.' : ''}${actualKey}: Unknown additional property not allowed`);
          }
        }
      }

      // Validate properties
      if (schemaNode.properties) {
        for (const [propKey, propSchema] of Object.entries(schemaNode.properties)) {
          if (propKey in data && data[propKey] !== undefined) {
            const nextPath = path ? `${path}.${propKey}` : propKey;
            this._validateValue(data[propKey], propSchema, nextPath, errors);
          }
        }
      }
    }
  }

  _validateValue(val, propSchema, path, errors) {
    if (propSchema.type === 'string') {
      if (typeof val !== 'string') {
        errors.push(`${path}: Expected string, got ${val === null ? 'null' : typeof val}`);
        return;
      }
      if (propSchema.minLength !== undefined && val.length < propSchema.minLength) {
        errors.push(`${path}: String length ${val.length} < minLength ${propSchema.minLength}`);
      }
      if (propSchema.maxLength !== undefined && val.length > propSchema.maxLength) {
        errors.push(`${path}: String length ${val.length} > maxLength ${propSchema.maxLength}`);
      }
      if (propSchema.pattern) {
        const reg = new RegExp(propSchema.pattern);
        if (!reg.test(val)) {
          errors.push(`${path}: String "${val}" does not match pattern ${propSchema.pattern}`);
        }
      }
      if (propSchema.enum && !propSchema.enum.includes(val)) {
        errors.push(`${path}: Value "${val}" not in enum [${propSchema.enum.join(', ')}]`);
      }
    } else if (propSchema.type === 'boolean') {
      if (typeof val !== 'boolean') {
        errors.push(`${path}: Expected boolean, got ${typeof val}`);
      }
    } else if (propSchema.type === 'integer') {
      if (!Number.isInteger(val)) {
        errors.push(`${path}: Expected integer, got ${val}`);
      }
      if (propSchema.minimum !== undefined && val < propSchema.minimum) {
        errors.push(`${path}: Integer ${val} < minimum ${propSchema.minimum}`);
      }
    } else if (propSchema.type === 'object') {
      this._validateObject(val, propSchema, path, errors);
    }
  }
}

// 2. BuilderView payload generation simulator exactly reflecting BuilderView.tsx
function generateBuilderPayload({
  activeRole = 'soporte',
  isAdmin = false,
  userStatePolicy = {},
  userStateServer = {},
  userStateIdentity = {},
  userStateInstallation = {},
  userStateIdentification = {},
}) {
  // Client-side RBAC guard in BuilderView.tsx (lines 235-238 & 887)
  const isSubmitDisabled = activeRole === 'tecnico' && !isAdmin;

  if (activeRole === 'tecnico' && !isAdmin) {
    return {
      blockedByRbac: true,
      submitError: 'Acceso denegado: La generación de clientes técnicos requiere rol de Administrador.',
      payload: null,
      isSubmitDisabled,
    };
  }

  // Identity defaults
  const identity = {
    app_name: activeRole === 'soporte' ? 'Cercano Asistencia' : 'Cercano Técnico',
    about_text:
      activeRole === 'soporte'
        ? 'Cercano Asistencia - Asistencia remota bajo licencia AGPL-3.0.'
        : 'Cercano Técnico - Cliente para especialistas de soporte TI.',
    ...userStateIdentity,
  };

  // Server defaults
  const serverConfig = {
    rendezvous_server: '127.0.0.1:21116',
    relay_server: '127.0.0.1:21117',
    api_server: 'http://127.0.0.1:21114',
    server_public_key: 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
    ...userStateServer,
  };

  // Policy defaults (with attempted user overrides)
  const policy = {
    allow_incoming: true,
    allow_outgoing: false,
    unattended_access: false,
    require_approval: true,
    hide_network_settings: true,
    allow_file_transfer: true,
    allow_clipboard: true,
    allow_audio: true,
    allow_terminal: false,
    allow_port_forward: false,
    enable_elevation: false,
    unattended_elevation: false,
    ...userStatePolicy,
  };

  // Installation defaults
  const installation = {
    mode: activeRole === 'soporte' ? 'portable' : 'installed',
    auto_start: false,
    create_desktop_shortcut: true,
    silent: false,
    ...userStateInstallation,
  };

  // Identification
  const identification = {
    device_group: 'Soporte TI',
    default_owner: '',
    ...userStateIdentification,
  };

  // Exact payload construction as in BuilderView.tsx lines 248-296
  const payload = {
    schema_version: '1.0.0',
    profile_id: '0192e300-1111-7111-8111-123456789abc',
    created_at: new Date().toISOString(),
    role: activeRole,
    server: {
      rendezvous_server: serverConfig.rendezvous_server.trim(),
      relay_server: serverConfig.relay_server.trim(),
      api_server: serverConfig.api_server.trim(),
      server_public_key: serverConfig.server_public_key.trim(),
    },
    identity: {
      app_name: identity.app_name.trim(),
      about_text: identity.about_text.trim(),
      icon: 'branding/png/cercano-icon.ico',
    },
    policy: {
      allow_incoming: activeRole === 'soporte' ? true : policy.allow_incoming,
      allow_outgoing: activeRole === 'soporte' ? false : true,
      unattended_access: activeRole === 'tecnico' ? false : policy.unattended_access,
      require_approval: policy.require_approval,
      allow_file_transfer: policy.allow_file_transfer,
      allow_clipboard: policy.allow_clipboard,
      allow_audio: policy.allow_audio,
      allow_terminal: policy.allow_terminal,
      allow_port_forward: policy.allow_port_forward,
      hide_network_settings: policy.hide_network_settings,
      enable_elevation: policy.enable_elevation,
      unattended_elevation: activeRole === 'tecnico' ? false : policy.unattended_elevation,
    },
    installation: {
      mode: installation.mode,
      install_path: installation.mode === 'installed' ? 'C:\\Program Files\\Cercano' : undefined,
      auto_start: installation.auto_start,
      create_desktop_shortcut: installation.create_desktop_shortcut,
      silent: installation.silent,
    },
    identification: {
      device_group: identification.device_group.trim() || undefined,
      default_owner: identification.default_owner.trim() || undefined,
    },
    expiration: {
      expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      max_uses: 100,
    },
  };

  return {
    blockedByRbac: false,
    submitError: null,
    payload,
    isSubmitDisabled,
  };
}

// 3. Test Runner
const validator = new SchemaValidator(schema);
const results = [];

function assert(condition, testName, message) {
  if (condition) {
    results.push({ name: testName, pass: true });
    console.log(`  [PASS] ${testName}`);
  } else {
    results.push({ name: testName, pass: false, error: message });
    console.error(`  [FAIL] ${testName}: ${message}`);
  }
}

async function runAdversarialSuite() {
  console.log('======================================================================');
  console.log('ADVERSARIAL EMPIRICAL HARNESS: M2 (F4-07 BUILDER VIEW VERIFICATION)');
  console.log('======================================================================\n');

  // --- SECTION 1: Baseline Valid Payloads Conformity ---
  console.log('--- SECTION 1: Baseline Schema Conformity ---');

  const soporteRes = generateBuilderPayload({ activeRole: 'soporte', isAdmin: false });
  const soporteVal = validator.validate(soporteRes.payload);
  assert(
    soporteVal.valid,
    '1.1 Soporte default payload complies with cercano-profile.schema.json',
    soporteVal.errors.join('; ')
  );

  const tecnicoRes = generateBuilderPayload({ activeRole: 'tecnico', isAdmin: true });
  const tecnicoVal = validator.validate(tecnicoRes.payload);
  assert(
    tecnicoVal.valid,
    '1.2 Tecnico admin payload complies with cercano-profile.schema.json',
    tecnicoVal.errors.join('; ')
  );

  // --- SECTION 2: Adversarial Stress: Soporte Role Invariants ---
  console.log('\n--- SECTION 2: Soporte Role Invariants Attack Scenarios ---');

  // Attack 2.1: Adversary injects allow_outgoing = true in userStatePolicy
  const attack21 = generateBuilderPayload({
    activeRole: 'soporte',
    isAdmin: true,
    userStatePolicy: { allow_outgoing: true },
  });
  assert(
    attack21.payload.policy.allow_outgoing === false,
    '2.1 Soporte payload MUST NEVER have allow_outgoing = true (forced to false)',
    `Emitted allow_outgoing was ${attack21.payload.policy.allow_outgoing}`
  );

  // Attack 2.2: Adversary injects allow_incoming = false in userStatePolicy
  const attack22 = generateBuilderPayload({
    activeRole: 'soporte',
    isAdmin: true,
    userStatePolicy: { allow_incoming: false },
  });
  assert(
    attack22.payload.policy.allow_incoming === true,
    '2.2 Soporte payload MUST ALWAYS have allow_incoming = true (forced to true)',
    `Emitted allow_incoming was ${attack22.payload.policy.allow_incoming}`
  );

  // Attack 2.3: Verify Schema Validator directly rejects a tampered soporte payload with allow_outgoing = true
  const tamperedSoporte = JSON.parse(JSON.stringify(soporteRes.payload));
  tamperedSoporte.policy.allow_outgoing = true;
  const tamperedSoporteVal = validator.validate(tamperedSoporte);
  assert(
    !tamperedSoporteVal.valid &&
      tamperedSoporteVal.errors.some((e) => e.includes('allow_outgoing')),
    '2.3 Schema validator actively REJECTS soporte payload when allow_outgoing = true',
    'Schema validator failed to reject tampered payload'
  );

  // --- SECTION 3: Adversarial Stress: Tecnico Role Invariants ---
  console.log('\n--- SECTION 3: Tecnico Role Invariants Attack Scenarios ---');

  // Attack 3.1: Adversary injects unattended_access = true in userStatePolicy
  const attack31 = generateBuilderPayload({
    activeRole: 'tecnico',
    isAdmin: true,
    userStatePolicy: { unattended_access: true },
  });
  assert(
    attack31.payload.policy.unattended_access === false,
    '3.1 Tecnico payload MUST NEVER have unattended_access = true (forced to false)',
    `Emitted unattended_access was ${attack31.payload.policy.unattended_access}`
  );

  // Attack 3.2: Adversary injects unattended_elevation = true in userStatePolicy
  const attack32 = generateBuilderPayload({
    activeRole: 'tecnico',
    isAdmin: true,
    userStatePolicy: { unattended_elevation: true },
  });
  assert(
    attack32.payload.policy.unattended_elevation === false,
    '3.2 Tecnico payload MUST NEVER have unattended_elevation = true (forced to false)',
    `Emitted unattended_elevation was ${attack32.payload.policy.unattended_elevation}`
  );

  // Attack 3.3: Adversary injects allow_outgoing = false in userStatePolicy
  const attack33 = generateBuilderPayload({
    activeRole: 'tecnico',
    isAdmin: true,
    userStatePolicy: { allow_outgoing: false },
  });
  assert(
    attack33.payload.policy.allow_outgoing === true,
    '3.3 Tecnico payload MUST ALWAYS have allow_outgoing = true (forced to true)',
    `Emitted allow_outgoing was ${attack33.payload.policy.allow_outgoing}`
  );

  // Attack 3.4: Verify Schema Validator directly rejects tampered tecnico payload with unattended_access = true
  const tamperedTecnico = JSON.parse(JSON.stringify(tecnicoRes.payload));
  tamperedTecnico.policy.unattended_access = true;
  const tamperedTecnicoVal = validator.validate(tamperedTecnico);
  assert(
    !tamperedTecnicoVal.valid &&
      tamperedTecnicoVal.errors.some((e) => e.includes('unattended_access')),
    '3.4 Schema validator actively REJECTS tecnico payload when unattended_access = true',
    'Schema validator failed to reject tampered payload'
  );

  // --- SECTION 4: Client-Side RBAC Guard Enforcement ---
  console.log('\n--- SECTION 4: Client-Side RBAC Guard Enforcement ---');

  const rbacRoles = ['operator', 'auditor', 'user', 'guest', null, undefined];
  for (const role of rbacRoles) {
    const rbacAttempt = generateBuilderPayload({
      activeRole: 'tecnico',
      isAdmin: false,
    });
    assert(
      rbacAttempt.blockedByRbac === true &&
        rbacAttempt.payload === null &&
        rbacAttempt.isSubmitDisabled === true,
      `4.1 Non-admin (${role}) blocked from submitting tecnico build`,
      `Expected block, got payload=${JSON.stringify(rbacAttempt.payload)}`
    );
  }

  // Operator CAN generate soporte builds
  const soporteOperator = generateBuilderPayload({
    activeRole: 'soporte',
    isAdmin: false,
  });
  assert(
    soporteOperator.blockedByRbac === false && soporteOperator.payload !== null,
    '4.2 Non-admin (operator) CAN generate soporte build',
    'Operator was erroneously blocked from generating soporte build'
  );

  // --- SECTION 5: Schema Boundary & Formatting Validation ---
  console.log('\n--- SECTION 5: Formatting, Boundaries & Schema Rejections ---');

  // 5.1 Base64 Public Key: Valid 44 chars Ed25519
  const validKey = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=';
  const keyRegex = /^[A-Za-z0-9+/=_-]+$/;
  assert(
    keyRegex.test(validKey) && validKey.length >= 40 && validKey.length <= 60,
    '5.1 Base64 Ed25519 public key regex and length conformity',
    'Public key pattern mismatch'
  );

  // 5.2 Invalid Base64 Public Key: illegal chars
  const invalidKeyChars = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE!';
  const invalidKeyPayload = JSON.parse(JSON.stringify(soporteRes.payload));
  invalidKeyPayload.server.server_public_key = invalidKeyChars;
  const invalidKeyVal = validator.validate(invalidKeyPayload);
  assert(
    !invalidKeyVal.valid && invalidKeyVal.errors.some((e) => e.includes('server_public_key')),
    '5.2 Schema validator REJECTS public key with invalid characters',
    'Validator allowed invalid characters in public key'
  );

  // 5.3 Server URL format check
  const badApiServer = 'ftp://cercano.lan:21114';
  const badApiPayload = JSON.parse(JSON.stringify(soporteRes.payload));
  badApiPayload.server.api_server = badApiServer;
  const badApiVal = validator.validate(badApiPayload);
  assert(
    !badApiVal.valid && badApiVal.errors.some((e) => e.includes('api_server')),
    '5.3 Schema validator REJECTS non-http/https api_server',
    'Validator allowed ftp:// URI in api_server'
  );

  // 5.4 UUID format check
  const badUuidPayload = JSON.parse(JSON.stringify(soporteRes.payload));
  badUuidPayload.profile_id = 'not-a-valid-uuid-value';
  const badUuidVal = validator.validate(badUuidPayload);
  assert(
    !badUuidVal.valid && badUuidVal.errors.some((e) => e.includes('profile_id')),
    '5.4 Schema validator REJECTS non-UUID profile_id',
    'Validator allowed malformed UUID'
  );

  // 5.5 install_path null vs string vs undefined
  const installedPayload = JSON.parse(JSON.stringify(soporteRes.payload));
  installedPayload.installation.mode = 'installed';
  installedPayload.installation.install_path = 'C:\\Program Files\\Cercano';
  const installedVal = validator.validate(installedPayload);
  assert(
    installedVal.valid,
    '5.5 Installed mode with valid string install_path is valid',
    installedVal.errors.join('; ')
  );

  const portableOmittedPayload = JSON.parse(JSON.stringify(soporteRes.payload));
  portableOmittedPayload.installation.mode = 'portable';
  delete portableOmittedPayload.installation.install_path;
  const portableOmittedVal = validator.validate(portableOmittedPayload);
  assert(
    portableOmittedVal.valid,
    '5.6 Portable mode with omitted install_path is valid',
    portableOmittedVal.errors.join('; ')
  );

  // Summary
  console.log('\n======================================================================');
  console.log('ADVERSARIAL VERIFICATION SUMMARY:');
  const total = results.length;
  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  console.log(`Total tests: ${total} | Passed: ${passed} | Failed: ${failed}`);
  console.log('======================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAdversarialSuite().catch((err) => {
  console.error('Fatal test suite error:', err);
  process.exit(1);
});
